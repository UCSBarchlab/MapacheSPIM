"""
Pure-Python ARM64 (AArch64) instruction encoder, compatible with GNU as.

Every A64 instruction is 4 bytes. Where the architecture allows several
encodings, the same choice as GNU as is made (for example ``mov`` of a
constant picks movz, then movn, then a bitmask orr; ``add x0, x1, #-5`` is
``sub x0, x1, #5``; misaligned offsets use ldur/stur).

Supported (64-bit X and 32-bit W forms):
    - Arithmetic: add, adds, sub, subs, neg, negs, cmp, cmn, adc, sbc,
      mul, madd, msub, mneg, smull, umull, smulh, umulh, smaddl, umaddl,
      sdiv, udiv, with immediates, shifted and extended registers
    - Logic: and, ands, orr, eor, bic, bics, orn, eon, tst, mvn, with
      bitmask immediates or shifted registers
    - Moves: mov (register, sp, or constant), movz, movn, movk
    - Shifts and bitfields: lsl, lsr, asr, ror (immediate or register),
      sxtb, sxth, sxtw, uxtb, uxth, ubfx, sbfx, ubfiz, sbfiz, bfi, bfxil,
      ubfm, sbfm, bfm, extr
    - Conditional: csel, csinc, csinv, csneg, cset, csetm, cinc, cinv,
      cneg, ccmp, ccmn
    - Loads/stores: ldr, str, ldrb, strb, ldrh, strh, ldrsb, ldrsh, ldrsw,
      ldur/stur variants, ldp, stp, ldpsw; offset, pre-index, post-index,
      register offset, and literal (label) addressing; ``ldr x0, =value``
      through a literal pool
    - Branches: b, bl, br, blr, ret, b.<cond>, cbz, cbnz, tbz, tbnz
    - Addresses: adr, adrp, with ``:lo12:symbol`` for add and loads/stores
    - System: svc, brk, hlt, nop
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple, cast

from .expr import Context, EncodeError, ExpressionError, parse_int, sign_extend

INSTR_SIZE = 4


class ARM64EncodeError(EncodeError):
    """Raised when an ARM64 instruction cannot be encoded."""


# ---------------------------------------------------------------------------
# Registers and operands
# ---------------------------------------------------------------------------


class Reg:
    """A general-purpose register operand."""

    __slots__ = ("num", "is64", "kind")

    def __init__(self, num: int, is64: bool, kind: str = "gp"):
        self.num = num  # 0-31
        self.is64 = is64
        self.kind = kind  # "gp", "sp", or "zr"

    def __repr__(self) -> str:
        return f"Reg({self.num}, {'x' if self.is64 else 'w'}, {self.kind})"


def parse_reg(text: str) -> Optional[Reg]:
    """Parse a register name, or return None if it is not one."""
    t = text.strip().lower()
    if t in ("sp", "wsp"):
        return Reg(31, t == "sp", "sp")
    if t in ("xzr", "wzr"):
        return Reg(31, t == "xzr", "zr")
    if t == "fp":
        return Reg(29, True)
    if t == "lr":
        return Reg(30, True)
    m = re.fullmatch(r"([xw])(\d+)", t)
    if m and int(m.group(2)) <= 30:
        return Reg(int(m.group(2)), m.group(1) == "x")
    return None


def _reg(text: str, what: str = "register") -> Reg:
    r = parse_reg(text)
    if r is None:
        raise ARM64EncodeError(f"expected a {what}, got '{text.strip()}'")
    return r


CONDITIONS = {
    "eq": 0, "ne": 1, "cs": 2, "hs": 2, "cc": 3, "lo": 3, "mi": 4, "pl": 5,
    "vs": 6, "vc": 7, "hi": 8, "ls": 9, "ge": 10, "lt": 11, "gt": 12, "le": 13,
    "al": 14, "nv": 15,
}  # fmt: skip

SHIFTS = {"lsl": 0, "lsr": 1, "asr": 2, "ror": 3}
EXTENDS = {
    "uxtb": 0, "uxth": 1, "uxtw": 2, "uxtx": 3, "sxtb": 4, "sxth": 5, "sxtw": 6, "sxtx": 7,
}  # fmt: skip


def split_operands(text: str) -> List[str]:
    """Split on commas outside [], (), and quotes."""
    ops: List[str] = []
    depth = 0
    cur = ""
    quote = False
    for ch in text:
        if ch == "'" and depth == 0:
            quote = not quote
        if not quote:
            if ch in "[(":
                depth += 1
            elif ch in "])":
                depth -= 1
            elif ch == "," and depth == 0:
                ops.append(cur.strip())
                cur = ""
                continue
        cur += ch
    if cur.strip() or ops:
        ops.append(cur.strip())
    return ops


def _same_size(*regs: Reg) -> None:
    if len({r.is64 for r in regs}) > 1:
        raise ARM64EncodeError("operands must all be X registers or all be W registers")


def _mask(bits: int) -> int:
    return (1 << bits) - 1


# ---------------------------------------------------------------------------
# Immediates
# ---------------------------------------------------------------------------


def encode_bitmask(value: int, bits: int) -> Optional[Tuple[int, int, int]]:
    """(N, immr, imms) for a logical immediate, or None if not encodable."""
    value &= _mask(bits)
    if value == 0 or value == _mask(bits):
        return None
    # Smallest repeating element
    size = bits
    while size > 2:
        half = size // 2
        if value & _mask(half) != (value >> half) & _mask(half):
            break
        size = half
    elem = value & _mask(size)
    ones = bin(elem).count("1")
    pattern = _mask(ones)
    for rotation in range(size):
        rotated = ((pattern >> rotation) | (pattern << (size - rotation))) & _mask(size)
        if rotated == elem:
            n = 1 if size == 64 else 0
            imms = ((-size << 1) & 0x3F) | (ones - 1)
            return n, rotation, imms
    return None


def _move_wide(value: int, bits: int) -> Optional[Tuple[int, int, int]]:
    """(opc, hw, imm16) for movz (opc 2) or movn (opc 0), or None."""
    value &= _mask(bits)
    for opc, candidate in ((2, value), (0, ~value & _mask(bits))):
        for hw in range(bits // 16):
            if candidate & ~(0xFFFF << (16 * hw)) & _mask(bits) == 0:
                return opc, hw, (candidate >> (16 * hw)) & 0xFFFF
    return None


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

LOAD_STORE = {
    # name: (size, opc, access size in bytes, register width 64?)  per register kind
    "strb": (0, 0, 1), "ldrb": (0, 1, 1), "ldrsb": (0, None, 1),
    "strh": (1, 0, 2), "ldrh": (1, 1, 2), "ldrsh": (1, None, 2),
    "ldrsw": (2, 2, 4),
    "str": (None, 0, None), "ldr": (None, 1, None),
}  # fmt: skip
UNSCALED = {
    "sturb": "strb", "ldurb": "ldrb", "ldursb": "ldrsb", "sturh": "strh", "ldurh": "ldrh",
    "ldursh": "ldrsh", "ldursw": "ldrsw", "stur": "str", "ldur": "ldr",
}  # fmt: skip


class Encoder:
    """Encodes one instruction at a known address."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.pc = ctx.address

    # --- operand helpers ---

    def imm(self, text: str) -> int:
        t = text.strip()
        if t.startswith("#"):
            t = t[1:].strip()
        if t.lower().startswith(":lo12:"):
            return self.ctx.eval(t[6:]) & 0xFFF
        return self.ctx.eval(t)

    def is_imm(self, text: str) -> bool:
        t = text.strip()
        return t.startswith("#") or (parse_reg(t) is None and not t.startswith("["))

    def target(self, text: str) -> int:
        """Branch/literal target: an address (label or expression)."""
        t = text.strip()
        if t.startswith("#"):
            t = t[1:]
        value = self.ctx.eval(t)
        return value

    def pc_offset(self, text: str, bits: int, scale: int = 4, what: str = "branch target") -> int:
        if not self.ctx.strict:
            self.ctx.eval(text.strip().lstrip("#"))
            return 0
        offset = self.target(text) - self.pc
        if offset % scale:
            raise ARM64EncodeError(f"{what} is not aligned to {scale} bytes")
        offset //= scale
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        if not lo <= offset <= hi:
            reach = (1 << (bits - 1)) * scale
            raise ARM64EncodeError(f"{what} out of range (+/-{reach // 1024}KB)")
        return offset & _mask(bits)

    def shift_amount(self, text: str, kinds: Dict[str, int]) -> Tuple[int, int]:
        """Parse 'lsl #3' style modifiers: (kind code, amount)."""
        parts = text.strip().split(None, 1)
        name = parts[0].lower()
        if name not in kinds:
            raise ARM64EncodeError(f"unexpected '{text.strip()}'")
        amount = self.imm(parts[1]) if len(parts) > 1 else 0
        return kinds[name], amount

    # --- instruction families ---

    def add_sub(self, op: int, s: int, ops: List[str]) -> int:
        """add/adds/sub/subs rd, rn, operand."""
        if len(ops) not in (3, 4):
            raise ARM64EncodeError("expected rd, rn, operand")
        rd, rn = _reg(ops[0]), _reg(ops[1])
        sf = int(rd.is64)
        if self.is_imm(ops[2]):
            _same_size(rd, rn)
            value = self.imm(ops[2])
            shift = 0
            if len(ops) == 4:
                kind, amount = self.shift_amount(ops[3], {"lsl": 0})
                if amount not in (0, 12):
                    raise ARM64EncodeError("the shift must be lsl #0 or lsl #12")
                shift = amount // 12
            elif value < 0 and ops[2].strip().lstrip("#").strip()[:1] != ":":
                # add x0, x1, #-5  ->  sub x0, x1, #5 (as GNU as does)
                value, op = -value, op ^ 1
            if not shift and value > 0xFFF and value & 0xFFF == 0 and value >> 12 <= 0xFFF:
                value, shift = value >> 12, 1
            if not 0 <= value <= 0xFFF:
                raise ARM64EncodeError(f"immediate {value} out of range (0 to 4095)")
            if rd.kind == "zr" and not s:
                raise ARM64EncodeError("the destination of add/sub (immediate) cannot be xzr")
            if rn.kind == "zr":
                raise ARM64EncodeError("the first source cannot be xzr here; use sp or a register")
            return (
                (sf << 31)
                | (op << 30)
                | (s << 29)
                | (0x22 << 23)
                | (shift << 22)
                | (value << 10)
                | (rn.num << 5)
                | rd.num
            )
        rm = _reg(ops[2])
        uses_sp = rn.kind == "sp" or (rd.kind == "sp" and not s)
        extend = None
        if len(ops) == 4:
            name = ops[3].strip().split()[0].lower()
            if name in EXTENDS or (uses_sp and name == "lsl"):
                extend = ops[3]
        if uses_sp or extend is not None:
            # Extended register form (the only one that accepts sp)
            if extend is not None:
                name = extend.strip().split()[0].lower()
                amount = (
                    self.imm(extend.strip().split(None, 1)[1]) if len(extend.split()) > 1 else 0
                )
                option = EXTENDS.get(name, 3 if sf else 2)
            else:
                amount, option = 0, 3 if sf else 2
            if not 0 <= amount <= 4:
                raise ARM64EncodeError("extend shift must be 0 to 4")
            if rd.kind == "zr" and not s:
                raise ARM64EncodeError("invalid use of xzr")
            return (
                (sf << 31)
                | (op << 30)
                | (s << 29)
                | (0x59 << 21)
                | (rm.num << 16)
                | (option << 13)
                | (amount << 10)
                | (rn.num << 5)
                | rd.num
            )
        _same_size(rd, rn, rm)
        shift, amount = (0, 0)
        if len(ops) == 4:
            shift, amount = self.shift_amount(ops[3], {"lsl": 0, "lsr": 1, "asr": 2})
        if not 0 <= amount < (64 if sf else 32):
            raise ARM64EncodeError(f"shift amount {amount} out of range")
        return (
            (sf << 31)
            | (op << 30)
            | (s << 29)
            | (0x0B << 24)
            | (shift << 22)
            | (rm.num << 16)
            | (amount << 10)
            | (rn.num << 5)
            | rd.num
        )

    def logical(self, opc: int, invert: int, ops: List[str]) -> int:
        """and/orr/eor/ands (and bic/orn/eon/bics when invert)."""
        if len(ops) not in (3, 4):
            raise ARM64EncodeError("expected rd, rn, operand")
        rd, rn = _reg(ops[0]), _reg(ops[1])
        _same_size(rd, rn)
        sf = int(rd.is64)
        bits = 64 if sf else 32
        if self.is_imm(ops[2]):
            if len(ops) == 4:
                raise ARM64EncodeError("a logical immediate cannot be shifted")
            value = self.imm(ops[2])
            if invert:
                value = ~value
            if not sf and not -(1 << 31) <= value < (1 << 32):
                raise ARM64EncodeError(f"immediate {value:#x} out of range for a W register")
            enc = encode_bitmask(value, bits)
            if enc is None:
                raise ARM64EncodeError(
                    f"immediate {self.imm(ops[2]):#x} is not a valid bitmask immediate"
                )
            n, immr, imms = enc
            if rd.kind == "zr" and opc != 3:
                pass  # orr xzr would be odd but GNU treats register 31 as sp here
            return (
                (sf << 31)
                | (opc << 29)
                | (0x24 << 23)
                | (n << 22)
                | (immr << 16)
                | (imms << 10)
                | (rn.num << 5)
                | rd.num
            )
        rm = _reg(ops[2])
        _same_size(rd, rm)
        shift, amount = (0, 0)
        if len(ops) == 4:
            shift, amount = self.shift_amount(ops[3], SHIFTS)
        if not 0 <= amount < bits:
            raise ARM64EncodeError(f"shift amount {amount} out of range")
        for r in (rd, rn, rm):
            if r.kind == "sp":
                raise ARM64EncodeError("sp cannot be used in this instruction")
        return (
            (sf << 31)
            | (opc << 29)
            | (0x0A << 24)
            | (shift << 22)
            | (invert << 21)
            | (rm.num << 16)
            | (amount << 10)
            | (rn.num << 5)
            | rd.num
        )

    def move_wide(self, opc: int, ops: List[str]) -> int:
        """movz/movn/movk rd, #imm{, lsl #shift}."""
        if len(ops) not in (2, 3):
            raise ARM64EncodeError("expected rd, #imm{, lsl #n}")
        rd = _reg(ops[0])
        sf = int(rd.is64)
        value = self.imm(ops[1])
        hw = 0
        if len(ops) == 3:
            _, amount = self.shift_amount(ops[2], {"lsl": 0})
            if amount % 16 or amount >= (64 if sf else 32):
                raise ARM64EncodeError(
                    "shift must be lsl #0, #16" + (", #32, or #48" if sf else "")
                )
            hw = amount // 16
        if not 0 <= value <= 0xFFFF:
            raise ARM64EncodeError(f"immediate {value} out of range (0 to 65535)")
        return (sf << 31) | (opc << 29) | (0x25 << 23) | (hw << 21) | (value << 5) | rd.num

    def bitfield(self, opc: int, rd: Reg, rn: Reg, immr: int, imms: int) -> int:
        _same_size(rd, rn)
        sf = int(rd.is64)
        bits = 64 if sf else 32
        if not (0 <= immr < bits and 0 <= imms < bits):
            raise ARM64EncodeError("bit position out of range")
        return (
            (sf << 31)
            | (opc << 29)
            | (0x26 << 23)
            | (sf << 22)
            | (immr << 16)
            | (imms << 10)
            | (rn.num << 5)
            | rd.num
        )

    def data2(self, opcode: int, ops: List[str]) -> int:
        """Two-source data processing: udiv, sdiv, lslv, lsrv, asrv, rorv."""
        if len(ops) != 3:
            raise ARM64EncodeError("expected rd, rn, rm")
        rd, rn, rm = (_reg(o) for o in ops)
        _same_size(rd, rn, rm)
        return (
            (int(rd.is64) << 31)
            | (0xD6 << 21)
            | (rm.num << 16)
            | (opcode << 10)
            | (rn.num << 5)
            | rd.num
        )

    def data3(self, op31: int, o0: int, rd: Reg, rn: Reg, rm: Reg, ra: Reg, sf: int) -> int:
        return (
            (sf << 31)
            | (0x1B << 24)
            | (op31 << 21)
            | (rm.num << 16)
            | (o0 << 15)
            | (ra.num << 10)
            | (rn.num << 5)
            | rd.num
        )

    def cond_select(self, op: int, op2: int, rd: Reg, rn: Reg, rm: Reg, cond: int) -> int:
        _same_size(rd, rn, rm)
        return (
            (int(rd.is64) << 31)
            | (op << 30)
            | (0xD4 << 21)
            | (rm.num << 16)
            | (cond << 12)
            | (op2 << 10)
            | (rn.num << 5)
            | rd.num
        )

    def cond(self, text: str) -> int:
        name = text.strip().lower()
        if name not in CONDITIONS:
            raise ARM64EncodeError(f"unknown condition '{text.strip()}'")
        return CONDITIONS[name]

    # --- loads and stores ---

    def parse_address(self, ops: List[str]) -> Tuple[str, Reg, object, bool, bool]:
        """Parse [base, ...] addressing: (mode, base, offset, writeback, post).

        mode is "imm" (offset is an int), "reg" (offset is (Reg, option, amount)),
        or "literal" (offset is the target expression).
        """
        text = ops[0].strip()
        if not text.startswith("["):
            return "literal", Reg(0, True), text, False, False
        writeback = text.endswith("!")
        if writeback:
            text = text[:-1].strip()
        if not text.endswith("]"):
            raise ARM64EncodeError(f"expected an address like [x1, #8], got '{ops[0]}'")
        inner = split_operands(text[1:-1])
        base = _reg(inner[0], "base register")
        if not base.is64:
            raise ARM64EncodeError("the base register must be an X register or sp")
        if base.kind == "zr":
            raise ARM64EncodeError("xzr cannot be a base register")
        if len(ops) == 2:  # post-index: [xn], #imm
            if writeback or len(inner) != 1:
                raise ARM64EncodeError("expected [xn], #imm for post-index addressing")
            return "imm", base, self.imm(ops[1]), True, True
        if len(ops) > 2:
            raise ARM64EncodeError("too many operands")
        if len(inner) == 1:
            return "imm", base, 0, writeback, False
        if self.is_imm(inner[1]) and len(inner) == 2:
            mode = "lo12" if ":lo12:" in inner[1].lower() else "imm"
            return mode, base, self.imm(inner[1]), writeback, False
        if writeback:
            raise ARM64EncodeError("register offsets cannot use writeback (!)")
        index = _reg(inner[1], "index register")
        option, amount, has_amount = (3 if index.is64 else None), 0, False
        if len(inner) == 3:
            parts = inner[2].split(None, 1)
            name = parts[0].lower()
            if name == "lsl":
                option = 3
            elif name in ("uxtw", "sxtw", "sxtx"):
                option = EXTENDS[name]
            else:
                raise ARM64EncodeError(f"unexpected '{inner[2]}'")
            if len(parts) > 1:
                amount, has_amount = self.imm(parts[1]), True
        if option is None:
            raise ARM64EncodeError("a W index register needs uxtw or sxtw")
        if (option in (2, 6)) == index.is64:
            raise ARM64EncodeError("uxtw/sxtw take a W index; lsl/sxtx take an X index")
        return "reg", base, (index, option, amount, has_amount), False, False

    def load_store(self, name: str, ops: List[str], unscaled_only: bool = False) -> int:
        if len(ops) < 2:
            raise ARM64EncodeError(f"expected {name} rt, [address]")
        rt = _reg(ops[0])
        if rt.kind == "sp":
            raise ARM64EncodeError("sp cannot be loaded or stored directly")
        size, opc, access = LOAD_STORE[name]
        if name in ("ldr", "str"):
            size = 3 if rt.is64 else 2
            access = 8 if rt.is64 else 4
        elif name in ("ldrsb", "ldrsh"):
            opc = 2 if rt.is64 else 3
        elif name == "ldrsw":
            if not rt.is64:
                raise ARM64EncodeError("ldrsw loads into an X register")
        elif rt.is64:
            raise ARM64EncodeError(f"{name} uses a W register")
        mode, base, offset, writeback, post = self.parse_address(ops[1:])

        if mode == "literal":
            if unscaled_only or name not in ("ldr", "ldrsw"):
                raise ARM64EncodeError(f"{name} cannot load from a label; use ldr")
            opc_lit = {("ldr", False): 0, ("ldr", True): 1, ("ldrsw", True): 2}[(name, rt.is64)]
            imm19 = self.pc_offset(str(offset), 19, what="literal address")
            return (opc_lit << 30) | (0x18 << 24) | (imm19 << 5) | rt.num

        base_bits = (size << 30) | (0x7 << 27) | (opc << 22) | (base.num << 5) | rt.num
        assert access is not None
        if mode == "reg":
            index, option, amount, has_amount = cast(Tuple[Reg, int, int, bool], offset)
            scale = {1: 0, 2: 1, 4: 2, 8: 3}[access]
            if has_amount and amount not in (0, scale):
                raise ARM64EncodeError(f"the index shift must be #0 or #{scale}")
            # S selects shifting by the access size; for bytes it records an explicit #0
            s = int(has_amount and (access == 1 or amount == scale))
            return (
                base_bits | (1 << 21) | (index.num << 16) | (option << 13) | (s << 12) | (2 << 10)
            )

        assert isinstance(offset, int)
        if mode == "lo12":
            # :lo12:symbol always uses the scaled form, so the address must be aligned
            if writeback or offset % access:
                raise ARM64EncodeError(
                    f":lo12: offset {offset:#x} is not a multiple of the access size ({access})"
                )
            return base_bits | (1 << 24) | ((offset // access) << 10)
        if writeback:
            if not -256 <= offset <= 255:
                raise ARM64EncodeError(f"offset {offset} out of range (-256 to 255)")
            mode_bits = 1 if post else 3
            return base_bits | ((offset & 0x1FF) << 12) | (mode_bits << 10)
        if not unscaled_only and offset >= 0 and offset % access == 0 and offset // access <= 0xFFF:
            return base_bits | (1 << 24) | ((offset // access) << 10)
        if -256 <= offset <= 255:
            return base_bits | ((offset & 0x1FF) << 12)  # ldur/stur
        raise ARM64EncodeError(
            f"offset {offset} out of range (unsigned multiple of {access} up to "
            f"{0xFFF * access}, or -256 to 255)"
        )

    def load_store_pair(self, name: str, ops: List[str]) -> int:
        if len(ops) < 3:
            raise ARM64EncodeError(f"expected {name} rt1, rt2, [address]")
        rt, rt2 = _reg(ops[0]), _reg(ops[1])
        _same_size(rt, rt2)
        load = 1 if name.startswith("ld") else 0
        if name == "ldpsw":
            if not rt.is64:
                raise ARM64EncodeError("ldpsw loads into X registers")
            opc, access = 1, 4
        else:
            opc, access = (2, 8) if rt.is64 else (0, 4)
        mode, base, offset, writeback, post = self.parse_address(ops[2:])
        if mode not in ("imm", "lo12"):
            raise ARM64EncodeError(f"{name} needs an address like [xn, #imm]")
        assert isinstance(offset, int)
        if offset % access or not -64 <= offset // access <= 63:
            raise ARM64EncodeError(
                f"offset {offset} must be a multiple of {access} from {-64 * access} to {63 * access}"
            )
        variant = 1 if post else (3 if writeback else 2)
        return (
            (opc << 30)
            | (0x5 << 27)
            | (variant << 23)
            | (load << 22)
            | (((offset // access) & 0x7F) << 15)
            | (rt2.num << 10)
            | (base.num << 5)
            | rt.num
        )

    # --- main dispatch ---

    def encode(self, mnemonic: str, ops: List[str]) -> int:  # noqa: C901
        m = mnemonic

        # Branches
        if m in ("b", "bl"):
            self.expect(ops, 1, f"{m} label")
            return ((0x25 if m == "bl" else 0x05) << 26) | self.pc_offset(ops[0], 26)
        if m.startswith("b.") and m[2:] in CONDITIONS:
            self.expect(ops, 1, f"{m} label")
            return (0x54 << 24) | (self.pc_offset(ops[0], 19) << 5) | CONDITIONS[m[2:]]
        if len(m) >= 3 and m[0] == "b" and m[1:] in CONDITIONS:  # 'beq' shorthand
            return self.encode("b." + m[1:], ops)
        if m in ("cbz", "cbnz"):
            self.expect(ops, 2, f"{m} rt, label")
            rt = _reg(ops[0])
            return (
                (int(rt.is64) << 31)
                | (0x1A << 25)
                | ((m == "cbnz") << 24)
                | (self.pc_offset(ops[1], 19) << 5)
                | rt.num
            )
        if m in ("tbz", "tbnz"):
            self.expect(ops, 3, f"{m} rt, #bit, label")
            rt = _reg(ops[0])
            bit = self.imm(ops[1])
            if not 0 <= bit < (64 if rt.is64 else 32):
                raise ARM64EncodeError(f"bit number {bit} out of range")
            return (
                ((bit >> 5) << 31)
                | (0x1B << 25)
                | ((m == "tbnz") << 24)
                | ((bit & 0x1F) << 19)
                | (self.pc_offset(ops[2], 14) << 5)
                | rt.num
            )
        if m in ("br", "blr"):
            self.expect(ops, 1, f"{m} xn")
            rn = _reg(ops[0])
            return (0xD61F0000 if m == "br" else 0xD63F0000) | (rn.num << 5)
        if m == "ret":
            rn = _reg(ops[0]) if ops else Reg(30, True)
            return 0xD65F0000 | (rn.num << 5)

        # System
        if m in ("svc", "brk", "hlt", "hvc"):
            value = self.imm(ops[0]) if ops else 0
            if not 0 <= value <= 0xFFFF:
                raise ARM64EncodeError(f"immediate {value} out of range (0 to 65535)")
            base = {"svc": 0xD4000001, "hvc": 0xD4000002, "brk": 0xD4200000, "hlt": 0xD4400000}[m]
            return base | (value << 5)
        if m == "nop":
            self.expect(ops, 0, "nop")
            return 0xD503201F

        # Addresses
        if m in ("adr", "adrp"):
            self.expect(ops, 2, f"{m} xd, label")
            rd = _reg(ops[0])
            if not self.ctx.strict:
                return 0
            target = self.target(ops[1])
            if m == "adr":
                offset = target - self.pc
                if not -(1 << 20) <= offset < (1 << 20):
                    raise ARM64EncodeError(
                        "adr target out of range (+/-1MB); for data use "
                        f"'ldr {ops[0]}, ={ops[1].strip()}' or adrp + add :lo12:"
                    )
                op = 0
            else:
                offset = (target >> 12) - (self.pc >> 12)
                if not -(1 << 20) <= offset < (1 << 20):
                    raise ARM64EncodeError("adrp target out of range (+/-4GB)")
                op = 1
            offset &= _mask(21)
            return (op << 31) | ((offset & 3) << 29) | (0x10 << 24) | ((offset >> 2) << 5) | rd.num

        # Arithmetic
        if m in ("add", "adds", "sub", "subs"):
            return self.add_sub(int(m.startswith("sub")), int(m.endswith("s")), ops)
        if m in ("cmp", "cmn"):
            if len(ops) not in (2, 3):
                raise ARM64EncodeError(f"expected {m} rn, operand")
            rn = _reg(ops[0])
            zr = "xzr" if rn.is64 else "wzr"
            return self.add_sub(int(m == "cmp"), 1, [zr, *ops])
        if m in ("neg", "negs"):
            if len(ops) not in (2, 3):
                raise ARM64EncodeError(f"expected {m} rd, rm")
            rd = _reg(ops[0])
            zr = "xzr" if rd.is64 else "wzr"
            if parse_reg(ops[1]) is None:
                raise ARM64EncodeError(f"{m} needs a register operand")
            return self.add_sub(1, int(m == "negs"), [ops[0], zr, *ops[1:]])
        if m in ("adc", "adcs", "sbc", "sbcs"):
            self.expect(ops, 3, f"{m} rd, rn, rm")
            rd, rn, rm = (_reg(o) for o in ops)
            _same_size(rd, rn, rm)
            op = int(m.startswith("sbc"))
            s = int(m.endswith("s"))
            return (
                (int(rd.is64) << 31)
                | (op << 30)
                | (s << 29)
                | (0xD0 << 21)
                | (rm.num << 16)
                | (rn.num << 5)
                | rd.num
            )

        # Logic
        logic = {
            "and": (0, 0), "orr": (1, 0), "eor": (2, 0), "ands": (3, 0),
            "bic": (0, 1), "orn": (1, 1), "eon": (2, 1), "bics": (3, 1),
        }  # fmt: skip
        if m in logic:
            opc, invert = logic[m]
            return self.logical(opc, invert, ops)
        if m == "tst":
            if len(ops) not in (2, 3):
                raise ARM64EncodeError("expected tst rn, operand")
            zr = "xzr" if _reg(ops[0]).is64 else "wzr"
            return self.logical(3, 0, [zr, *ops])
        if m == "mvn":
            if len(ops) not in (2, 3):
                raise ARM64EncodeError("expected mvn rd, rm")
            zr = "xzr" if _reg(ops[0]).is64 else "wzr"
            return self.logical(1, 1, [ops[0], zr, *ops[1:]])

        # Moves
        if m == "mov":
            self.expect(ops, 2, "mov rd, operand")
            rd = _reg(ops[0])
            src = parse_reg(ops[1])
            if src is not None:
                _same_size(rd, src)
                if rd.kind == "sp" or src.kind == "sp":
                    return self.add_sub(0, 0, [ops[0], ops[1], "#0"])
                zr = "xzr" if rd.is64 else "wzr"
                return self.logical(1, 0, [ops[0], zr, ops[1]])
            bits = 64 if rd.is64 else 32
            value = self.imm(ops[1])
            if not rd.is64 and not -(1 << 31) <= value < (1 << 32):
                raise ARM64EncodeError(f"immediate {value:#x} out of range for a W register")
            wide = _move_wide(value, bits)
            if wide is not None and rd.kind != "sp":
                opc, hw, imm16 = wide
                return (
                    (int(rd.is64) << 31)
                    | (opc << 29)
                    | (0x25 << 23)
                    | (hw << 21)
                    | (imm16 << 5)
                    | rd.num
                )
            enc = encode_bitmask(value, bits)
            if enc is not None:
                zr = "xzr" if rd.is64 else "wzr"
                return self.logical(1, 0, [ops[0], zr, f"#{value}"])
            raise ARM64EncodeError(
                f"{value:#x} cannot be loaded with one mov; use 'ldr {ops[0]}, ={ops[1].lstrip('#')}' "
                "or movz followed by movk"
            )
        if m in ("movz", "movn", "movk"):
            return self.move_wide({"movn": 0, "movz": 2, "movk": 3}[m], ops)

        # Multiply and divide
        if m in ("mul", "mneg", "madd", "msub"):
            n = 3 if m in ("mul", "mneg") else 4
            self.expect(ops, n, f"{m} rd, rn, rm" + (", ra" if n == 4 else ""))
            rd, rn, rm = (_reg(o) for o in ops[:3])
            ra = _reg(ops[3]) if n == 4 else Reg(31, rd.is64, "zr")
            _same_size(rd, rn, rm, ra)
            return self.data3(0, int(m in ("msub", "mneg")), rd, rn, rm, ra, int(rd.is64))
        if m in ("smull", "umull", "smaddl", "umaddl", "smnegl", "umnegl", "smsubl", "umsubl"):
            n = 3 if m.endswith("ull") or m.endswith("negl") else 4
            self.expect(ops, n, f"{m} xd, wn, wm" + (", xa" if n == 4 else ""))
            rd, rn, rm = (_reg(o) for o in ops[:3])
            ra = _reg(ops[3]) if n == 4 else Reg(31, True, "zr")
            if not (rd.is64 and ra.is64 and not rn.is64 and not rm.is64):
                raise ARM64EncodeError(f"{m} takes an X destination and W sources")
            op31 = 5 if m.startswith("u") else 1
            o0 = int("sub" in m or "neg" in m)
            return self.data3(op31, o0, rd, rn, rm, ra, 1)
        if m in ("smulh", "umulh"):
            self.expect(ops, 3, f"{m} xd, xn, xm")
            rd, rn, rm = (_reg(o) for o in ops)
            if not (rd.is64 and rn.is64 and rm.is64):
                raise ARM64EncodeError(f"{m} takes X registers")
            return self.data3(6 if m == "umulh" else 2, 0, rd, rn, rm, Reg(31, True, "zr"), 1)
        if m in ("udiv", "sdiv"):
            return self.data2(2 if m == "udiv" else 3, ops)

        # Shifts
        if m in ("lsl", "lsr", "asr", "ror"):
            self.expect(ops, 3, f"{m} rd, rn, amount")
            if not self.is_imm(ops[2]):
                return self.data2({"lsl": 8, "lsr": 9, "asr": 10, "ror": 11}[m], ops)
            rd, rn = _reg(ops[0]), _reg(ops[1])
            bits = 64 if rd.is64 else 32
            amount = self.imm(ops[2])
            if not 0 <= amount < bits:
                raise ARM64EncodeError(f"shift amount {amount} out of range (0 to {bits - 1})")
            if m == "lsl":
                return self.bitfield(2, rd, rn, (-amount) % bits, bits - 1 - amount)
            if m == "lsr":
                return self.bitfield(2, rd, rn, amount, bits - 1)
            if m == "asr":
                return self.bitfield(0, rd, rn, amount, bits - 1)
            return self.extr(rd, rn, rn, amount)
        if m in ("lslv", "lsrv", "asrv", "rorv"):
            return self.data2({"lslv": 8, "lsrv": 9, "asrv": 10, "rorv": 11}[m], ops)
        if m == "extr":
            self.expect(ops, 4, "extr rd, rn, rm, #lsb")
            rd, rn, rm = (_reg(o) for o in ops[:3])
            return self.extr(rd, rn, rm, self.imm(ops[3]))

        # Bitfield aliases
        if m in ("sxtb", "sxth", "sxtw", "uxtb", "uxth"):
            self.expect(ops, 2, f"{m} rd, wn")
            rd, rn = _reg(ops[0]), _reg(ops[1])
            if rn.is64:
                raise ARM64EncodeError(f"{m} takes a W source register")
            width = {"b": 8, "h": 16, "w": 32}[m[-1]]
            if m.startswith("u"):
                if rd.is64:
                    raise ARM64EncodeError(f"{m} takes a W destination register")
                return self.bitfield(2, rd, rn, 0, width - 1)
            if m == "sxtw" and not rd.is64:
                raise ARM64EncodeError("sxtw takes an X destination register")
            return self.bitfield(0, rd, Reg(rn.num, rd.is64), 0, width - 1)
        if m in ("ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil"):
            self.expect(ops, 4, f"{m} rd, rn, #lsb, #width")
            rd, rn = _reg(ops[0]), _reg(ops[1])
            bits = 64 if rd.is64 else 32
            lsb, width = self.imm(ops[2]), self.imm(ops[3])
            if not (0 <= lsb < bits and 1 <= width <= bits - lsb):
                raise ARM64EncodeError("bit field out of range")
            opc = {"s": 0, "b": 1, "u": 2}[m[0]]
            if m in ("ubfx", "sbfx", "bfxil"):
                return self.bitfield(opc, rd, rn, lsb, lsb + width - 1)
            return self.bitfield(opc, rd, rn, (-lsb) % bits, width - 1)
        if m in ("ubfm", "sbfm", "bfm"):
            self.expect(ops, 4, f"{m} rd, rn, #immr, #imms")
            rd, rn = _reg(ops[0]), _reg(ops[1])
            return self.bitfield(
                {"sbfm": 0, "bfm": 1, "ubfm": 2}[m], rd, rn, self.imm(ops[2]), self.imm(ops[3])
            )

        # Conditional select
        csel = {"csel": (0, 0), "csinc": (0, 1), "csinv": (1, 0), "csneg": (1, 1)}
        if m in csel:
            self.expect(ops, 4, f"{m} rd, rn, rm, cond")
            rd, rn, rm = (_reg(o) for o in ops[:3])
            return self.cond_select(*csel[m], rd, rn, rm, self.cond(ops[3]))
        if m in ("cset", "csetm"):
            self.expect(ops, 2, f"{m} rd, cond")
            rd = _reg(ops[0])
            zero = Reg(31, rd.is64, "zr")
            op = 1 if m == "csetm" else 0
            return self.cond_select(op, 0 if op else 1, rd, zero, zero, self.inverted(ops[1]))
        if m in ("cinc", "cinv", "cneg"):
            self.expect(ops, 3, f"{m} rd, rn, cond")
            rd, rn = _reg(ops[0]), _reg(ops[1])
            op, op2 = {"cinc": (0, 1), "cinv": (1, 0), "cneg": (1, 1)}[m]
            return self.cond_select(op, op2, rd, rn, rn, self.inverted(ops[2]))
        if m in ("ccmp", "ccmn"):
            self.expect(ops, 4, f"{m} rn, operand, #nzcv, cond")
            rn = _reg(ops[0])
            nzcv = self.imm(ops[2])
            if not 0 <= nzcv <= 15:
                raise ARM64EncodeError("nzcv must be 0 to 15")
            op = 1 if m == "ccmp" else 0
            head = (int(rn.is64) << 31) | (op << 30) | (1 << 29) | (0xD2 << 21)
            if self.is_imm(ops[1]):
                value = self.imm(ops[1])
                if not 0 <= value <= 31:
                    raise ARM64EncodeError("immediate must be 0 to 31")
                return (
                    head
                    | (value << 16)
                    | (self.cond(ops[3]) << 12)
                    | (1 << 11)
                    | (rn.num << 5)
                    | nzcv
                )
            rm = _reg(ops[1])
            _same_size(rn, rm)
            return head | (rm.num << 16) | (self.cond(ops[3]) << 12) | (rn.num << 5) | nzcv

        # Loads and stores
        if m in LOAD_STORE:
            return self.load_store(m, ops)
        if m in UNSCALED:
            return self.load_store(UNSCALED[m], ops, unscaled_only=True)
        if m in ("ldp", "stp", "ldpsw"):
            return self.load_store_pair(m, ops)

        raise ARM64EncodeError(f"unknown instruction '{mnemonic}'")

    def extr(self, rd: Reg, rn: Reg, rm: Reg, lsb: int) -> int:
        _same_size(rd, rn, rm)
        sf = int(rd.is64)
        if not 0 <= lsb < (64 if sf else 32):
            raise ARM64EncodeError("shift amount out of range")
        return (
            (sf << 31)
            | (0x27 << 23)
            | (sf << 22)
            | (rm.num << 16)
            | (lsb << 10)
            | (rn.num << 5)
            | rd.num
        )

    def inverted(self, text: str) -> int:
        cond = self.cond(text)
        if cond >= 14:
            raise ARM64EncodeError("al and nv cannot be used here")
        return cond ^ 1

    @staticmethod
    def expect(ops: List[str], n: int, usage: str) -> None:
        if len(ops) != n:
            raise ARM64EncodeError(f"expected {usage}")


def _split_instruction(text: str) -> Tuple[str, List[str]]:
    parts = text.strip().split(None, 1)
    if not parts:
        raise ARM64EncodeError("empty instruction")
    return parts[0].lower(), split_operands(parts[1]) if len(parts) > 1 else []


def _context(address: int, labels: Dict[str, int], strict: bool) -> Context:
    return Context(address, labels, strict=strict, error=ARM64EncodeError)


def encode(text: str, address: int, labels: Dict[str, int]) -> bytes:
    """
    Encode one ARM64 instruction to little-endian machine code (4 bytes).

    Raises:
        ARM64EncodeError: If the instruction is invalid.
    """
    mnemonic, ops = _split_instruction(text)
    encoder = Encoder(_context(address, labels, strict=True))
    try:
        word = encoder.encode(mnemonic, ops)
    except ExpressionError as e:
        raise ARM64EncodeError(str(e))
    return word.to_bytes(4, "little")


def instruction_size(text: str, labels: Dict[str, int], address: int = 0) -> int:
    """Every A64 instruction is 4 bytes."""
    return INSTR_SIZE


# ---------------------------------------------------------------------------
# Literal pools (ldr x0, =value)
# ---------------------------------------------------------------------------

_LITERAL_LOAD = re.compile(r"^\s*(ldr|ldrsw)\s+([^,]+),\s*=\s*(.+?)\s*$", re.IGNORECASE)


def literal_load(text: str) -> Optional[Tuple[str, str, str]]:
    """If text is 'ldr rt, =expr', return (mnemonic, rt, expr)."""
    m = _LITERAL_LOAD.match(text)
    if not m:
        return None
    return m.group(1).lower(), m.group(2).strip(), m.group(3)


def literal_size(mnemonic: str, rt: str) -> int:
    """Pool entry size for 'ldr rt, =expr' (8 for X registers, 4 for W)."""
    reg = parse_reg(rt)
    if reg is None:
        raise ARM64EncodeError(f"expected a register, got '{rt}'")
    return 8 if reg.is64 and mnemonic == "ldr" else 4


def constant_value(expression: str) -> Optional[int]:
    """The value of a constant pool expression, or None if it uses symbols."""
    return parse_int(expression.lstrip("#"))


__all__ = [
    "ARM64EncodeError",
    "encode",
    "encode_bitmask",
    "instruction_size",
    "literal_load",
    "literal_size",
    "constant_value",
    "sign_extend",
]
