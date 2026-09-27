"""
Pure-Python x86-64 instruction encoder, compatible with GNU as.

Accepts AT&T syntax (GNU's default: ``movq $4, %rax``) and Intel syntax
(``mov rax, 4``). Without a ``.att_syntax``/``.intel_syntax`` directive, each
instruction's syntax is recognized from its operands (``%``/``$`` mean AT&T).

Encodings follow GNU as's choices: accumulator short forms when shorter,
sign-extended 8-bit immediates when a constant fits, 32-bit fields for
symbolic values, ``c7`` vs ``movabs`` for 64-bit moves, and jumps that
start short (rel8) and grow to rel32 only when the target is out of range.

Supported instructions (with b/w/l/q operand sizes):
    mov, movabs, movzx/movz*, movsx/movs*, movsxd/movslq, lea, xchg,
    add, or, adc, sbb, and, sub, xor, cmp, test, inc, dec, neg, not,
    mul, imul (1, 2, 3 operands), div, idiv, shl/sal, shr, sar, rol, ror,
    rcl, rcr, push, pop, jmp, call, ret, j<cc>, set<cc>, cmov<cc>,
    cbw/cwde/cdqe, cwd/cdq/cqo (cwtl/cltq/cltd/cqto), leave, nop, hlt,
    syscall, int, int3
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Mapping, Optional, Set, Tuple, Union

from .expr import Context, EncodeError, ExpressionError, UndefinedSymbol, evaluate

# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------


class X86EncodeError(EncodeError):
    """Raised when an x86-64 instruction cannot be encoded."""


@dataclass(frozen=True)
class Reg:
    num: int  # 0-15 (ah/ch/dh/bh use 4-7 with high8)
    size: int  # bytes: 1, 2, 4, 8
    high8: bool = False  # ah, ch, dh, bh (cannot be used with REX)
    needs_rex: bool = False  # spl, bpl, sil, dil
    rip: bool = False  # %rip, only valid as a memory base


_REGS: Dict[str, Reg] = {}
for _i, _name in enumerate(["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]):
    _REGS["r" + _name] = Reg(_i, 8)
    _REGS["e" + _name] = Reg(_i, 4)
    _REGS[_name] = Reg(_i, 2)
for _i in range(8, 16):
    _REGS[f"r{_i}"] = Reg(_i, 8)
    _REGS[f"r{_i}d"] = Reg(_i, 4)
    _REGS[f"r{_i}w"] = Reg(_i, 2)
    _REGS[f"r{_i}b"] = Reg(_i, 1)
    _REGS[f"r{_i}l"] = Reg(_i, 1)
for _i, _name in enumerate(["al", "cl", "dl", "bl"]):
    _REGS[_name] = Reg(_i, 1)
for _i, _name in enumerate(["ah", "ch", "dh", "bh"]):
    _REGS[_name] = Reg(_i + 4, 1, high8=True)
for _i, _name in enumerate(["spl", "bpl", "sil", "dil"]):
    _REGS[_name] = Reg(_i + 4, 1, needs_rex=True)
_REGS["rip"] = Reg(0, 8, rip=True)

SIZE_SUFFIX = {"b": 1, "w": 2, "l": 4, "q": 8}
PTR_SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8}

CONDITIONS = {
    "o": 0, "no": 1, "b": 2, "c": 2, "nae": 2, "ae": 3, "nb": 3, "nc": 3,
    "e": 4, "z": 4, "ne": 5, "nz": 5, "be": 6, "na": 6, "a": 7, "nbe": 7,
    "s": 8, "ns": 9, "p": 10, "pe": 10, "np": 11, "po": 11,
    "l": 12, "nge": 12, "ge": 13, "nl": 13, "le": 14, "ng": 14, "g": 15, "nle": 15,
}  # fmt: skip

ALU_OPS = {"add": 0, "or": 1, "adc": 2, "sbb": 3, "and": 4, "sub": 5, "xor": 6, "cmp": 7}
SHIFT_OPS = {"rol": 0, "ror": 1, "rcl": 2, "rcr": 3, "shl": 4, "sal": 4, "shr": 5, "sar": 7}
UNARY_OPS = {"not": 2, "neg": 3, "mul": 4, "div": 6, "idiv": 7}


def _fits8(v: int) -> bool:
    return -128 <= v <= 127


def _fits32(v: int) -> bool:
    return -(1 << 31) <= v < (1 << 31)


# ---------------------------------------------------------------------------
# Operands
# ---------------------------------------------------------------------------


@dataclass
class Imm:
    expr: str


@dataclass
class Mem:
    disp: str  # expression text ("" for none)
    base: Optional[Reg] = None
    index: Optional[Reg] = None
    scale: int = 1
    size: Optional[int] = None  # from Intel "qword ptr"


@dataclass
class Target:
    """A jump/call destination written as a label or address."""

    expr: str


Operand = Union[Reg, Imm, Mem, Target]


def _split(text: str) -> List[str]:
    """Split operands on commas outside (), [], and quotes."""
    ops: List[str] = []
    depth = 0
    cur = ""
    quote = False
    for ch in text:
        if ch == "'" and depth == 0:
            quote = not quote
        if not quote:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif ch == "," and depth == 0:
                ops.append(cur.strip())
                cur = ""
                continue
        cur += ch
    if cur.strip() or ops:
        ops.append(cur.strip())
    return ops


def _reg_or_none(text: str) -> Optional[Reg]:
    return _REGS.get(text.strip().lower())


def parse_att_operand(text: str, is_branch: bool) -> Tuple[Operand, bool]:
    """Parse one AT&T operand; returns (operand, indirect '*')."""
    t = text.strip()
    indirect = t.startswith("*")
    if indirect:
        t = t[1:].strip()
    if t.startswith("%"):
        reg = _reg_or_none(t[1:])
        if reg is None or reg.rip:
            raise X86EncodeError(f"unknown register '{t}'")
        return reg, indirect
    if t.startswith("$"):
        return Imm(t[1:].strip()), indirect
    m = re.fullmatch(r"(.*?)\(\s*(%\w+)?\s*(?:,\s*(%\w+)\s*(?:,\s*([^)]*))?)?\)", t)
    if m:
        base = _reg_or_none(m.group(2)[1:]) if m.group(2) else None
        index = _reg_or_none(m.group(3)[1:]) if m.group(3) else None
        if m.group(2) and base is None:
            raise X86EncodeError(f"unknown register '{m.group(2)}'")
        if m.group(3) and index is None:
            raise X86EncodeError(f"unknown register '{m.group(3)}'")
        scale = int(m.group(4).strip(), 0) if m.group(4) and m.group(4).strip() else 1
        return Mem(m.group(1).strip(), base, index, scale), indirect
    if is_branch and not indirect:
        return Target(t), False
    return Mem(t), indirect


def parse_intel_operand(text: str, is_branch: bool, absolute: Callable[[str], bool]) -> Operand:
    """Parse one Intel-syntax operand."""
    t = text.strip()
    size = None
    m = re.match(r"^(byte|word|dword|qword)\s+ptr\s+(.*)$", t, re.IGNORECASE)
    if m:
        size = PTR_SIZES[m.group(1).lower()]
        t = m.group(2).strip()
    reg = _reg_or_none(t.lstrip("%"))
    if reg is not None and not reg.rip:
        return reg
    if t.lower().startswith("offset "):
        return Imm(t[7:].strip())
    if "[" in t:
        m = re.fullmatch(r"(.*?)\[(.*)\]\s*(.*)", t)
        if not m:
            raise X86EncodeError(f"cannot parse memory operand '{text}'")
        disp_parts = [p for p in (m.group(1).strip(), m.group(3).strip()) if p]
        base = index = None
        scale = 1
        terms = re.findall(r"([+-]?)\s*([^+-]+)", m.group(2))
        for sign, term in terms:
            term = term.strip()
            if "*" in term:
                a, b = (x.strip() for x in term.split("*", 1))
                r = _reg_or_none(a) or _reg_or_none(b)
                if r is not None:
                    index = r
                    scale = int(b if _reg_or_none(a) else a, 0)
                    continue
            r = _reg_or_none(term)
            if r is not None and sign != "-":
                if base is None:
                    base = r
                elif index is None:
                    index = r
                else:
                    raise X86EncodeError(f"too many registers in '{text}'")
                continue
            disp_parts.append(f"{sign}{term}" if sign or not disp_parts else f"+{term}")
        disp = "".join(p if p[:1] in "+-" or i == 0 else "+" + p for i, p in enumerate(disp_parts))
        return Mem(disp, base, index, scale, size)
    if is_branch:
        return Target(t)
    # A bare symbol is a memory reference in GNU's Intel syntax; numbers
    # and absolute constants are immediates
    if absolute(t):
        if size is not None:
            raise X86EncodeError(f"'{text}' is not a memory operand")
        return Imm(t)
    return Mem(t, size=size)


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


@dataclass
class _Parts:
    """Pieces of one instruction; assembled at the end so RIP-relative
    displacements can be computed from the instruction's full length."""

    prefix: bytes = b""
    rex: int = 0  # W R X B bits
    force_rex: bool = False
    forbid_rex: bool = False
    opcode: bytes = b""
    modrm: bytes = b""
    disp: bytes = b""
    rip_target: Optional[int] = None
    imm: bytes = b""


class Encoder:
    def __init__(self, ctx: Context, absolute_symbols: Set[str], long_jump: bool):
        self.ctx = ctx
        self.pc = ctx.address
        self.absolute_symbols = absolute_symbols
        self.long_jump = long_jump

    # --- values ---

    def value(self, expr: str) -> int:
        return self.ctx.eval(expr)

    def is_symbolic(self, expr: str) -> bool:
        """Does the expression refer to a label (relocatable), not only constants?"""
        found = False

        def resolve(name: str) -> int:
            nonlocal found
            if name not in self.absolute_symbols:
                found = True
            return 0

        try:
            evaluate(expr, resolve)
        except ExpressionError:
            return True
        return found

    def is_absolute(self, text: str) -> bool:
        return not self.is_symbolic(text)

    # --- ModRM ---

    def modrm(self, parts: _Parts, reg_field: int, rm: Operand) -> None:
        """Fill in ModRM/SIB/displacement for reg_field and an r/m operand."""
        if reg_field >= 8:
            parts.rex |= 4  # REX.R
        if isinstance(rm, Reg):
            if rm.num >= 8:
                parts.rex |= 1  # REX.B
            parts.modrm = bytes([0xC0 | ((reg_field & 7) << 3) | (rm.num & 7)])
            return
        if not isinstance(rm, Mem):
            raise X86EncodeError("expected a register or memory operand")
        disp_value = self.value(rm.disp) if rm.disp else 0
        symbolic = bool(rm.disp) and self.is_symbolic(rm.disp)
        base, index = rm.base, rm.index
        r = (reg_field & 7) << 3
        if base is not None and base.rip:
            if index is not None:
                raise X86EncodeError("rip-relative addressing cannot use an index register")
            parts.modrm = bytes([r | 0x05])
            parts.rip_target = disp_value
            parts.disp = b"\0\0\0\0"
            return
        for reg in (base, index):
            if reg is not None and reg.size not in (8, 4):
                raise X86EncodeError("address registers must be 64-bit (or 32-bit)")
        if (base is not None and base.size == 4) or (index is not None and index.size == 4):
            parts.prefix += b"\x67"
        if index is not None:
            if index.num == 4:
                raise X86EncodeError("%rsp cannot be an index register")
            if rm.scale not in (1, 2, 4, 8):
                raise X86EncodeError(f"scale must be 1, 2, 4, or 8, not {rm.scale}")
            if index.num >= 8:
                parts.rex |= 2  # REX.X
        if base is not None and base.num >= 8:
            parts.rex |= 1
        scale_bits = {1: 0, 2: 1, 4: 2, 8: 3}.get(rm.scale, 0)

        if base is None:
            # disp32 with SIB: no base (index or absolute address)
            idx = index.num & 7 if index is not None else 4
            parts.modrm = bytes([r | 0x04, (scale_bits << 6) | (idx << 3) | 5])
            parts.disp = (disp_value & 0xFFFFFFFF).to_bytes(4, "little")
            if not symbolic and not _fits32(disp_value) and disp_value >= (1 << 32):
                raise X86EncodeError(f"address {disp_value:#x} does not fit in 32 bits")
            return

        if symbolic or not _fits8(disp_value):
            mod, disp = 0x80, (disp_value & 0xFFFFFFFF).to_bytes(4, "little")
        elif disp_value == 0 and (base.num & 7) != 5:
            mod, disp = 0x00, b""
        else:
            mod, disp = 0x40, (disp_value & 0xFF).to_bytes(1, "little")
        if index is not None or (base.num & 7) == 4:
            idx = index.num & 7 if index is not None else 4
            parts.modrm = bytes([mod | r | 0x04, (scale_bits << 6) | (idx << 3) | (base.num & 7)])
        else:
            parts.modrm = bytes([mod | r | (base.num & 7)])
        parts.disp = disp

    def finish(
        self, parts: _Parts, size: Optional[int], regs: List[Reg], default64: bool = False
    ) -> bytes:
        """Assemble prefixes, REX, opcode, ModRM, displacement, immediate."""
        prefix = parts.prefix
        if size == 2:
            prefix = b"\x66" + prefix
        rex = parts.rex
        if size == 8 and not default64:
            rex |= 8
        force = parts.force_rex or any(r.needs_rex for r in regs)
        if any(r.high8 for r in regs) and (rex or force):
            raise X86EncodeError("ah, bh, ch, and dh cannot be used with REX registers")
        rex_bytes = bytes([0x40 | rex]) if rex or force else b""
        code = prefix + rex_bytes + parts.opcode + parts.modrm + parts.disp + parts.imm
        if parts.rip_target is not None:
            offset = len(prefix) + len(rex_bytes) + len(parts.opcode) + len(parts.modrm)
            rel = parts.rip_target - (self.pc + len(code))
            if self.ctx.strict and not _fits32(rel):
                raise X86EncodeError("rip-relative target out of range")
            code = code[:offset] + (rel & 0xFFFFFFFF).to_bytes(4, "little") + code[offset + 4 :]
        return code

    def imm_bytes(self, expr: str, size: int) -> bytes:
        # GNU as truncates an oversized immediate (with a warning) rather
        # than rejecting it, so do the same.
        value = self.value(expr)
        return (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")

    # --- operand size ---

    @staticmethod
    def operand_size(ops: List[Operand], suffix: Optional[int], mnemonic: str) -> int:
        sizes = {op.size for op in ops if isinstance(op, Reg)}
        sizes |= {op.size for op in ops if isinstance(op, Mem) and op.size}
        if suffix:
            if sizes and sizes != {suffix}:
                raise X86EncodeError(f"operand size does not match the '{mnemonic}' suffix")
            return suffix
        if len(sizes) > 1:
            raise X86EncodeError("operand sizes do not match")
        if not sizes:
            raise X86EncodeError(
                f"cannot tell the operand size of '{mnemonic}'; add a size suffix "
                "(b/w/l/q, e.g. movq) or 'qword ptr'"
            )
        return sizes.pop()

    # --- instruction families ---

    def alu(self, op: int, dst: Operand, src: Operand, size: int) -> bytes:
        regs = [o for o in (dst, src) if isinstance(o, Reg)]
        parts = _Parts()
        wide = 0 if size == 1 else 1
        if isinstance(src, Imm):
            symbolic = self.is_symbolic(src.expr)
            value = self.value(src.expr)
            acc = isinstance(dst, Reg) and dst.num == 0 and not dst.high8
            if size == 1:
                if acc:
                    parts.opcode = bytes([op * 8 + 4])
                    parts.imm = self.imm_bytes(src.expr, 1)
                    return self.finish(parts, size, regs)
                parts.opcode = b"\x80"
                self.modrm(parts, op, dst)
                parts.imm = self.imm_bytes(src.expr, 1)
                return self.finish(parts, size, regs)
            if not symbolic and _fits8(value):
                parts.opcode = b"\x83"
                self.modrm(parts, op, dst)
                parts.imm = (value & 0xFF).to_bytes(1, "little")
                return self.finish(parts, size, regs)
            imm_size = 2 if size == 2 else 4
            if size == 8 and not symbolic and not _fits32(value):
                raise X86EncodeError(
                    f"immediate {value:#x} does not fit in 32 bits (sign-extended)"
                )
            if acc:
                parts.opcode = bytes([op * 8 + 5])
            else:
                parts.opcode = b"\x81"
                self.modrm(parts, op, dst)
            parts.imm = (
                self.imm_bytes(src.expr, imm_size)
                if size != 8
                else (value & 0xFFFFFFFF).to_bytes(4, "little")
            )
            return self.finish(parts, size, regs)
        if isinstance(src, Reg):
            parts.opcode = bytes([op * 8 + wide])  # r/m, reg
            self.modrm(parts, src.num, dst)
            return self.finish(parts, size, regs)
        if isinstance(dst, Reg) and isinstance(src, Mem):
            parts.opcode = bytes([op * 8 + 2 + wide])  # reg, r/m
            self.modrm(parts, dst.num, src)
            return self.finish(parts, size, regs)
        raise X86EncodeError("invalid operands (memory to memory is not allowed)")

    def mov(self, dst: Operand, src: Operand, size: int, movabs: bool = False) -> bytes:
        regs = [o for o in (dst, src) if isinstance(o, Reg)]
        parts = _Parts()
        wide = 0 if size == 1 else 1
        if isinstance(src, Imm):
            value = self.value(src.expr)
            symbolic = self.is_symbolic(src.expr)
            if isinstance(dst, Reg):
                if size == 8:
                    if movabs or (not symbolic and not _fits32(value)):
                        parts.opcode = bytes([0xB8 + (dst.num & 7)])
                        parts.rex |= 1 if dst.num >= 8 else 0
                        parts.imm = (value & ((1 << 64) - 1)).to_bytes(8, "little")
                        return self.finish(parts, size, regs)
                    parts.opcode = b"\xc7"
                    self.modrm(parts, 0, dst)
                    parts.imm = (value & 0xFFFFFFFF).to_bytes(4, "little")
                    return self.finish(parts, size, regs)
                base = 0xB0 if size == 1 else 0xB8
                parts.opcode = bytes([base + (dst.num & 7)])
                parts.rex |= 1 if dst.num >= 8 else 0
                parts.imm = self.imm_bytes(src.expr, size)
                return self.finish(parts, size, regs)
            if movabs:
                raise X86EncodeError("movabs takes a register destination")
            parts.opcode = b"\xc6" if size == 1 else b"\xc7"
            self.modrm(parts, 0, dst)
            if size == 8:
                if not symbolic and not _fits32(value):
                    raise X86EncodeError(
                        f"immediate {value:#x} does not fit in 32 bits (sign-extended)"
                    )
                parts.imm = (value & 0xFFFFFFFF).to_bytes(4, "little")
            else:
                parts.imm = self.imm_bytes(src.expr, size)
            return self.finish(parts, size, regs)
        if isinstance(src, Reg):
            parts.opcode = bytes([0x88 + wide])
            self.modrm(parts, src.num, dst)
            return self.finish(parts, size, regs)
        if isinstance(dst, Reg) and isinstance(src, Mem):
            parts.opcode = bytes([0x8A + wide])
            self.modrm(parts, dst.num, src)
            return self.finish(parts, size, regs)
        raise X86EncodeError("invalid operands for mov")

    def unary(self, ext: int, op: Operand, size: int, opcode8: int, opcode: int) -> bytes:
        parts = _Parts()
        parts.opcode = bytes([opcode8 if size == 1 else opcode])
        self.modrm(parts, ext, op)
        return self.finish(parts, size, [op] if isinstance(op, Reg) else [])

    def shift(self, ext: int, dst: Operand, count: Optional[Operand], size: int) -> bytes:
        regs = [dst] if isinstance(dst, Reg) else []
        parts = _Parts()
        b8 = size == 1
        if count is None or (
            isinstance(count, Imm)
            and not self.is_symbolic(count.expr)
            and self.value(count.expr) == 1
        ):
            parts.opcode = b"\xd0" if b8 else b"\xd1"
        elif isinstance(count, Reg):
            if count.num != 1 or count.size != 1:
                raise X86EncodeError("the shift count register must be %cl")
            parts.opcode = b"\xd2" if b8 else b"\xd3"
        elif isinstance(count, Imm):
            parts.opcode = b"\xc0" if b8 else b"\xc1"
            parts.imm = self.imm_bytes(count.expr, 1)
        else:
            raise X86EncodeError("the shift count must be an immediate or %cl")
        self.modrm(parts, ext, dst)
        return self.finish(parts, size, regs)

    def test(self, a: Operand, b: Operand, size: int) -> bytes:
        # test is symmetric; normalize to (r/m, reg-or-imm)
        if isinstance(a, Imm):
            a, b = b, a
        if isinstance(a, Reg) and isinstance(b, Mem):
            a, b = b, a
        regs = [o for o in (a, b) if isinstance(o, Reg)]
        parts = _Parts()
        if isinstance(b, Imm):
            imm_size = min(size, 4)
            if isinstance(a, Reg) and a.num == 0 and not a.high8:
                parts.opcode = b"\xa8" if size == 1 else b"\xa9"
            else:
                parts.opcode = b"\xf6" if size == 1 else b"\xf7"
                self.modrm(parts, 0, a)
            value = self.value(b.expr)
            parts.imm = (value & ((1 << (8 * imm_size)) - 1)).to_bytes(imm_size, "little")
            return self.finish(parts, size, regs)
        if isinstance(b, Reg):
            parts.opcode = b"\x84" if size == 1 else b"\x85"
            self.modrm(parts, b.num, a)
            return self.finish(parts, size, regs)
        raise X86EncodeError("invalid operands for test")

    def jump(self, kind: str, cond: int, target: Target) -> bytes:
        """jmp/jcc/call to a label. jmp and jcc use rel8 unless the layout
        pass decided this jump needs rel32 (GNU as's relaxation)."""
        dest = self.value(target.expr)
        if kind == "call":
            return b"\xe8" + ((dest - (self.pc + 5)) & 0xFFFFFFFF).to_bytes(4, "little")
        if not self.long_jump:
            rel8 = dest - (self.pc + 2)
            if self.ctx.strict and not _fits8(rel8):
                raise X86EncodeError("internal error: short jump out of range; please report this")
            op = 0xEB if kind == "jmp" else 0x70 + cond
            return bytes([op, rel8 & 0xFF])
        if kind == "jmp":
            return b"\xe9" + ((dest - (self.pc + 5)) & 0xFFFFFFFF).to_bytes(4, "little")
        return bytes([0x0F, 0x80 + cond]) + ((dest - (self.pc + 6)) & 0xFFFFFFFF).to_bytes(
            4, "little"
        )


def _raise(name: str) -> int:
    raise UndefinedSymbol(name)


# ---------------------------------------------------------------------------
# Instruction dispatch
# ---------------------------------------------------------------------------

_SPECIAL = {
    "movzbw": ("movzx", 1, 2), "movzbl": ("movzx", 1, 4), "movzbq": ("movzx", 1, 8),
    "movzwl": ("movzx", 2, 4), "movzwq": ("movzx", 2, 8),
    "movsbw": ("movsx", 1, 2), "movsbl": ("movsx", 1, 4), "movsbq": ("movsx", 1, 8),
    "movswl": ("movsx", 2, 4), "movswq": ("movsx", 2, 8), "movslq": ("movsxd", 4, 8),
}  # fmt: skip

_NO_OPERANDS = {
    "ret": b"\xc3", "leave": b"\xc9", "nop": b"\x90", "hlt": b"\xf4", "syscall": b"\x0f\x05",
    "int3": b"\xcc", "cbw": b"\x66\x98", "cbtw": b"\x66\x98", "cwde": b"\x98", "cwtl": b"\x98",
    "cdqe": b"\x48\x98", "cltq": b"\x48\x98", "cwd": b"\x66\x99", "cwtd": b"\x66\x99",
    "cdq": b"\x99", "cltd": b"\x99", "cqo": b"\x48\x99", "cqto": b"\x48\x99", "ud2": b"\x0f\x0b",
}  # fmt: skip

_BASE_MNEMONICS = set(ALU_OPS) | set(SHIFT_OPS) | set(UNARY_OPS) | {
    "mov", "movabs", "lea", "test", "inc", "dec", "imul", "push", "pop", "xchg", "jmp",
    "call", "ret", "movzx", "movsx", "movsxd",
}  # fmt: skip


def _split_mnemonic(m: str) -> Tuple[str, Optional[int]]:
    """Split an AT&T mnemonic into (base, size from suffix)."""
    if m in _BASE_MNEMONICS or m in _NO_OPERANDS or m in _SPECIAL:
        return m, None
    if m[:-1] in _BASE_MNEMONICS and m[-1] in SIZE_SUFFIX:
        return m[:-1], SIZE_SUFFIX[m[-1]]
    for prefix in ("set", "cmov"):
        if m.startswith(prefix):
            rest = m[len(prefix) :]
            if rest in CONDITIONS:
                return m, None
            if rest[:-1] in CONDITIONS and rest[-1] in SIZE_SUFFIX:
                return m[:-1], SIZE_SUFFIX[rest[-1]]
    return m, None


def _looks_att(ops_text: str) -> bool:
    return "%" in ops_text or "$" in ops_text or ops_text.lstrip().startswith("*")


def encode_instruction(
    text: str,
    ctx: Context,
    syntax: str,
    absolute_symbols: Set[str],
    long_jump: bool,
) -> bytes:
    parts = text.strip().split(None, 1)
    if not parts:
        raise X86EncodeError("empty instruction")
    mnemonic = parts[0].lower()
    ops_text = parts[1] if len(parts) > 1 else ""
    enc = Encoder(ctx, absolute_symbols, long_jump)

    if mnemonic in _NO_OPERANDS and not ops_text:
        return _NO_OPERANDS[mnemonic]

    att = syntax == "att" or (syntax == "auto" and (_looks_att(ops_text) or not ops_text))
    if syntax == "auto" and not att and _split_mnemonic(mnemonic)[1] is not None:
        # A size suffix ("imulq d0") only exists in AT&T syntax.
        att = True
    base, suffix = _split_mnemonic(mnemonic) if att else (mnemonic, None)
    is_branch = base in ("jmp", "call") or (base.startswith("j") and base[1:] in CONDITIONS)
    raw = _split(ops_text) if ops_text else []
    operands: List[Operand] = []
    indirect = False
    if att:
        for r in raw:
            op, ind = parse_att_operand(r, is_branch)
            operands.append(op)
            indirect = indirect or ind
        operands.reverse()  # AT&T is source, destination
    else:
        operands = [parse_intel_operand(r, is_branch, enc.is_absolute) for r in raw]
        if is_branch and operands and not isinstance(operands[0], Target):
            indirect = True

    try:
        return _dispatch(enc, base, suffix, operands, indirect, mnemonic)
    except ExpressionError as e:
        raise X86EncodeError(str(e))


def _dispatch(  # noqa: C901
    enc: Encoder,
    m: str,
    suffix: Optional[int],
    ops: List[Operand],
    indirect: bool,
    original: str,
) -> bytes:
    def expect(n: int) -> None:
        if len(ops) != n:
            raise X86EncodeError(f"'{original}' takes {n} operand{'s' if n != 1 else ''}")

    regs = [o for o in ops if isinstance(o, Reg)]

    if m in _NO_OPERANDS:
        if m == "ret" and len(ops) == 1 and isinstance(ops[0], Imm):
            return b"\xc2" + enc.imm_bytes(ops[0].expr, 2)
        expect(0)
        return _NO_OPERANDS[m]

    if m == "int":
        expect(1)
        if not isinstance(ops[0], Imm):
            raise X86EncodeError("int takes an immediate")
        return b"\xcd" + enc.imm_bytes(ops[0].expr, 1)

    # Jumps and calls
    if m in ("jmp", "call") or (m.startswith("j") and m[1:] in CONDITIONS):
        expect(1)
        target = ops[0]
        if indirect or isinstance(target, (Reg, Mem)):
            if m not in ("jmp", "call"):
                raise X86EncodeError("conditional jumps cannot be indirect")
            if isinstance(target, Reg) and target.size != 8:
                raise X86EncodeError(f"{m} through a register needs a 64-bit register")
            parts = _Parts(opcode=b"\xff")
            enc.modrm(parts, 4 if m == "jmp" else 2, target)
            return enc.finish(parts, 8, regs, default64=True)
        if not isinstance(target, Target):
            raise X86EncodeError(f"{m} needs a label")
        kind = m if m in ("jmp", "call") else "jcc"
        return enc.jump(kind, CONDITIONS.get(m[1:], 0), target)

    if m.startswith("set") and m[3:] in CONDITIONS:
        expect(1)
        size = (
            Encoder.operand_size(ops, suffix or 1, original) if not isinstance(ops[0], Mem) else 1
        )
        if size != 1:
            raise X86EncodeError("set<cc> takes an 8-bit operand")
        parts = _Parts(opcode=bytes([0x0F, 0x90 + CONDITIONS[m[3:]]]))
        enc.modrm(parts, 0, ops[0])
        return enc.finish(parts, 1, regs)

    if m.startswith("cmov") and m[4:] in CONDITIONS:
        expect(2)
        dst, src = ops
        if not isinstance(dst, Reg):
            raise X86EncodeError("cmov needs a register destination")
        size = Encoder.operand_size(ops, suffix, original)
        parts = _Parts(opcode=bytes([0x0F, 0x40 + CONDITIONS[m[4:]]]))
        enc.modrm(parts, dst.num, src)
        return enc.finish(parts, size, regs)

    if m in ALU_OPS:
        expect(2)
        dst, src = ops
        size = Encoder.operand_size(ops, suffix, original)
        return enc.alu(ALU_OPS[m], dst, src, size)

    if m in ("mov", "movabs"):
        expect(2)
        dst, src = ops
        size = Encoder.operand_size(ops, suffix, original)
        return enc.mov(dst, src, size, movabs=m == "movabs")

    if m == "lea":
        expect(2)
        dst, src = ops
        if not isinstance(dst, Reg) or not isinstance(src, Mem):
            raise X86EncodeError("lea takes a memory operand and a register")
        parts = _Parts(opcode=b"\x8d")
        enc.modrm(parts, dst.num, src)
        return enc.finish(parts, suffix or dst.size, regs)

    if m == "test":
        expect(2)
        return enc.test(ops[0], ops[1], Encoder.operand_size(ops, suffix, original))

    if m in ("inc", "dec"):
        expect(1)
        size = Encoder.operand_size(ops, suffix, original)
        return enc.unary(0 if m == "inc" else 1, ops[0], size, 0xFE, 0xFF)

    if m in UNARY_OPS:
        expect(1)
        size = Encoder.operand_size(ops, suffix, original)
        return enc.unary(UNARY_OPS[m], ops[0], size, 0xF6, 0xF7)

    if m == "imul":
        if len(ops) == 1:
            size = Encoder.operand_size(ops, suffix, original)
            return enc.unary(5, ops[0], size, 0xF6, 0xF7)
        if len(ops) == 2 and isinstance(ops[1], Imm):
            ops = [ops[0], ops[0], ops[1]]  # imul $imm, %reg == imul $imm, %reg, %reg
        if len(ops) == 2:
            dst, src = ops
            if not isinstance(dst, Reg):
                raise X86EncodeError("imul needs a register destination")
            size = Encoder.operand_size(ops, suffix, original)
            parts = _Parts(opcode=b"\x0f\xaf")
            enc.modrm(parts, dst.num, src)
            return enc.finish(parts, size, regs)
        if len(ops) == 3:
            dst, src, imm = ops
            if not isinstance(dst, Reg) or not isinstance(imm, Imm):
                raise X86EncodeError("expected imul $imm, source, register")
            size = Encoder.operand_size([dst, src], suffix, original)
            value = enc.value(imm.expr)
            parts = _Parts()
            if not enc.is_symbolic(imm.expr) and _fits8(value):
                parts.opcode = b"\x6b"
                parts.imm = (value & 0xFF).to_bytes(1, "little")
            else:
                parts.opcode = b"\x69"
                parts.imm = (value & ((1 << (16 if size == 2 else 32)) - 1)).to_bytes(
                    2 if size == 2 else 4, "little"
                )
            enc.modrm(parts, dst.num, src)
            return enc.finish(parts, size, [r for r in (dst, src) if isinstance(r, Reg)])
        raise X86EncodeError("imul takes 1, 2, or 3 operands")

    if m in SHIFT_OPS:
        if len(ops) == 1:
            dst, count = ops[0], None
        else:
            expect(2)
            dst, count = ops[0], ops[1]
        size = Encoder.operand_size([dst], suffix, original)
        return enc.shift(SHIFT_OPS[m], dst, count, size)

    if m in ("push", "pop"):
        expect(1)
        op = ops[0]
        if isinstance(op, Reg):
            if op.size not in (8, 2):
                raise X86EncodeError(f"{m} takes a 64-bit register")
            parts = _Parts(opcode=bytes([(0x50 if m == "push" else 0x58) + (op.num & 7)]))
            parts.rex |= 1 if op.num >= 8 else 0
            return enc.finish(parts, op.size, [op], default64=True)
        if isinstance(op, Imm):
            if m == "pop":
                raise X86EncodeError("pop needs a register or memory destination")
            value = enc.value(op.expr)
            if not enc.is_symbolic(op.expr) and _fits8(value):
                return b"\x6a" + (value & 0xFF).to_bytes(1, "little")
            return b"\x68" + (value & 0xFFFFFFFF).to_bytes(4, "little")
        size = suffix or 8
        parts = _Parts(opcode=b"\xff" if m == "push" else b"\x8f")
        enc.modrm(parts, 6 if m == "push" else 0, op)
        return enc.finish(parts, size, [], default64=True)

    if m == "xchg":
        expect(2)
        a, b = ops
        size = Encoder.operand_size(ops, suffix, original)
        both = isinstance(a, Reg) and isinstance(b, Reg)
        if both and size == 8 and a.num == 0 and b.num == 0:
            return b"\x90"  # GNU drops REX.W: it is just nop
        # 90 would be nop, which (unlike xchg) leaves the top of rax alone.
        same32 = both and size == 4 and a.num == 0 and b.num == 0
        if both and size != 1 and not same32 and (a.num == 0 or b.num == 0):
            other = b if a.num == 0 else a
            parts = _Parts(opcode=bytes([0x90 + (other.num & 7)]))
            parts.rex |= 1 if other.num >= 8 else 0
            return enc.finish(parts, size, regs)
        if isinstance(b, Reg):
            a, b = b, a
        if not isinstance(a, Reg):
            raise X86EncodeError("xchg needs a register operand")
        parts = _Parts(opcode=b"\x86" if size == 1 else b"\x87")
        enc.modrm(parts, a.num, b)
        return enc.finish(parts, size, regs)

    if m in ("movzx", "movsx", "movsxd") or m in _SPECIAL:
        expect(2)
        dst, src = ops
        if m in _SPECIAL:
            kind, src_size, dst_size = _SPECIAL[m]
        else:
            kind = m
            if not isinstance(dst, Reg):
                raise X86EncodeError(f"{m} needs a register destination")
            dst_size = dst.size
            src_size = (
                src.size
                if isinstance(src, (Reg, Mem)) and src.size
                else (4 if m == "movsxd" else (suffix or 0))
            )
            if not src_size:
                raise X86EncodeError(f"cannot tell the source size of '{m}'; use e.g. 'byte ptr'")
        if not isinstance(dst, Reg) or dst.size != dst_size:
            raise X86EncodeError(f"{original} needs a {8 * dst_size}-bit register destination")
        if isinstance(src, Reg) and src.size != src_size:
            raise X86EncodeError(f"{original} needs a {8 * src_size}-bit source")
        parts = _Parts()
        if kind == "movsxd":
            parts.opcode = b"\x63"
        else:
            base = 0xB6 if kind == "movzx" else 0xBE
            parts.opcode = bytes([0x0F, base + (1 if src_size == 2 else 0)])
        enc.modrm(parts, dst.num, src)
        return enc.finish(parts, dst_size, regs)

    raise X86EncodeError(f"unknown instruction '{original}'")


# ---------------------------------------------------------------------------
# Module interface used by the assembler
# ---------------------------------------------------------------------------


def _context(address: int, labels: Dict[str, int], strict: bool) -> Context:
    return Context(address, labels, strict=strict, error=X86EncodeError)


def is_relaxable(text: str) -> bool:
    """True for jmp/jcc to a label, whose size depends on the distance."""
    parts = text.strip().split(None, 1)
    if len(parts) != 2:
        return False
    m = parts[0].lower()
    op = parts[1].strip()
    if op.startswith(("*", "%", "[")) or _reg_or_none(op) is not None:
        return False
    return m == "jmp" or (m.startswith("j") and m[1:] in CONDITIONS)


def encode(
    text: str,
    address: int,
    labels: Dict[str, int],
    syntax: str = "auto",
    absolute_symbols: Optional[Set[str]] = None,
    long_jump: bool = False,
) -> bytes:
    """
    Encode one x86-64 instruction.

    Args:
        syntax: "att", "intel", or "auto" (decided per instruction).
        absolute_symbols: Names that are constants (.equ), not addresses.
        long_jump: Use the rel32 form for jmp/jcc (decided by layout).

    Raises:
        X86EncodeError: If the instruction is invalid.
    """
    return encode_instruction(
        text, _context(address, labels, True), syntax, absolute_symbols or set(), long_jump
    )


def instruction_size(
    text: str,
    labels: Dict[str, int],
    address: int = 0,
    syntax: str = "auto",
    absolute_symbols: Optional[Set[str]] = None,
    long_jump: bool = False,
) -> int:
    """Size in bytes, for the layout pass (unknown labels count as 0)."""
    try:
        return len(
            encode_instruction(
                text, _context(address, labels, False), syntax, absolute_symbols or set(), long_jump
            )
        )
    except (X86EncodeError, ExpressionError):
        return 1  # the real error is reported by encode()


# The nops GNU as pads code with, by length
_NOPS = [bytes.fromhex(h) for h in (
    "90",
    "6690",
    "0f1f00",
    "0f1f4000",
    "0f1f440000",
    "660f1f440000",
    "0f1f8000000000",
    "0f1f840000000000",
    "660f1f840000000000",
    "662e0f1f840000000000",
    "66662e0f1f840000000000",
)]  # fmt: skip


def nop_padding(count: int, after_data: bool) -> bytes:
    """Alignment padding of ``count`` bytes, as GNU as generates it.

    After data (which might be part of an instruction) it starts with a
    one-byte nop. More than 7 of the longest nops are jumped over.
    """
    out = bytearray()
    if after_data and count:
        out.append(0x90)
        count -= 1
    if count // len(_NOPS) > 7:
        if count - 2 < 128:
            count -= 2
            out += bytes([0xEB, count])
        else:
            count -= 5
            out += b"\xe9" + count.to_bytes(4, "little")
    longest = _NOPS[-1]
    out += longest * (count // len(longest))
    if count % len(longest):
        out += _NOPS[count % len(longest) - 1]
    return bytes(out)


def short_jump_fits(
    text: str, address: int, labels: Mapping[str, int], syntax: str = "auto"
) -> bool:
    """Whether a relaxable jump at ``address`` reaches its target with rel8."""
    parts = text.strip().split(None, 1)
    try:
        dest = evaluate(parts[1].strip(), lambda n: labels[n] if n in labels else _raise(n))
    except ExpressionError:
        return True  # unknown yet: stay short
    return _fits8(dest - (address + 2))
