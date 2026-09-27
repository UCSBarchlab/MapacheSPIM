"""
Pure-Python RISC-V (RV64IM) instruction encoder.

The Keystone release on PyPI has no RISC-V support, so MapacheSPIM encodes
RISC-V itself. RISC-V's six instruction formats are regular enough that a
table-driven encoder is short, and doing it here means the most commonly
taught ISA needs no native assembler library at all.

Supported:
    - RV64I base integer instructions (including the *W word variants)
    - M extension (multiply/divide)
    - ecall, ebreak, fence, and the Zicsr instructions
    - Common pseudo-instructions: nop, li, la, lla, mv, not, neg, negw,
      sext.w, seqz, snez, sltz, sgtz, beqz, bnez, blez, bgez, bltz, bgtz,
      bgt, ble, bgtu, bleu, j, jr, ret, call, tail, csrr, csrw, csrs, csrc
    - Operand expressions: integers (dec/hex/bin/octal), character
      literals, symbols, symbol +/- constant, %hi(), %lo(),
      %pcrel_hi(), %pcrel_lo()

Compressed (C extension) instructions are never emitted, so every
instruction is 4 bytes, matching what the simulator's disassembler shows.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

INSTR_SIZE = 4


class RISCVEncodeError(ValueError):
    """Raised when an instruction cannot be encoded."""


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

_ABI_NAMES = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
]  # fmt: skip

REGISTERS: Dict[str, int] = {name: i for i, name in enumerate(_ABI_NAMES)}
REGISTERS.update({f"x{i}": i for i in range(32)})
REGISTERS["fp"] = 8


def parse_register(text: str) -> int:
    name = text.strip().lower()
    if name not in REGISTERS:
        raise RISCVEncodeError(f"unknown register '{text.strip()}'")
    return REGISTERS[name]


# ---------------------------------------------------------------------------
# CSRs (a small set of names; any CSR can also be given by number)
# ---------------------------------------------------------------------------

CSR_NAMES: Dict[str, int] = {
    "fflags": 0x001, "frm": 0x002, "fcsr": 0x003,
    "cycle": 0xC00, "time": 0xC01, "instret": 0xC02,
    "mstatus": 0x300, "misa": 0x301, "mie": 0x304, "mtvec": 0x305,
    "mscratch": 0x340, "mepc": 0x341, "mcause": 0x342, "mtval": 0x343, "mip": 0x344,
    "mhartid": 0xF14,
}  # fmt: skip


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

_RELOC_RE = re.compile(r"^%(hi|lo|pcrel_hi|pcrel_lo)\((.*)\)$", re.IGNORECASE)
_TERM_RE = re.compile(r"\s*([+-]?)\s*([^+\-\s][^+\-]*)")


def _parse_int(text: str) -> Optional[int]:
    """Parse an integer or character literal, or return None."""
    t = text.strip()
    if len(t) >= 3 and t[0] == "'" and t[-1] == "'":
        body = t[1:-1]
        escapes = {"\\n": 10, "\\t": 9, "\\r": 13, "\\0": 0, "\\\\": 92, "\\'": 39}
        if body in escapes:
            return escapes[body]
        if len(body) == 1:
            return ord(body)
        return None
    try:
        return int(t, 0)
    except ValueError:
        pass
    # int(..., 0) rejects leading zeros like "010"; accept them as decimal
    if re.fullmatch(r"[+-]?\d+", t):
        return int(t, 10)
    return None


class Context:
    """Address and symbol information needed to encode one instruction."""

    def __init__(self, address: int, labels: Dict[str, int], strict: bool = True):
        self.address = address
        self.labels = labels
        # When not strict (the sizing pass), unknown symbols evaluate to 0
        self.strict = strict

    def symbol(self, name: str) -> int:
        if name in self.labels:
            return self.labels[name]
        if self.strict:
            raise RISCVEncodeError(f"undefined symbol '{name}'")
        return 0

    def eval(self, text: str) -> int:
        """Evaluate an operand expression such as 'label+8' or '%lo(msg)'."""
        text = text.strip()
        if not text:
            raise RISCVEncodeError("missing operand")

        m = _RELOC_RE.match(text)
        if m:
            kind, inner = m.group(1).lower(), m.group(2)
            value = self.eval(inner)
            if kind == "hi":
                return ((value + 0x800) >> 12) & 0xFFFFF
            if kind == "lo":
                return _sign_extend(value & 0xFFF, 12)
            if kind == "pcrel_hi":
                offset = value - self.address
                return ((offset + 0x800) >> 12) & 0xFFFFF
            # %pcrel_lo(label) names the auipc instruction; the low part is
            # relative to that instruction's pc and the auipc's target.
            raise RISCVEncodeError("%pcrel_lo is not supported; use la or lla instead")

        value = _parse_int(text)
        if value is not None:
            return value

        total = 0
        pos = 0
        matched = False
        for m2 in _TERM_RE.finditer(text):
            if m2.start() != pos and text[pos : m2.start()].strip():
                break
            sign, term = m2.group(1), m2.group(2).strip()
            v = _parse_int(term)
            if v is None:
                if not re.fullmatch(r"[A-Za-z_.$][\w.$]*", term):
                    raise RISCVEncodeError(f"cannot parse expression '{text}'")
                v = self.symbol(term)
            total += -v if sign == "-" else v
            pos = m2.end()
            matched = True
        if not matched or text[pos:].strip():
            raise RISCVEncodeError(f"cannot parse expression '{text}'")
        return total


def _sign_extend(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _check_signed(value: int, bits: int, what: str) -> int:
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    if not lo <= value <= hi:
        raise RISCVEncodeError(f"{what} {value} out of range ({lo} to {hi})")
    return value


def _check_unsigned(value: int, bits: int, what: str) -> int:
    if not 0 <= value < (1 << bits):
        raise RISCVEncodeError(f"{what} {value} out of range (0 to {(1 << bits) - 1})")
    return value


# ---------------------------------------------------------------------------
# Instruction formats
# ---------------------------------------------------------------------------


def _r(opcode: int, f3: int, f7: int, rd: int, rs1: int, rs2: int) -> int:
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opcode


def _i(opcode: int, f3: int, rd: int, rs1: int, imm: int) -> int:
    imm = _check_signed(imm, 12, "immediate")
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opcode


def _s(opcode: int, f3: int, rs1: int, rs2: int, imm: int) -> int:
    imm = _check_signed(imm, 12, "offset") & 0xFFF
    return (
        ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 0x1F) << 7) | opcode
    )


def _b(f3: int, rs1: int, rs2: int, offset: int) -> int:
    if offset % 2:
        raise RISCVEncodeError(f"branch offset {offset} is not a multiple of 2")
    offset = _check_signed(offset, 13, "branch offset") & 0x1FFF
    return (
        (((offset >> 12) & 1) << 31)
        | (((offset >> 5) & 0x3F) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (f3 << 12)
        | (((offset >> 1) & 0xF) << 8)
        | (((offset >> 11) & 1) << 7)
        | 0x63
    )


def _u(opcode: int, rd: int, imm20: int) -> int:
    # Accept both unsigned (0..0xFFFFF) and negative 20-bit forms
    if -(1 << 19) <= imm20 < 0:
        imm20 &= 0xFFFFF
    _check_unsigned(imm20, 20, "upper immediate")
    return (imm20 << 12) | (rd << 7) | opcode


def _j(rd: int, offset: int) -> int:
    if offset % 2:
        raise RISCVEncodeError(f"jump offset {offset} is not a multiple of 2")
    offset = _check_signed(offset, 21, "jump offset") & 0x1FFFFF
    return (
        (((offset >> 20) & 1) << 31)
        | (((offset >> 1) & 0x3FF) << 21)
        | (((offset >> 11) & 1) << 20)
        | (((offset >> 12) & 0xFF) << 12)
        | (rd << 7)
        | 0x6F
    )


# (opcode, funct3, funct7)
R_TYPE: Dict[str, Tuple[int, int, int]] = {
    "add": (0x33, 0, 0x00), "sub": (0x33, 0, 0x20), "sll": (0x33, 1, 0x00),
    "slt": (0x33, 2, 0x00), "sltu": (0x33, 3, 0x00), "xor": (0x33, 4, 0x00),
    "srl": (0x33, 5, 0x00), "sra": (0x33, 5, 0x20), "or": (0x33, 6, 0x00),
    "and": (0x33, 7, 0x00),
    "addw": (0x3B, 0, 0x00), "subw": (0x3B, 0, 0x20), "sllw": (0x3B, 1, 0x00),
    "srlw": (0x3B, 5, 0x00), "sraw": (0x3B, 5, 0x20),
    # M extension
    "mul": (0x33, 0, 0x01), "mulh": (0x33, 1, 0x01), "mulhsu": (0x33, 2, 0x01),
    "mulhu": (0x33, 3, 0x01), "div": (0x33, 4, 0x01), "divu": (0x33, 5, 0x01),
    "rem": (0x33, 6, 0x01), "remu": (0x33, 7, 0x01),
    "mulw": (0x3B, 0, 0x01), "divw": (0x3B, 4, 0x01), "divuw": (0x3B, 5, 0x01),
    "remw": (0x3B, 6, 0x01), "remuw": (0x3B, 7, 0x01),
}  # fmt: skip

# (opcode, funct3)
I_ALU: Dict[str, Tuple[int, int]] = {
    "addi": (0x13, 0), "slti": (0x13, 2), "sltiu": (0x13, 3),
    "xori": (0x13, 4), "ori": (0x13, 6), "andi": (0x13, 7),
    "addiw": (0x1B, 0),
}  # fmt: skip

# (opcode, funct3, funct6/7 high bits, shamt bits)
SHIFT_IMM: Dict[str, Tuple[int, int, int, int]] = {
    "slli": (0x13, 1, 0x00, 6), "srli": (0x13, 5, 0x00, 6), "srai": (0x13, 5, 0x10, 6),
    "slliw": (0x1B, 1, 0x00, 5), "srliw": (0x1B, 5, 0x00, 5), "sraiw": (0x1B, 5, 0x20, 5),
}  # fmt: skip

LOADS: Dict[str, int] = {"lb": 0, "lh": 1, "lw": 2, "ld": 3, "lbu": 4, "lhu": 5, "lwu": 6}
STORES: Dict[str, int] = {"sb": 0, "sh": 1, "sw": 2, "sd": 3}
BRANCHES: Dict[str, int] = {"beq": 0, "bne": 1, "blt": 4, "bge": 5, "bltu": 6, "bgeu": 7}
CSR_OPS: Dict[str, int] = {
    "csrrw": 1, "csrrs": 2, "csrrc": 3, "csrrwi": 5, "csrrsi": 6, "csrrci": 7,
}  # fmt: skip

# Pseudo-branches: name -> (real branch, swap operands, zero operand position)
ZERO_BRANCHES: Dict[str, Tuple[str, bool]] = {
    # name: (real, register goes second)
    "beqz": ("beq", False), "bnez": ("bne", False),
    "bltz": ("blt", False), "bgez": ("bge", False),
    "blez": ("bge", True), "bgtz": ("blt", True),
}  # fmt: skip
SWAP_BRANCHES: Dict[str, str] = {"bgt": "blt", "ble": "bge", "bgtu": "bltu", "bleu": "bgeu"}


# ---------------------------------------------------------------------------
# Operand helpers
# ---------------------------------------------------------------------------


def split_operands(text: str) -> List[str]:
    """Split operands on commas that are not inside parentheses or quotes."""
    ops: List[str] = []
    depth = 0
    quote = False
    cur = ""
    for ch in text:
        if ch == "'" and depth == 0:
            quote = not quote
        if not quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                ops.append(cur.strip())
                cur = ""
                continue
        cur += ch
    if cur.strip() or ops:
        ops.append(cur.strip())
    return ops


_MEM_RE = re.compile(r"^(.*)\(\s*([A-Za-z0-9]+)\s*\)$")


def _parse_mem(text: str, ctx: Context) -> Tuple[int, int]:
    """Parse 'imm(reg)' (imm optional) into (offset, reg)."""
    m = _MEM_RE.match(text.strip())
    if not m:
        raise RISCVEncodeError(f"expected offset(register), got '{text}'")
    offset_text = m.group(1).strip()
    offset = ctx.eval(offset_text) if offset_text else 0
    return offset, parse_register(m.group(2))


def _is_mem_operand(text: str) -> bool:
    m = _MEM_RE.match(text.strip())
    return bool(m) and m.group(2).lower() in REGISTERS


def _expect(ops: List[str], n: int, usage: str) -> None:
    if len(ops) != n:
        raise RISCVEncodeError(f"expected {usage}")


def _parse_csr(text: str, ctx: Context) -> int:
    name = text.strip().lower()
    if name in CSR_NAMES:
        return CSR_NAMES[name]
    return _check_unsigned(ctx.eval(text), 12, "CSR number")


# ---------------------------------------------------------------------------
# li expansion (shared by encoding and sizing)
# ---------------------------------------------------------------------------


def _li_sequence(rd: int, value: int) -> List[int]:
    """Instruction words that load a 64-bit constant into rd."""
    value = _sign_extend(value, 64)
    if -2048 <= value <= 2047:
        return [_i(0x13, 0, rd, 0, value)]  # addi rd, x0, value
    if -(1 << 31) <= value < (1 << 31):
        lo = _sign_extend(value & 0xFFF, 12)
        hi = ((value - lo) >> 12) & 0xFFFFF
        words = [_u(0x37, rd, hi)]  # lui
        if lo:
            words.append(_i(0x1B, 0, rd, rd, lo))  # addiw keeps it 32-bit sign-extended
        return words
    # 64-bit: build the upper bits recursively, then shift in 12 bits at a time
    lo = _sign_extend(value & 0xFFF, 12)
    upper = (value - lo) >> 12
    shift = 12
    while upper and not upper & 1 and shift < 60:
        upper >>= 1
        shift += 1
    words = _li_sequence(rd, upper)
    words.append((((shift & 0x3F) << 20) | (rd << 15) | (1 << 12) | (rd << 7) | 0x13))  # slli
    if lo:
        words.append(_i(0x13, 0, rd, rd, lo))
    return words


def _pcrel_pair(target: int, pc: int) -> Tuple[int, int]:
    """Split a pc-relative offset into auipc (hi20) and addi/jalr (lo12) parts."""
    offset = target - pc
    lo = _sign_extend(offset & 0xFFF, 12)
    hi = ((offset - lo) >> 12) & 0xFFFFF
    return hi, lo


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


def _encode(mnemonic: str, ops: List[str], ctx: Context) -> List[int]:
    m = mnemonic
    pc = ctx.address

    def target_offset(text: str) -> int:
        """Branch/jump operand: a label (pc-relative) or a literal offset."""
        value = _parse_int(text)
        if value is not None:
            return value
        return ctx.eval(text) - pc

    if m in R_TYPE:
        _expect(ops, 3, f"{m} rd, rs1, rs2")
        opcode, f3, f7 = R_TYPE[m]
        return [_r(opcode, f3, f7, parse_register(ops[0]), parse_register(ops[1]), parse_register(ops[2]))]

    if m in I_ALU:
        _expect(ops, 3, f"{m} rd, rs1, imm")
        opcode, f3 = I_ALU[m]
        return [_i(opcode, f3, parse_register(ops[0]), parse_register(ops[1]), ctx.eval(ops[2]))]

    if m in SHIFT_IMM:
        _expect(ops, 3, f"{m} rd, rs1, shamt")
        opcode, f3, hi, bits = SHIFT_IMM[m]
        shamt = _check_unsigned(ctx.eval(ops[2]), bits, "shift amount")
        rd, rs1 = parse_register(ops[0]), parse_register(ops[1])
        return [((hi << 26) if bits == 6 else (hi << 25)) | (shamt << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opcode]

    if m in LOADS:
        _expect(ops, 2, f"{m} rd, offset(rs1)")
        rd = parse_register(ops[0])
        if _is_mem_operand(ops[1]):
            offset, rs1 = _parse_mem(ops[1], ctx)
            return [_i(0x03, LOADS[m], rd, rs1, offset)]
        # 'lw rd, symbol' -> auipc rd, %pcrel_hi(symbol); lw rd, %pcrel_lo(rd)
        hi, lo = _pcrel_pair(ctx.eval(ops[1]), pc)
        return [_u(0x17, rd, hi), _i(0x03, LOADS[m], rd, rd, lo)]

    if m in STORES:
        if len(ops) == 3:
            # 'sw rs2, symbol, rt' -> auipc rt, hi; sw rs2, lo(rt)
            rs2, rt = parse_register(ops[0]), parse_register(ops[2])
            hi, lo = _pcrel_pair(ctx.eval(ops[1]), pc)
            return [_u(0x17, rt, hi), _s(0x23, STORES[m], rt, rs2, lo)]
        _expect(ops, 2, f"{m} rs2, offset(rs1)")
        offset, rs1 = _parse_mem(ops[1], ctx)
        return [_s(0x23, STORES[m], rs1, parse_register(ops[0]), offset)]

    if m in BRANCHES:
        _expect(ops, 3, f"{m} rs1, rs2, label")
        return [_b(BRANCHES[m], parse_register(ops[0]), parse_register(ops[1]), target_offset(ops[2]))]

    if m in SWAP_BRANCHES:
        _expect(ops, 3, f"{m} rs1, rs2, label")
        real = SWAP_BRANCHES[m]
        return [_b(BRANCHES[real], parse_register(ops[1]), parse_register(ops[0]), target_offset(ops[2]))]

    if m in ZERO_BRANCHES:
        _expect(ops, 2, f"{m} rs, label")
        real, reg_second = ZERO_BRANCHES[m]
        rs = parse_register(ops[0])
        rs1, rs2 = (0, rs) if reg_second else (rs, 0)
        return [_b(BRANCHES[real], rs1, rs2, target_offset(ops[1]))]

    if m == "lui":
        _expect(ops, 2, "lui rd, imm")
        return [_u(0x37, parse_register(ops[0]), ctx.eval(ops[1]))]

    if m == "auipc":
        _expect(ops, 2, "auipc rd, imm")
        return [_u(0x17, parse_register(ops[0]), ctx.eval(ops[1]))]

    if m == "jal":
        if len(ops) == 1:
            return [_j(1, target_offset(ops[0]))]
        _expect(ops, 2, "jal [rd,] label")
        return [_j(parse_register(ops[0]), target_offset(ops[1]))]

    if m == "jalr":
        if len(ops) == 1:
            if _is_mem_operand(ops[0]):
                offset, rs1 = _parse_mem(ops[0], ctx)
                return [_i(0x67, 0, 1, rs1, offset)]
            return [_i(0x67, 0, 1, parse_register(ops[0]), 0)]
        if len(ops) == 2:
            if _is_mem_operand(ops[1]):
                offset, rs1 = _parse_mem(ops[1], ctx)
                return [_i(0x67, 0, parse_register(ops[0]), rs1, offset)]
            return [_i(0x67, 0, parse_register(ops[0]), parse_register(ops[1]), 0)]
        _expect(ops, 3, "jalr rd, rs1, offset")
        return [_i(0x67, 0, parse_register(ops[0]), parse_register(ops[1]), ctx.eval(ops[2]))]

    if m in CSR_OPS:
        _expect(ops, 3, f"{m} rd, csr, source")
        csr = _parse_csr(ops[1], ctx)
        rd = parse_register(ops[0])
        if m.endswith("i"):
            src = _check_unsigned(ctx.eval(ops[2]), 5, "CSR immediate")
        else:
            src = parse_register(ops[2])
        return [(csr << 20) | (src << 15) | (CSR_OPS[m] << 12) | (rd << 7) | 0x73]

    # --- no-operand instructions ---
    if m in ("ecall", "ebreak", "nop", "ret", "fence", "fence.i"):
        if ops and m != "fence":
            raise RISCVEncodeError(f"{m} takes no operands")
        if m == "ecall":
            return [0x00000073]
        if m == "ebreak":
            return [0x00100073]
        if m == "nop":
            return [_i(0x13, 0, 0, 0, 0)]
        if m == "ret":
            return [_i(0x67, 0, 0, 1, 0)]
        if m == "fence.i":
            return [0x0000100F]
        return [0x0FF0000F]  # fence iorw, iorw

    # --- pseudo-instructions ---
    if m == "li":
        _expect(ops, 2, "li rd, imm")
        return _li_sequence(parse_register(ops[0]), ctx.eval(ops[1]))

    if m in ("la", "lla"):
        _expect(ops, 2, f"{m} rd, symbol")
        rd = parse_register(ops[0])
        hi, lo = _pcrel_pair(ctx.eval(ops[1]), pc)
        return [_u(0x17, rd, hi), _i(0x13, 0, rd, rd, lo)]

    if m == "mv":
        _expect(ops, 2, "mv rd, rs")
        return [_i(0x13, 0, parse_register(ops[0]), parse_register(ops[1]), 0)]

    if m == "not":
        _expect(ops, 2, "not rd, rs")
        return [_i(0x13, 4, parse_register(ops[0]), parse_register(ops[1]), -1)]

    if m in ("neg", "negw"):
        _expect(ops, 2, f"{m} rd, rs")
        opcode = 0x33 if m == "neg" else 0x3B
        return [_r(opcode, 0, 0x20, parse_register(ops[0]), 0, parse_register(ops[1]))]

    if m == "sext.w":
        _expect(ops, 2, "sext.w rd, rs")
        return [_i(0x1B, 0, parse_register(ops[0]), parse_register(ops[1]), 0)]

    if m == "seqz":
        _expect(ops, 2, "seqz rd, rs")
        return [_i(0x13, 3, parse_register(ops[0]), parse_register(ops[1]), 1)]

    if m == "snez":
        _expect(ops, 2, "snez rd, rs")
        return [_r(0x33, 3, 0, parse_register(ops[0]), 0, parse_register(ops[1]))]

    if m == "sltz":
        _expect(ops, 2, "sltz rd, rs")
        return [_r(0x33, 2, 0, parse_register(ops[0]), parse_register(ops[1]), 0)]

    if m == "sgtz":
        _expect(ops, 2, "sgtz rd, rs")
        return [_r(0x33, 2, 0, parse_register(ops[0]), 0, parse_register(ops[1]))]

    if m == "j":
        _expect(ops, 1, "j label")
        return [_j(0, target_offset(ops[0]))]

    if m == "jr":
        _expect(ops, 1, "jr rs")
        return [_i(0x67, 0, 0, parse_register(ops[0]), 0)]

    if m in ("call", "tail"):
        _expect(ops, 1, f"{m} label")
        link = 1 if m == "call" else 0
        offset = target_offset(ops[0])
        if -(1 << 20) <= offset < (1 << 20) and m == "call":
            return [_j(link, offset)]
        # Far call/tail: auipc t1 (or ra), then jalr
        scratch = 1 if m == "call" else 6
        hi, lo = _pcrel_pair(pc + offset, pc)
        return [_u(0x17, scratch, hi), _i(0x67, 0, link, scratch, lo)]

    if m in ("csrr", "csrw", "csrs", "csrc"):
        _expect(ops, 2, f"{m} ...")
        if m == "csrr":
            return [(_parse_csr(ops[1], ctx) << 20) | (2 << 12) | (parse_register(ops[0]) << 7) | 0x73]
        f3 = {"csrw": 1, "csrs": 2, "csrc": 3}[m]
        return [(_parse_csr(ops[0], ctx) << 20) | (parse_register(ops[1]) << 15) | (f3 << 12) | 0x73]

    raise RISCVEncodeError(f"unknown instruction '{mnemonic}'")


def _split_instruction(text: str) -> Tuple[str, List[str]]:
    parts = text.strip().split(None, 1)
    if not parts:
        raise RISCVEncodeError("empty instruction")
    mnemonic = parts[0].lower()
    ops = split_operands(parts[1]) if len(parts) > 1 else []
    return mnemonic, ops


def encode(text: str, address: int, labels: Dict[str, int]) -> bytes:
    """
    Encode one RISC-V instruction (or pseudo-instruction) to machine code.

    Args:
        text: Instruction text, e.g. "addi a0, a0, 1" or "la a0, msg".
        address: Address the instruction will be placed at.
        labels: Symbol table used to resolve labels and constants.

    Returns:
        Little-endian machine code (4 bytes per instruction).

    Raises:
        RISCVEncodeError: If the instruction is invalid.
    """
    mnemonic, ops = _split_instruction(text)
    words = _encode(mnemonic, ops, Context(address, labels, strict=True))
    return b"".join(w.to_bytes(4, "little") for w in words)


def instruction_size(text: str, labels: Dict[str, int]) -> int:
    """
    Size in bytes that ``encode`` will produce, for the label-layout pass.

    Label addresses are not known yet during that pass, so labels resolve to
    0. That is safe because the only size-dependent pseudo-instructions are
    li (whose size depends on the constant, and constants from .equ are known
    early) and far call/tail (which fall back to 8 bytes for undefined
    targets, handled here).
    """
    mnemonic, ops = _split_instruction(text)
    if mnemonic == "call":
        # Near calls are a single jal; programs large enough to need a far
        # call do not fit in the simulator's default memory anyway.
        return INSTR_SIZE
    if mnemonic == "tail":
        return 2 * INSTR_SIZE
    try:
        words = _encode(mnemonic, ops, Context(0, labels, strict=False))
    except RISCVEncodeError:
        return INSTR_SIZE  # the real error is reported by encode()
    return len(words) * INSTR_SIZE

