"""
Pure-Python MIPS32 (big-endian) instruction encoder.

MIPS is the ISA SPIM itself simulates, so it should assemble everywhere
without a native library. Like GNU as in its default ".set reorder" mode,
every branch and jump is followed by a nop in its delay slot, so programs
behave as students expect even though the simulator models delay slots.

Supported:
    - MIPS32 integer instructions: arithmetic/logic, shifts, set-less-than,
      mult/div and hi/lo moves, mul/madd/msub/clz/clo, loads and stores
      (including unaligned lwl/lwr/swl/swr), branches, jumps, syscall, break
    - Pseudo-instructions: nop, move, li, la, not, neg, negu, abs, b, bal,
      beqz, bnez, blt, bgt, ble, bge (and unsigned variants), mul with an
      immediate, three-operand div/divu/rem/remu, lw/sw/... from a label
    - Registers as $0-$31 or by name ($zero, $at, $v0, ..., $s8/$fp, $ra)
    - Operand expressions: integers, character literals, symbols,
      symbol +/- constant, %hi(), %lo()
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from .expr import Context, EncodeError, parse_int, sign_extend, split_operands

INSTR_SIZE = 4
NOP = 0x00000000
AT = 1  # assembler temporary used by pseudo-instructions


class MIPSEncodeError(EncodeError):
    """Raised when a MIPS instruction cannot be encoded."""


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

_NAMES = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
]  # fmt: skip

REGISTERS: Dict[str, int] = {name: i for i, name in enumerate(_NAMES)}
REGISTERS.update({str(i): i for i in range(32)})
REGISTERS["s8"] = 30


def parse_register(text: str) -> int:
    t = text.strip()
    if t.startswith("$") and t[1:].lower() in REGISTERS:
        return REGISTERS[t[1:].lower()]
    if t.lower() in REGISTERS and not t.isdigit():
        raise MIPSEncodeError(f"unknown register '{t}' (MIPS registers need a $: ${t})")
    raise MIPSEncodeError(f"unknown register '{t}' (registers look like $t0 or $8)")


def _is_register(text: str) -> bool:
    t = text.strip()
    return t.startswith("$") and t[1:].lower() in REGISTERS


# ---------------------------------------------------------------------------
# Formats
# ---------------------------------------------------------------------------


def _r(rs: int, rt: int, rd: int, shamt: int, funct: int, opcode: int = 0) -> int:
    return (opcode << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct


def _i(opcode: int, rs: int, rt: int, imm: int) -> int:
    return (opcode << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def _signed16(value: int, what: str = "immediate") -> int:
    if not -0x8000 <= value <= 0x7FFF:
        raise MIPSEncodeError(f"{what} {value} out of range (-32768 to 32767)")
    return value


def _unsigned16(value: int, what: str = "immediate") -> int:
    if not 0 <= value <= 0xFFFF:
        raise MIPSEncodeError(f"{what} {value} out of range (0 to 65535)")
    return value


# funct codes for opcode 0 (SPECIAL)
ALU3: Dict[str, int] = {
    "add": 0x20, "addu": 0x21, "sub": 0x22, "subu": 0x23,
    "and": 0x24, "or": 0x25, "xor": 0x26, "nor": 0x27,
    "slt": 0x2A, "sltu": 0x2B,
    "movn": 0x0B, "movz": 0x0A,
}  # fmt: skip
SHIFT_IMM: Dict[str, int] = {"sll": 0x00, "srl": 0x02, "sra": 0x03}
SHIFT_VAR: Dict[str, int] = {"sllv": 0x04, "srlv": 0x06, "srav": 0x07}
MULDIV: Dict[str, int] = {"mult": 0x18, "multu": 0x19, "div": 0x1A, "divu": 0x1B}
HILO_TO: Dict[str, int] = {"mfhi": 0x10, "mflo": 0x12}
HILO_FROM: Dict[str, int] = {"mthi": 0x11, "mtlo": 0x13}
# SPECIAL2 (opcode 0x1C)
SPECIAL2_ACC: Dict[str, int] = {"madd": 0x00, "maddu": 0x01, "msub": 0x04, "msubu": 0x05}

ALU_IMM: Dict[str, Tuple[int, bool]] = {
    # name: (opcode, signed immediate)
    "addi": (0x08, True), "addiu": (0x09, True), "slti": (0x0A, True),
    "sltiu": (0x0B, True), "andi": (0x0C, False), "ori": (0x0D, False),
    "xori": (0x0E, False),
}  # fmt: skip
# Register-form mnemonics that take an immediate third operand (like GNU as)
IMM_FORMS: Dict[str, str] = {
    "add": "addi", "addu": "addiu", "slt": "slti", "sltu": "sltiu",
    "and": "andi", "or": "ori", "xor": "xori",
}  # fmt: skip

LOADS: Dict[str, int] = {
    "lb": 0x20, "lh": 0x21, "lwl": 0x22, "lw": 0x23, "lbu": 0x24, "lhu": 0x25, "lwr": 0x26,
    "ll": 0x30,
}  # fmt: skip
STORES: Dict[str, int] = {"sb": 0x28, "sh": 0x29, "swl": 0x2A, "sw": 0x2B, "swr": 0x2E, "sc": 0x38}

BRANCH2: Dict[str, int] = {"beq": 0x04, "bne": 0x05}
BRANCH1: Dict[str, Tuple[int, int]] = {
    # name: (opcode, rt field)
    "blez": (0x06, 0), "bgtz": (0x07, 0),
    "bltz": (0x01, 0x00), "bgez": (0x01, 0x01),
    "bltzal": (0x01, 0x10), "bgezal": (0x01, 0x11),
}  # fmt: skip
# Comparison pseudo-branches: name -> (slt variant, swap operands, branch if $at != 0)
COMPARE_BRANCHES: Dict[str, Tuple[str, bool, bool]] = {
    "blt": ("slt", False, True), "bge": ("slt", False, False),
    "bgt": ("slt", True, True), "ble": ("slt", True, False),
    "bltu": ("sltu", False, True), "bgeu": ("sltu", False, False),
    "bgtu": ("sltu", True, True), "bleu": ("sltu", True, False),
}  # fmt: skip

_MEM_RE = re.compile(r"^(.*)\(\s*(\$\w+)\s*\)$")


def _parse_mem(text: str, ctx: Context) -> Tuple[int, int]:
    """Parse 'offset($reg)' into (offset, reg)."""
    m = _MEM_RE.match(text.strip())
    if not m:
        raise MIPSEncodeError(f"expected offset($register), got '{text}'")
    offset_text = m.group(1).strip()
    offset = ctx.eval(offset_text) if offset_text else 0
    return _signed16(offset, "offset"), parse_register(m.group(2))


def _expect(ops: List[str], n: int, usage: str) -> None:
    if len(ops) != n:
        raise MIPSEncodeError(f"expected {usage}")


# ---------------------------------------------------------------------------
# Pseudo-instruction helpers
# ---------------------------------------------------------------------------


def _li(rt: int, value: int) -> List[int]:
    """Load a 32-bit constant (same choices as GNU as)."""
    value &= 0xFFFFFFFF
    signed = sign_extend(value, 32)
    if -0x8000 <= signed <= 0x7FFF:
        return [_i(0x09, 0, rt, signed)]  # addiu rt, $zero, value
    if value <= 0xFFFF:
        return [_i(0x0D, 0, rt, value)]  # ori rt, $zero, value
    words = [_i(0x0F, 0, rt, value >> 16)]  # lui
    if value & 0xFFFF:
        words.append(_i(0x0D, rt, rt, value & 0xFFFF))  # ori
    return words


def _la(rt: int, address: int) -> List[int]:
    """Load an address: lui, plus ori when the low half is non-zero."""
    address &= 0xFFFFFFFF
    words = [_i(0x0F, 0, rt, address >> 16)]
    if address & 0xFFFF:
        words.append(_i(0x0D, rt, rt, address & 0xFFFF))
    return words


def _hi_lo(address: int) -> Tuple[int, int]:
    """Split an address for lui + signed 16-bit offset."""
    lo = sign_extend(address, 16)
    hi = ((address - lo) >> 16) & 0xFFFF
    return hi, lo


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


def _encode(mnemonic: str, ops: List[str], ctx: Context) -> List[int]:
    m = mnemonic
    pc = ctx.address

    def branch_offset(text: str, at: int) -> int:
        """Word offset from the delay slot of a branch at address `at`."""
        value = parse_int(text)
        target = value if value is not None else ctx.eval(text)
        if not ctx.strict:
            return 0  # sizing pass: labels may not be resolved yet
        delta = target - (at + 4)
        if delta % 4:
            raise MIPSEncodeError(f"branch target 0x{target:x} is not word-aligned")
        return _signed16(delta >> 2, "branch offset")

    def jump_target(text: str) -> int:
        target = ctx.eval(text)
        if not ctx.strict:
            return 0
        if target % 4:
            raise MIPSEncodeError(f"jump target 0x{target:x} is not word-aligned")
        if (target & 0xF0000000) != ((pc + 4) & 0xF0000000):
            raise MIPSEncodeError(f"jump target 0x{target:x} is outside the current 256MB region")
        return (target >> 2) & 0x03FFFFFF

    # --- no-operand ---
    if m in ("nop", "syscall", "break", "eret"):
        if m == "nop":
            return [NOP]
        if m == "eret":
            return [0x42000018]
        code = 0
        if ops:
            _expect(ops, 1, f"{m} [code]")
            code = ctx.eval(ops[0]) & 0xFFFFF
        return [(code << 6) | (0x0C if m == "syscall" else 0x0D)]

    # --- R-type ---
    if m in ALU3:
        _expect(ops, 3, f"{m} $rd, $rs, $rt")
        bare_register_name = ops[2].lower() in REGISTERS and not ops[2].isdigit()
        if m in IMM_FORMS and not ops[2].startswith("$") and not bare_register_name:
            return _encode(IMM_FORMS[m], ops, ctx)
        rd, rs, rt = (parse_register(o) for o in ops)
        return [_r(rs, rt, rd, 0, ALU3[m])]

    if m in SHIFT_IMM:
        _expect(ops, 3, f"{m} $rd, $rt, shamt")
        if _is_register(ops[2]):
            return _encode(m + "v", ops, ctx)
        shamt = ctx.eval(ops[2])
        if not 0 <= shamt <= 31:
            raise MIPSEncodeError(f"shift amount {shamt} out of range (0 to 31)")
        return [_r(0, parse_register(ops[1]), parse_register(ops[0]), shamt, SHIFT_IMM[m])]

    if m in SHIFT_VAR:
        _expect(ops, 3, f"{m} $rd, $rt, $rs")
        rd, rt, rs = (parse_register(o) for o in ops)
        return [_r(rs, rt, rd, 0, SHIFT_VAR[m])]

    if m in MULDIV:
        if len(ops) == 3 and m in ("div", "divu"):
            # Three-operand pseudo form: quotient into rd
            rd = parse_register(ops[0])
            return [
                _r(parse_register(ops[1]), parse_register(ops[2]), 0, 0, MULDIV[m]),
                _r(0, 0, rd, 0, 0x12),
            ]
        _expect(ops, 2, f"{m} $rs, $rt")
        return [_r(parse_register(ops[0]), parse_register(ops[1]), 0, 0, MULDIV[m])]

    if m in ("rem", "remu"):
        _expect(ops, 3, f"{m} $rd, $rs, $rt")
        rd = parse_register(ops[0])
        funct = MULDIV["div" if m == "rem" else "divu"]
        return [
            _r(parse_register(ops[1]), parse_register(ops[2]), 0, 0, funct),
            _r(0, 0, rd, 0, 0x10),
        ]

    if m in HILO_TO:
        _expect(ops, 1, f"{m} $rd")
        return [_r(0, 0, parse_register(ops[0]), 0, HILO_TO[m])]

    if m in HILO_FROM:
        _expect(ops, 1, f"{m} $rs")
        return [_r(parse_register(ops[0]), 0, 0, 0, HILO_FROM[m])]

    if m == "mul":
        _expect(ops, 3, "mul $rd, $rs, $rt")
        rd, rs = parse_register(ops[0]), parse_register(ops[1])
        if _is_register(ops[2]):
            return [_r(rs, parse_register(ops[2]), rd, 0, 0x02, opcode=0x1C)]
        # mul by constant: load it into $at first
        return _li(AT, ctx.eval(ops[2])) + [_r(rs, AT, rd, 0, 0x02, opcode=0x1C)]

    if m in SPECIAL2_ACC:
        _expect(ops, 2, f"{m} $rs, $rt")
        return [
            _r(parse_register(ops[0]), parse_register(ops[1]), 0, 0, SPECIAL2_ACC[m], opcode=0x1C)
        ]

    if m in ("clz", "clo"):
        _expect(ops, 2, f"{m} $rd, $rs")
        rd, rs = parse_register(ops[0]), parse_register(ops[1])
        return [_r(rs, rd, rd, 0, 0x20 if m == "clz" else 0x21, opcode=0x1C)]

    # --- jumps (each followed by a delay-slot nop) ---
    if m == "jr":
        _expect(ops, 1, "jr $rs")
        return [_r(parse_register(ops[0]), 0, 0, 0, 0x08), NOP]

    if m == "jalr":
        if len(ops) == 1:
            rd, rs = 31, parse_register(ops[0])
        else:
            _expect(ops, 2, "jalr [$rd,] $rs")
            rd, rs = parse_register(ops[0]), parse_register(ops[1])
        return [_r(rs, 0, rd, 0, 0x09), NOP]

    if m in ("j", "jal"):
        _expect(ops, 1, f"{m} label")
        if m == "j" and _is_register(ops[0]):
            return _encode("jr", ops, ctx)
        opcode = 0x02 if m == "j" else 0x03
        return [(opcode << 26) | jump_target(ops[0]), NOP]

    # --- branches ---
    if m in BRANCH2:
        _expect(ops, 3, f"{m} $rs, $rt, label")
        rs = parse_register(ops[0])
        if _is_register(ops[1]):
            return [_i(BRANCH2[m], rs, parse_register(ops[1]), branch_offset(ops[2], pc)), NOP]
        # Compare against a constant via $at
        words = _li(AT, ctx.eval(ops[1]))
        at = pc + 4 * len(words)
        return words + [_i(BRANCH2[m], rs, AT, branch_offset(ops[2], at)), NOP]

    if m in BRANCH1:
        _expect(ops, 2, f"{m} $rs, label")
        opcode, rt = BRANCH1[m]
        return [_i(opcode, parse_register(ops[0]), rt, branch_offset(ops[1], pc)), NOP]

    if m in ("beqz", "bnez"):
        _expect(ops, 2, f"{m} $rs, label")
        opcode = BRANCH2["beq" if m == "beqz" else "bne"]
        return [_i(opcode, parse_register(ops[0]), 0, branch_offset(ops[1], pc)), NOP]

    if m in ("b", "bal"):
        _expect(ops, 1, f"{m} label")
        if m == "b":
            return [_i(0x04, 0, 0, branch_offset(ops[0], pc)), NOP]  # beq $0, $0
        return [_i(0x01, 0, 0x11, branch_offset(ops[0], pc)), NOP]  # bgezal $0

    if m in COMPARE_BRANCHES:
        _expect(ops, 3, f"{m} $rs, $rt, label")
        slt, swap, if_set = COMPARE_BRANCHES[m]
        rs = parse_register(ops[0])
        words = []
        if _is_register(ops[1]):
            rt = parse_register(ops[1])
        else:
            words = _li(AT, ctx.eval(ops[1]))
            rt = AT
        a, b = (rt, rs) if swap else (rs, rt)
        words.append(_r(a, b, AT, 0, ALU3[slt]))
        at = pc + 4 * len(words)
        opcode = BRANCH2["bne" if if_set else "beq"]
        return words + [_i(opcode, AT, 0, branch_offset(ops[2], at)), NOP]

    # --- immediates ---
    if m in ALU_IMM:
        _expect(ops, 3, f"{m} $rt, $rs, imm")
        opcode, signed = ALU_IMM[m]
        rt, rs = parse_register(ops[0]), parse_register(ops[1])
        imm = ctx.eval(ops[2])
        imm = _signed16(imm) if signed else _unsigned16(imm)
        return [_i(opcode, rs, rt, imm)]

    if m == "lui":
        _expect(ops, 2, "lui $rt, imm")
        imm = ctx.eval(ops[1])
        if -0x8000 <= imm < 0:
            imm &= 0xFFFF
        return [_i(0x0F, 0, parse_register(ops[0]), _unsigned16(imm))]

    # --- loads and stores ---
    if m in LOADS or m in STORES:
        opcode = LOADS[m] if m in LOADS else STORES[m]
        _expect(ops, 2, f"{m} $rt, offset($rs)")
        rt = parse_register(ops[0])
        if _MEM_RE.match(ops[1].strip()):
            offset, base = _parse_mem(ops[1], ctx)
            return [_i(opcode, base, rt, offset)]
        # 'lw $t0, label' -> lui $at, %hi(label); lw $t0, %lo(label)($at)
        hi, lo = _hi_lo(ctx.eval(ops[1]))
        return [_i(0x0F, 0, AT, hi), _i(opcode, AT, rt, lo)]

    # --- data movement pseudo-instructions ---
    if m == "move":
        _expect(ops, 2, "move $rd, $rs")
        return [_r(parse_register(ops[1]), 0, parse_register(ops[0]), 0, ALU3["or"])]

    if m == "li":
        _expect(ops, 2, "li $rt, imm")
        return _li(parse_register(ops[0]), ctx.eval(ops[1]))

    if m == "la":
        _expect(ops, 2, "la $rt, label")
        return _la(parse_register(ops[0]), ctx.eval(ops[1]))

    if m == "not":
        _expect(ops, 2, "not $rd, $rs")
        return [_r(parse_register(ops[1]), 0, parse_register(ops[0]), 0, ALU3["nor"])]

    if m in ("neg", "negu"):
        _expect(ops, 2, f"{m} $rd, $rs")
        funct = ALU3["sub" if m == "neg" else "subu"]
        return [_r(0, parse_register(ops[1]), parse_register(ops[0]), 0, funct)]

    if m == "abs":
        _expect(ops, 2, "abs $rd, $rs")
        rd, rs = parse_register(ops[0]), parse_register(ops[1])
        # sra $at, rs, 31; xor rd, rs, $at; subu rd, rd, $at
        return [
            _r(0, rs, AT, 31, 0x03),
            _r(rs, AT, rd, 0, ALU3["xor"]),
            _r(rd, AT, rd, 0, ALU3["subu"]),
        ]

    raise MIPSEncodeError(f"unknown instruction '{mnemonic}'")


def _split_instruction(text: str) -> Tuple[str, List[str]]:
    parts = text.strip().split(None, 1)
    if not parts:
        raise MIPSEncodeError("empty instruction")
    return parts[0].lower(), split_operands(parts[1]) if len(parts) > 1 else []


def _context(address: int, labels: Dict[str, int], strict: bool) -> Context:
    return Context(address, labels, strict=strict, error=MIPSEncodeError, lo_bits=16)


def encode(text: str, address: int, labels: Dict[str, int]) -> bytes:
    """
    Encode one MIPS instruction (or pseudo-instruction) to big-endian machine code.

    Branches and jumps include their delay-slot nop.

    Raises:
        MIPSEncodeError: If the instruction is invalid.
    """
    mnemonic, ops = _split_instruction(text)
    words = _encode(mnemonic, ops, _context(address, labels, strict=True))
    return b"".join(w.to_bytes(4, "big") for w in words)


def instruction_size(text: str, labels: Dict[str, int], address: int = 0) -> int:
    """
    Size in bytes that ``encode`` will produce, for the label-layout pass.

    Unknown labels evaluate to 0 here; the only value-dependent sizes are li,
    la, and constant operands, and the assembler re-runs layout until label
    addresses are stable.
    """
    mnemonic, ops = _split_instruction(text)
    try:
        words = _encode(mnemonic, ops, _context(address, labels, strict=False))
    except MIPSEncodeError:
        return INSTR_SIZE  # the real error is reported by encode()
    return len(words) * INSTR_SIZE
