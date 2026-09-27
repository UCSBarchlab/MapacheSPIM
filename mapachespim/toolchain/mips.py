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

from .expr import (
    Context,
    EncodeError,
    ExpressionError,
    evaluate,
    parse_int,
    sign_extend,
    split_operands,
)

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
    "add": "addi", "addu": "addiu", "sub": "addi", "subu": "addiu",
    "slt": "slti", "sltu": "sltiu",
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


def _hi_lo(address: int) -> Tuple[int, int]:
    """Split an address into %hi (for lui) and %lo (a signed 16-bit offset)."""
    lo = sign_extend(address, 16)
    hi = ((address - lo) >> 16) & 0xFFFF
    return hi, lo


def _uses_symbols(text: str) -> bool:
    """True if an operand expression refers to any symbol (label or constant)."""
    found = False

    def resolve(name: str) -> int:
        nonlocal found
        found = True
        return 0

    try:
        evaluate(text, resolve, lambda name, value: value)
    except ExpressionError:
        return True
    return found


def _move(rd: int, rs: int) -> int:
    return _r(rs, 0, rd, 0, ALU3["or"])  # move rd, rs = or rd, rs, $zero


def _neg(rd: int, rs: int) -> int:
    return _r(0, rs, rd, 0, ALU3["sub"])  # neg rd, rs = sub rd, $zero, rs


def _break(code1: int = 0, code2: int = 0) -> int:
    return (code1 << 16) | (code2 << 6) | 0x0D


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


def _encode(mnemonic: str, ops: List[str], ctx: Context, reorder: bool = True) -> List[int]:
    """Encode one instruction or pseudo-instruction as a list of words.

    With ``reorder`` (GNU as's default ".set reorder"), a nop is placed in
    the delay slot of each branch and jump written in the source. With
    ".set noreorder", the programmer fills delay slots themselves.
    """
    m = mnemonic
    pc = ctx.address
    slot = [NOP] if reorder else []

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

    def is_reg_or_bare_name(text: str) -> bool:
        t = text.strip()
        return t.startswith("$") or (t.lower() in REGISTERS and not t.isdigit())

    def value_of(text: str) -> int:
        return ctx.eval(text) & 0xFFFFFFFF

    # --- no-operand ---
    if m == "nop":
        _expect(ops, 0, "nop")
        return [NOP]
    if m == "eret":
        return [0x42000018]
    if m == "syscall":
        code = ctx.eval(ops[0]) & 0xFFFFF if ops else 0
        if len(ops) > 1:
            raise MIPSEncodeError("expected syscall [code]")
        return [(code << 6) | 0x0C]
    if m == "break":
        if len(ops) > 2:
            raise MIPSEncodeError("expected break [code[, code]]")
        codes = [ctx.eval(o) & 0x3FF for o in ops]
        return [_break(*codes)]

    # --- three-register ALU (also accepting an immediate, like GNU as) ---
    if m in ALU3:
        _expect(ops, 3, f"{m} $rd, $rs, $rt")
        if m in IMM_FORMS and not is_reg_or_bare_name(ops[2]):
            rd, rs = parse_register(ops[0]), parse_register(ops[1])
            imm_op = IMM_FORMS[m]
            opcode, is_signed = ALU_IMM[imm_op]
            # Constants are 32-bit: 0xffffffff means -1 to a signed field
            imm = sign_extend(value_of(ops[2]), 32) if is_signed else value_of(ops[2])
            if m in ("sub", "subu"):
                imm = -imm  # subtracting is adding the negated value
            fits = -0x8000 <= imm <= 0x7FFF if is_signed else 0 <= imm <= 0xFFFF
            if fits:
                return [_i(opcode, rs, rd, imm)]
            # Too large for the immediate field: build it in $at
            return _li(AT, ctx.eval(ops[2])) + [_r(rs, AT, rd, 0, ALU3[m])]
        rd, rs, rt = (parse_register(o) for o in ops)
        return [_r(rs, rt, rd, 0, ALU3[m])]

    if m in SHIFT_IMM:
        _expect(ops, 3, f"{m} $rd, $rt, shamt")
        if _is_register(ops[2]):
            return _encode(m + "v", ops, ctx, reorder)
        shamt = ctx.eval(ops[2])
        if not 0 <= shamt <= 31:
            raise MIPSEncodeError(f"shift amount {shamt} out of range (0 to 31)")
        return [_r(0, parse_register(ops[1]), parse_register(ops[0]), shamt, SHIFT_IMM[m])]

    if m in SHIFT_VAR:
        _expect(ops, 3, f"{m} $rd, $rt, $rs")
        rd, rt, rs = (parse_register(o) for o in ops)
        return [_r(rs, rt, rd, 0, SHIFT_VAR[m])]

    # --- multiply and divide ---
    if m in MULDIV and len(ops) == 2:
        # The real instruction; results in HI/LO. (SPIM semantics: GNU as
        # instead expands 'div $s, $t' to 'div $s, $s, $t'.)
        return [_r(parse_register(ops[0]), parse_register(ops[1]), 0, 0, MULDIV[m])]

    if m in ("div", "divu", "rem", "remu"):
        _expect(ops, 3, f"{m} $rd, $rs, $rt")
        rd, rs = parse_register(ops[0]), parse_register(ops[1])
        signed_op = m in ("div", "rem")
        funct = MULDIV["div" if signed_op else "divu"]
        result = HILO_TO["mflo" if m in ("div", "divu") else "mfhi"]
        if _is_register(ops[2]):
            rt = parse_register(ops[2])
            if rd == 0 and m in ("div", "divu"):
                return [_r(rs, rt, 0, 0, funct)]  # 'div $zero, $s, $t' is the real instruction
            # Trap on division by zero (break 7), and for signed division on
            # overflow of -2^31 / -1 (break 6), as GNU as and SPIM do
            words = [_i(0x05, rt, 0, 2), _r(rs, rt, 0, 0, funct), _break(7)]
            if signed_op:
                words += [
                    _i(0x09, 0, AT, -1),  # li $at, -1
                    _i(0x05, rt, AT, 4),  # bne $rt, $at, done
                    _i(0x0F, 0, AT, 0x8000),  # lui $at, 0x8000 (delay slot)
                    _i(0x05, rs, AT, 2),  # bne $rs, $at, done
                    NOP,
                    _break(6),
                ]
            return words + [_r(0, 0, rd, 0, result)]
        divisor = sign_extend(value_of(ops[2]), 32)
        if divisor == 0:
            return [_break(7)]
        if divisor == 1 or (divisor == -1 and signed_op):
            if m in ("rem", "remu"):
                return [_move(rd, 0)]  # the remainder is always 0
            return [_move(rd, rs)] if divisor == 1 else [_neg(rd, rs)]
        return _li(AT, divisor) + [_r(rs, AT, 0, 0, funct), _r(0, 0, rd, 0, result)]

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
        # By a constant: li $at, value; mult $rs, $at; mflo $rd
        return _li(AT, ctx.eval(ops[2])) + [
            _r(rs, AT, 0, 0, MULDIV["mult"]),
            _r(0, 0, rd, 0, HILO_TO["mflo"]),
        ]

    if m in SPECIAL2_ACC:
        _expect(ops, 2, f"{m} $rs, $rt")
        return [
            _r(parse_register(ops[0]), parse_register(ops[1]), 0, 0, SPECIAL2_ACC[m], opcode=0x1C)
        ]

    if m in ("clz", "clo"):
        _expect(ops, 2, f"{m} $rd, $rs")
        rd, rs = parse_register(ops[0]), parse_register(ops[1])
        return [_r(rs, rd, rd, 0, 0x20 if m == "clz" else 0x21, opcode=0x1C)]

    # --- jumps ---
    if m == "jr":
        _expect(ops, 1, "jr $rs")
        return [_r(parse_register(ops[0]), 0, 0, 0, 0x08)] + slot

    if m == "jalr":
        if len(ops) == 1:
            rd, rs = 31, parse_register(ops[0])
        else:
            _expect(ops, 2, "jalr [$rd,] $rs")
            rd, rs = parse_register(ops[0]), parse_register(ops[1])
        if rd == rs:
            raise MIPSEncodeError(
                "jalr: source and destination must be different registers"
                + (" (the destination defaults to $ra)" if len(ops) == 1 else "")
            )
        return [_r(rs, 0, rd, 0, 0x09)] + slot

    if m in ("j", "jal"):
        _expect(ops, 1, f"{m} label")
        if m == "j" and _is_register(ops[0]):
            return _encode("jr", ops, ctx, reorder)
        opcode = 0x02 if m == "j" else 0x03
        return [(opcode << 26) | jump_target(ops[0])] + slot

    # --- branches ---
    def compare_branch(op: str, a: int, b_text: str, target: str) -> List[int]:
        """blt/bge/bgt/ble[u] a, b, target, following GNU as's macro rules
        (tc-mips.c M_BLT, M_BLTI, ...), including its special cases for 0,
        1, and the extreme values."""
        unsigned = op.endswith("u")
        kind = op[:3]  # blt, bge, bgt, ble
        bne, beq = BRANCH2["bne"], BRANCH2["beq"]
        sl = "sltu" if unsigned else "slt"

        if _is_register(b_text):
            b = parse_register(b_text)
            if kind in ("blt", "bge"):  # a < b, a >= b
                taken_if_less = kind == "blt"
                if b == 0:
                    if unsigned:
                        return never() if taken_if_less else always(target)
                    return [_i(0x01, a, 0 if taken_if_less else 1, off(target))] + slot  # bltz/bgez
                if a == 0:
                    if unsigned:
                        return [_i(bne if taken_if_less else beq, 0, b, off(target))] + slot
                    return [
                        _i(0x07 if taken_if_less else 0x06, b, 0, off(target))
                    ] + slot  # bgtz/blez
                words = [_r(a, b, AT, 0, ALU3[sl])]
                opcode = bne if taken_if_less else beq
            else:  # a > b, a <= b
                taken_if_greater = kind == "bgt"
                if b == 0:
                    if unsigned:
                        return [_i(bne if taken_if_greater else beq, a, 0, off(target))] + slot
                    return [_i(0x07 if taken_if_greater else 0x06, a, 0, off(target))] + slot
                if a == 0:
                    if unsigned:
                        return never() if taken_if_greater else always(target)
                    return [
                        _i(0x01, b, 0 if taken_if_greater else 1, off(target))
                    ] + slot  # bltz/bgez
                words = [_r(b, a, AT, 0, ALU3[sl])]
                opcode = bne if taken_if_greater else beq
            return words + [_i(opcode, AT, 0, offset_after(words, target))] + slot

        # Immediate operand (compared as a 32-bit value)
        v = sign_extend(value_of(b_text), 32)
        if kind == "bgt":  # a > v  ==  a >= v+1
            if (unsigned and (a == 0 or v == -1)) or (not unsigned and v >= 0x7FFFFFFF):
                return never()
            v, kind = v + 1, "bge"
        elif kind == "ble":  # a <= v  ==  a < v+1
            if (unsigned and (a == 0 or v == -1)) or (not unsigned and v >= 0x7FFFFFFF):
                return always(target)
            v, kind = v + 1, "blt"

        if kind == "blt":
            if unsigned and v == 0:
                return never()
            if unsigned and v == 1:
                return [_i(beq, a, 0, off(target))] + slot  # a < 1  ==  a == 0
            if not unsigned and v in (0, 1):
                return [
                    _i(0x01, a, 0, off(target)) if v == 0 else _i(0x06, a, 0, off(target))
                ] + slot
            opcode = bne
        else:  # bge
            if unsigned and v == 0 or (not unsigned and v == -0x80000000):
                return always(target)
            if unsigned and v == 1:
                return [_i(bne, a, 0, off(target))] + slot  # a >= 1  ==  a != 0
            if not unsigned and v in (0, 1):
                return [
                    _i(0x01, a, 1, off(target)) if v == 0 else _i(0x07, a, 0, off(target))
                ] + slot
            opcode = beq
        # $at = (a < v)
        if -0x8000 <= v <= 0x7FFF:
            words = [_i(0x0B if unsigned else 0x0A, a, AT, v)]  # slti[u] $at, a, v
        else:
            words = _li(AT, v) + [_r(a, AT, AT, 0, ALU3[sl])]
        return words + [_i(opcode, AT, 0, offset_after(words, target))] + slot

    def off(target: str) -> int:
        return branch_offset(target, pc)

    def offset_after(words: List[int], target: str) -> int:
        return branch_offset(target, pc + 4 * len(words))

    def always(target: str) -> List[int]:
        return [_i(0x04, 0, 0, branch_offset(target, pc))] + slot  # b target

    def never() -> List[int]:
        return [NOP]  # a branch that is never taken (GNU emits a nop)

    if m in BRANCH2:
        _expect(ops, 3, f"{m} $rs, $rt, label")
        rs = parse_register(ops[0])
        if _is_register(ops[1]):
            return [_i(BRANCH2[m], rs, parse_register(ops[1]), branch_offset(ops[2], pc))] + slot
        value = value_of(ops[1])
        if value == 0:
            return [_i(BRANCH2[m], rs, 0, branch_offset(ops[2], pc))] + slot
        words = _li(AT, value)
        return words + [_i(BRANCH2[m], rs, AT, offset_after(words, ops[2]))] + slot

    if m in BRANCH1:
        _expect(ops, 2, f"{m} $rs, label")
        opcode, rt = BRANCH1[m]
        rs = parse_register(ops[0])
        if m in ("bltzal", "bgezal") and rs == 31:
            raise MIPSEncodeError(f"{m}: the source register must not be $ra (it is overwritten)")
        return [_i(opcode, rs, rt, branch_offset(ops[1], pc))] + slot

    if m in ("beqz", "bnez"):
        _expect(ops, 2, f"{m} $rs, label")
        opcode = BRANCH2["beq" if m == "beqz" else "bne"]
        return [_i(opcode, parse_register(ops[0]), 0, branch_offset(ops[1], pc))] + slot

    if m in ("b", "bal"):
        _expect(ops, 1, f"{m} label")
        if m == "b":
            return always(ops[0])
        return [_i(0x01, 0, 0x11, branch_offset(ops[0], pc))] + slot  # bgezal $0

    if m in COMPARE_BRANCHES:
        _expect(ops, 3, f"{m} $rs, $rt, label")
        return compare_branch(m, parse_register(ops[0]), ops[1], ops[2])

    # --- immediates ---
    if m in ALU_IMM:
        _expect(ops, 3, f"{m} $rt, $rs, imm")
        opcode, is_signed = ALU_IMM[m]
        rt, rs = parse_register(ops[0]), parse_register(ops[1])
        imm = ctx.eval(ops[2])
        imm = _signed16(imm) if is_signed else _unsigned16(imm)
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
        operand = ops[1].strip()
        match = _MEM_RE.match(operand)
        if match:
            offset_text, base = match.group(1).strip(), parse_register(match.group(2))
        else:
            offset_text, base = operand, 0
        offset = ctx.eval(offset_text) if offset_text else 0
        # A plain offset that fits (or an explicit %lo(...)) is one instruction
        if (
            not offset_text
            or offset_text.startswith("%")
            or (not _uses_symbols(offset_text) and -0x8000 <= offset <= 0x7FFF)
        ):
            return [_i(opcode, base, rt, _signed16(offset, "offset"))]
        # Otherwise: lui tmp, %hi(addr); [addu tmp, tmp, base]; op rt, %lo(addr)(tmp)
        # A load can use its own destination as tmp; stores and the partial
        # loads lwl/lwr must use $at
        partial = m in ("lwl", "lwr")
        tmp = rt if (m in LOADS and not partial and rt not in (0, base)) else AT
        hi, lo = _hi_lo(offset)
        words = [_i(0x0F, 0, tmp, hi)]
        if base:
            words.append(_r(tmp, base, tmp, 0, ALU3["addu"]))
        return words + [_i(opcode, tmp, rt, lo)]

    # --- data movement pseudo-instructions ---
    if m == "move":
        _expect(ops, 2, "move $rd, $rs")
        return [_move(parse_register(ops[0]), parse_register(ops[1]))]

    if m == "li":
        _expect(ops, 2, "li $rt, imm")
        return _li(parse_register(ops[0]), ctx.eval(ops[1]))

    if m == "la":
        _expect(ops, 2, "la $rt, label")
        rt = parse_register(ops[0])
        if not _uses_symbols(ops[1]):
            return _li(rt, ctx.eval(ops[1]))  # a plain number: same as li
        hi, lo = _hi_lo(ctx.eval(ops[1]))
        return [_i(0x0F, 0, rt, hi), _i(0x09, rt, rt, lo)]  # lui; addiu

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
        # bgez $rs, done; move $rd, $rs (delay slot); neg $rd, $rs; done:
        delay = NOP if rd == rs else _move(rd, rs)
        return [_i(0x01, rs, 1, 2), delay, _neg(rd, rs)]

    raise MIPSEncodeError(f"unknown instruction '{mnemonic}'")


def _split_instruction(text: str) -> Tuple[str, List[str]]:
    parts = text.strip().split(None, 1)
    if not parts:
        raise MIPSEncodeError("empty instruction")
    return parts[0].lower(), split_operands(parts[1]) if len(parts) > 1 else []


def _context(address: int, labels: Dict[str, int], strict: bool) -> Context:
    return Context(address, labels, strict=strict, error=MIPSEncodeError, lo_bits=16)


def encode(text: str, address: int, labels: Dict[str, int], reorder: bool = True) -> bytes:
    """
    Encode one MIPS instruction (or pseudo-instruction) to big-endian machine code.

    Branches and jumps include their delay-slot nop.

    Raises:
        MIPSEncodeError: If the instruction is invalid.
    """
    mnemonic, ops = _split_instruction(text)
    words = _encode(mnemonic, ops, _context(address, labels, strict=True), reorder)
    return b"".join(w.to_bytes(4, "big") for w in words)


def instruction_size(
    text: str, labels: Dict[str, int], address: int = 0, reorder: bool = True
) -> int:
    """
    Size in bytes that ``encode`` will produce, for the label-layout pass.

    Unknown labels evaluate to 0 here; the only value-dependent sizes are li,
    la, and constant operands, and the assembler re-runs layout until label
    addresses are stable.
    """
    mnemonic, ops = _split_instruction(text)
    try:
        words = _encode(mnemonic, ops, _context(address, labels, strict=False), reorder)
    except MIPSEncodeError:
        return INSTR_SIZE  # the real error is reported by encode()
    return len(words) * INSTR_SIZE
