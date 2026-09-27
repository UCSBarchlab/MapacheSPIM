"""
Differential tests: the built-in MIPS32 assembler against GNU as.

Like test_differential_riscv.py: random programs per instruction family
(fixed seeds) must assemble to byte-identical .text with GNU as in its default
".set reorder" mode (-O0, non-PIC), which fills branch delay slots with nops.

One deliberate difference is excluded: SPIM, MARS, and textbooks treat the
two-operand `div $s, $t` / `divu $s, $t` as the real instruction (results in
HI/LO), while GNU as expands it to `div $s, $s, $t`. MapacheSPIM follows SPIM.

Skipped when mips-linux-gnu binutils are not installed.
Set MAPACHESPIM_FUZZ_SCALE=N to generate N times as many instructions.
"""

import random

import pytest

from mapachespim.toolchain.mips import (
    ALU3,
    ALU_IMM,
    BRANCH1,
    COMPARE_BRANCHES,
    LOADS,
    SHIFT_IMM,
    SHIFT_VAR,
    STORES,
)

from .gnu_reference import (
    FUZZ_SCALE,
    describe_mismatch,
    gnu_accepts,
    gnu_assemble,
    gnu_available,
    ours_text,
    trim_padding,
)

ISA = "mips32"
pytestmark = pytest.mark.skipif(not gnu_available(ISA), reason="GNU MIPS binutils not installed")

NAMES = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5",
    "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
    "gp", "sp", "fp", "ra",
]  # fmt: skip

# $at is the assembler's temporary; GNU warns when programs use it directly
USABLE = [i for i in range(32) if i != 1]


def reg(rng: random.Random) -> str:
    n = rng.choice(USABLE)
    return f"${NAMES[n]}" if rng.random() < 0.7 else f"${n}"


def nonzero_reg(rng: random.Random) -> str:
    n = rng.choice([i for i in USABLE if i != 0])
    return f"${NAMES[n]}" if rng.random() < 0.7 else f"${n}"


def signed(rng: random.Random, bits: int) -> int:
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    return rng.choice([lo, hi, 0, -1, 1, lo + 1, hi - 1, rng.randint(lo, hi), rng.randint(lo, hi)])


def unsigned(rng: random.Random, bits: int) -> int:
    hi = (1 << bits) - 1
    return rng.choice([0, 1, hi, hi - 1, rng.randint(0, hi), rng.randint(0, hi)])


def fmt_int(rng: random.Random, value: int) -> str:
    return hex(value) if value >= 0 and rng.random() < 0.4 else str(value)


def any_const(rng: random.Random) -> int:
    """A 32-bit constant that may or may not fit an immediate field."""
    bits = rng.choice([4, 15, 16, 17, 31, 32])
    value = rng.randrange(1 << bits)
    if rng.random() < 0.2:
        value = value << 16
    if rng.random() < 0.4:
        value = -value
    return max(-(1 << 31), min(value, (1 << 32) - 1))


DATA = """
.data
d0: .word 1
d1: .word 2
d2: .byte 3
.align 2
d3: .space 100
d4: .word 4
.space 40000
d5: .word 5
"""
DATA_LABELS = ["d0", "d1", "d2", "d3", "d4", "d5"]


def program(lines, labels=0, rng=None) -> str:
    body = list(lines)
    if labels and rng is not None:
        positions = sorted(rng.sample(range(len(body) + 1), labels))
        for i, pos in enumerate(reversed(positions)):
            body.insert(pos, f"L{labels - 1 - i}:")
    text = "\n".join(f"    {line}" if not line.endswith(":") else line for line in body)
    return f".text\n.globl _start\n_start:\n{text}\n{DATA}"


def assert_same_chunked(lines, labels, rng, chunk=1500) -> None:
    """Check long generated programs in pieces small enough that every branch
    stays within MIPS's +/-128KB range (GNU as would relax longer ones)."""
    for start in range(0, len(lines), chunk):
        assert_same(program(lines[start : start + chunk], labels, rng))


def assert_same(source: str) -> None:
    ours, errors, debug_lines = ours_text(ISA, source)
    assert not errors, f"MapacheSPIM rejected input GNU accepts: {errors}"
    gnu = trim_padding(gnu_assemble(ISA, source), ours)
    assert ours == gnu, describe_mismatch(ISA, source, ours, gnu, debug_lines)


def n(base: int) -> int:
    return base * FUZZ_SCALE


# ---------------------------------------------------------------------------
# Real instructions
# ---------------------------------------------------------------------------


def test_register_register():
    rng = random.Random(1)
    lines = [f"{m} {reg(rng)}, {reg(rng)}, {reg(rng)}" for m in ALU3 for _ in range(n(8))]
    lines += [f"{m} {reg(rng)}, {reg(rng)}, {reg(rng)}" for m in SHIFT_VAR for _ in range(n(6))]
    lines += [f"mul {reg(rng)}, {reg(rng)}, {reg(rng)}" for _ in range(n(6))]
    assert_same(program(lines))


def test_shifts():
    rng = random.Random(2)
    lines = [
        f"{m} {reg(rng)}, {reg(rng)}, {rng.choice([0, 1, 31, rng.randrange(32)])}"
        for m in SHIFT_IMM
        for _ in range(n(8))
    ]
    assert_same(program(lines))


def test_immediates():
    rng = random.Random(3)
    lines = []
    for m, (_op, is_signed) in ALU_IMM.items():
        for _ in range(n(10)):
            value = signed(rng, 16) if is_signed else unsigned(rng, 16)
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, {fmt_int(rng, value)}")
    for _ in range(n(8)):
        lines.append(f"lui {reg(rng)}, {fmt_int(rng, unsigned(rng, 16))}")
    assert_same(program(lines))


def test_hi_lo_and_multiply_divide():
    rng = random.Random(4)
    lines = []
    for _ in range(n(6)):
        lines += [
            f"mult {reg(rng)}, {reg(rng)}",
            f"multu {reg(rng)}, {reg(rng)}",
            f"div $zero, {reg(rng)}, {reg(rng)}",
            f"divu $zero, {reg(rng)}, {reg(rng)}",
            f"mfhi {reg(rng)}",
            f"mflo {reg(rng)}",
            f"mthi {reg(rng)}",
            f"mtlo {reg(rng)}",
            f"madd {reg(rng)}, {reg(rng)}",
            f"maddu {reg(rng)}, {reg(rng)}",
            f"msub {reg(rng)}, {reg(rng)}",
            f"msubu {reg(rng)}, {reg(rng)}",
            f"clz {reg(rng)}, {reg(rng)}",
            f"clo {reg(rng)}, {reg(rng)}",
        ]
    assert_same(program(lines))


def test_loads_and_stores():
    rng = random.Random(5)
    lines = []
    for m in list(LOADS) + list(STORES):
        for _ in range(n(8)):
            offset = signed(rng, 16)
            mem = f"({reg(rng)})" if offset == 0 and rng.random() < 0.3 else f"{offset}({reg(rng)})"
            lines.append(f"{m} {reg(rng)}, {mem}")
    assert_same(program(lines))


def test_branches_and_jumps():
    rng = random.Random(6)
    labels = 10
    lines = []
    for _ in range(n(8)):
        lines += [
            f"beq {reg(rng)}, {reg(rng)}, L{rng.randrange(labels)}",
            f"bne {reg(rng)}, {reg(rng)}, L{rng.randrange(labels)}",
            f"beqz {reg(rng)}, L{rng.randrange(labels)}",
            f"bnez {reg(rng)}, L{rng.randrange(labels)}",
            f"b L{rng.randrange(labels)}",
            f"bal L{rng.randrange(labels)}",
            f"j L{rng.randrange(labels)}",
            f"jal L{rng.randrange(labels)}",
            f"jr {reg(rng)}",
            "jalr $t0, $t9",
            f"jalr {rng.choice(['$t9', '$t0', '$s0', '$v0'])}",
        ]
        for m in BRANCH1:
            rs = reg(rng) if m not in ("bltzal", "bgezal") else rng.choice(["$t0", "$s1", "$a0"])
            lines.append(f"{m} {rs}, L{rng.randrange(labels)}")
    rng.shuffle(lines)
    assert_same_chunked(lines, labels, rng)


def test_system():
    assert_same(program(["syscall", "break", "nop", "syscall 5", "break 7"]))


# ---------------------------------------------------------------------------
# Pseudo-instructions
# ---------------------------------------------------------------------------


def test_li_and_la():
    rng = random.Random(7)
    lines = []
    for value in [0, 1, -1, 0x7FFF, -0x8000, 0x8000, 0xFFFF, 0x10000, 0xFFFF0000, 0x7FFFFFFF,
                  -0x80000000, 0xFFFFFFFF, 0x12345678] + [any_const(rng) for _ in range(n(40))]:  # fmt: skip
        lines.append(f"li {nonzero_reg(rng)}, {fmt_int(rng, value)}")
    for _ in range(n(10)):
        label = rng.choice(DATA_LABELS)
        lines.append(f"la {nonzero_reg(rng)}, {label}{rng.choice(['', '+4', '-4', '+1000'])}")
        lines.append(f"la {nonzero_reg(rng)}, {fmt_int(rng, any_const(rng))}")
    assert_same(program(lines))


def test_register_pseudos():
    rng = random.Random(8)
    lines = []
    for _ in range(n(8)):
        lines += [
            f"move {reg(rng)}, {reg(rng)}",
            f"not {reg(rng)}, {reg(rng)}",
            f"neg {reg(rng)}, {reg(rng)}",
            f"negu {reg(rng)}, {reg(rng)}",
            f"abs {nonzero_reg(rng)}, {nonzero_reg(rng)}",
        ]
    assert_same(program(lines))


def test_compare_branches():
    rng = random.Random(9)
    labels = 10
    lines = []
    for m in COMPARE_BRANCHES:
        for _ in range(n(6)):
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, L{rng.randrange(labels)}")
            lines.append(f"{m} {reg(rng)}, {fmt_int(rng, any_const(rng))}, L{rng.randrange(labels)}")
        for value in (0, 1, -1, 0x7FFF, 0x8000, -0x8000):
            lines.append(f"{m} {reg(rng)}, {value}, L{rng.randrange(labels)}")
        lines.append(f"{m} {reg(rng)}, $zero, L{rng.randrange(labels)}")
        lines.append(f"{m} $zero, {reg(rng)}, L{rng.randrange(labels)}")
    for m in ("beq", "bne"):
        for _ in range(n(6)):
            lines.append(f"{m} {reg(rng)}, {fmt_int(rng, any_const(rng))}, L{rng.randrange(labels)}")
    rng.shuffle(lines)
    assert_same_chunked(lines, labels, rng)


def test_register_forms_with_immediates():
    """e.g. 'add $t0, $t1, 5' and constants too large for the immediate field."""
    rng = random.Random(10)
    lines = []
    for m in ("add", "addu", "sub", "subu", "and", "or", "xor", "slt", "sltu"):
        for _ in range(n(8)):
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, {fmt_int(rng, any_const(rng))}")
    assert_same(program(lines))


def test_multiply_divide_pseudos():
    rng = random.Random(11)
    lines = []
    for m in ("div", "divu", "rem", "remu", "mul"):
        for _ in range(n(8)):
            lines.append(f"{m} {nonzero_reg(rng)}, {reg(rng)}, {nonzero_reg(rng)}")
        for value in (1, 2, 7, -3, 100000):
            if m in ("divu", "remu") and value < 0:
                continue
            lines.append(f"{m} {nonzero_reg(rng)}, {reg(rng)}, {value}")
    assert_same(program(lines))


def test_symbol_loads_and_stores():
    rng = random.Random(12)
    lines = []
    for _ in range(n(8)):
        label = rng.choice(DATA_LABELS)
        lines += [
            f"{rng.choice(list(LOADS))} {nonzero_reg(rng)}, {label}",
            f"{rng.choice(list(STORES))} {reg(rng)}, {label}",
            f"lw {nonzero_reg(rng)}, {label}({reg(rng)})",
            f"sw {reg(rng)}, {label}+8({reg(rng)})",
            f"lw {nonzero_reg(rng)}, 100000({reg(rng)})",
            f"lui {nonzero_reg(rng)}, %hi({label})",
            f"addiu {nonzero_reg(rng)}, {reg(rng)}, %lo({label})",
            f"lw {nonzero_reg(rng)}, %lo({label})({reg(rng)})",
        ]
    assert_same(program(lines))


def test_noreorder():
    source = program(
        [
            ".set noreorder",
            "beq $t0, $t1, L0",
            "addiu $t2, $t2, 1",
            "jal L0",
            "nop",
            ".set reorder",
            "L0:",
            "bne $t0, $t1, L0",
            "jr $ra",
        ]
    )
    assert_same(source)


def test_whole_examples():
    from mapachespim.examples import list_examples

    for example in list_examples():
        if example.isa == "mips" and example.source is not None:
            assert_same(example.source.read_text().replace(".isa mips32", ""))


INVALID = [
    "addi $t0, $t1",
    "add $t0, $t1, $t2, $t3",
    "sll $t0, $t1, 32",
    "frobnicate $t0",
    "add $t0, $t1, $q9",
    "beq $t0, $t1, undefined_label",
    "j undefined_label",
    "lw $t0",
    "move $t0",
    "mfhi",
    "jr",
    "jalr $t0, $t0",
    "jalr $ra",
    "bgezal $ra, L0",
]


@pytest.mark.parametrize("line", INVALID)
def test_invalid_rejected(line):
    source = program([line, "L0:"])
    assert not gnu_accepts(ISA, source), f"test assumption: GNU accepts {line!r}"
    _, errors, _ = ours_text(ISA, source)
    assert errors, f"MapacheSPIM accepted invalid input {line!r}"
