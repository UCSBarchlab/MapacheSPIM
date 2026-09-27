"""
Differential tests: the built-in RISC-V assembler against GNU as.

Every test generates a random program (fixed seed, so failures reproduce)
covering one family of instructions with random registers, immediates across
their whole range including the boundaries, and forward/backward label
references, then requires byte-identical .text from both assemblers.

Skipped when riscv64-linux-gnu binutils are not installed.
Set MAPACHESPIM_FUZZ_SCALE=N to generate N times as many instructions.
"""

import random

import pytest

from .gnu_reference import (
    FUZZ_SCALE,
    describe_mismatch,
    gnu_accepts,
    gnu_assemble,
    gnu_available,
    ours_text,
    trim_padding,
)
from mapachespim.toolchain.riscv import (
    BRANCHES,
    I_ALU,
    LOADS,
    R_TYPE,
    SHIFT_IMM,
    STORES,
    SWAP_BRANCHES,
    ZERO_BRANCHES,
)

ISA = "riscv64"
pytestmark = pytest.mark.skipif(not gnu_available(ISA), reason="GNU RISC-V binutils not installed")

ABI = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
    "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
]  # fmt: skip


def reg(rng: random.Random) -> str:
    """A random register, by ABI name or xN."""
    n = rng.randrange(32)
    return ABI[n] if rng.random() < 0.7 else f"x{n}"


def nonzero_reg(rng: random.Random) -> str:
    n = rng.randrange(1, 32)
    return ABI[n] if rng.random() < 0.7 else f"x{n}"


def signed(rng: random.Random, bits: int) -> int:
    """Random signed value, biased toward the edges of the range."""
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    return rng.choice([lo, hi, 0, -1, 1, lo + 1, hi - 1, rng.randint(lo, hi), rng.randint(lo, hi)])


def fmt_int(rng: random.Random, value: int) -> str:
    """Write an integer in decimal or hex, as students do."""
    if value >= 0 and rng.random() < 0.4:
        return hex(value)
    return str(value)


DATA = """
.data
d0: .word 1
d1: .dword 2
d2: .byte 3
.align 3
d3: .space 100
d4: .word 4
"""
DATA_LABELS = ["d0", "d1", "d2", "d3", "d4"]


def program(lines, labels=0, rng=None) -> str:
    """Wrap instruction lines in a program, scattering `labels` labels L0..Ln."""
    body = list(lines)
    if labels and rng is not None:
        positions = sorted(rng.sample(range(len(body) + 1), labels))
        for i, pos in enumerate(reversed(positions)):
            body.insert(pos, f"L{labels - 1 - i}:")
    text = "\n".join(f"    {line}" if not line.endswith(":") else line for line in body)
    return f".text\n.globl _start\n_start:\n{text}\n{DATA}"


def assert_same(source: str) -> None:
    ours, errors, debug_lines = ours_text(ISA, source)
    gnu = trim_padding(gnu_assemble(ISA, source), ours)
    assert not errors, f"MapacheSPIM rejected input GNU accepts: {errors}"
    assert ours == gnu, describe_mismatch(ISA, source, ours, gnu, debug_lines)


def n(base: int) -> int:
    return base * FUZZ_SCALE


# ---------------------------------------------------------------------------
# Real instructions
# ---------------------------------------------------------------------------


def test_register_register():
    rng = random.Random(1)
    lines = [f"{m} {reg(rng)}, {reg(rng)}, {reg(rng)}" for m in R_TYPE for _ in range(n(8))]
    assert_same(program(lines))


def test_register_immediate():
    rng = random.Random(2)
    lines = [
        f"{m} {reg(rng)}, {reg(rng)}, {fmt_int(rng, signed(rng, 12))}"
        for m in I_ALU
        for _ in range(n(12))
    ]
    assert_same(program(lines))


def test_shift_immediate():
    rng = random.Random(3)
    lines = []
    for m, (_op, _f3, _hi, bits) in SHIFT_IMM.items():
        for shamt in [0, 1, (1 << bits) - 1] + [rng.randrange(1 << bits) for _ in range(n(6))]:
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, {shamt}")
    assert_same(program(lines))


def test_loads_and_stores():
    rng = random.Random(4)
    lines = []
    for m in list(LOADS) + list(STORES):
        for _ in range(n(10)):
            offset = signed(rng, 12)
            mem = f"({reg(rng)})" if offset == 0 and rng.random() < 0.3 else f"{offset}({reg(rng)})"
            lines.append(f"{m} {reg(rng)}, {mem}")
    assert_same(program(lines))


def test_branches():
    rng = random.Random(5)
    labels = 12
    lines = []
    for m in list(BRANCHES) + list(SWAP_BRANCHES):
        for _ in range(n(8)):
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, L{rng.randrange(labels)}")
    for m in ZERO_BRANCHES:
        for _ in range(n(8)):
            lines.append(f"{m} {reg(rng)}, L{rng.randrange(labels)}")
    rng.shuffle(lines)
    assert_same(program(lines, labels, rng))


def test_branch_relaxation_sees_labels_like_gnu():
    """Deciding whether a branch reaches its label, GNU as uses this layout
    pass's address for labels already passed and the previous pass's for
    labels ahead. Using the previous pass's address for both relaxes an
    extra branch in this program (found by the 50x fuzz run)."""
    rng = random.Random(4)
    lines = [f"beq a0, a1, L{rng.randrange(4)}" for _ in range(1600)]
    assert_same(program(lines, 4, rng))


def test_jumps():
    rng = random.Random(6)
    labels = 8
    lines = []
    for _ in range(n(10)):
        lines += [
            f"jal L{rng.randrange(labels)}",
            f"jal {reg(rng)}, L{rng.randrange(labels)}",
            f"j L{rng.randrange(labels)}",
            f"jalr {reg(rng)}",
            f"jalr {reg(rng)}, {signed(rng, 12)}({reg(rng)})",
            f"jalr {reg(rng)}, {reg(rng)}, {signed(rng, 12)}",
            f"jr {reg(rng)}",
            "ret",
            f"call L{rng.randrange(labels)}",
            f"tail L{rng.randrange(labels)}",
        ]
    rng.shuffle(lines)
    assert_same(program(lines, labels, rng))


def test_upper_immediates():
    rng = random.Random(7)
    lines = []
    for m in ("lui", "auipc"):
        for value in [0, 1, 0xFFFFF, 0x80000, 0x7FFFF] + [rng.randrange(1 << 20) for _ in range(n(10))]:
            lines.append(f"{m} {reg(rng)}, {hex(value)}")
    assert_same(program(lines))


def test_system_and_csr():
    rng = random.Random(8)
    lines = ["ecall", "ebreak", "fence", "nop"]
    csrs = ["mscratch", "mepc", "mtvec", "mstatus", "0x340"]
    for _ in range(n(4)):
        csr = rng.choice(csrs)
        lines += [
            f"csrrw {reg(rng)}, {csr}, {reg(rng)}",
            f"csrrs {reg(rng)}, {csr}, {reg(rng)}",
            f"csrrc {reg(rng)}, {csr}, {reg(rng)}",
            f"csrrwi {reg(rng)}, {csr}, {rng.randrange(32)}",
            f"csrrsi {reg(rng)}, {csr}, {rng.randrange(32)}",
            f"csrrci {reg(rng)}, {csr}, {rng.randrange(32)}",
            f"csrr {reg(rng)}, {csr}",
            f"csrw {csr}, {reg(rng)}",
            f"csrs {csr}, {reg(rng)}",
            f"csrc {csr}, {reg(rng)}",
            f"csrr {reg(rng)}, cycle",
        ]
    assert_same(program(lines))


# ---------------------------------------------------------------------------
# Pseudo-instructions
# ---------------------------------------------------------------------------


def interesting_constants(rng: random.Random, count: int):
    """Constants that exercise every path of li's expansion."""
    values = [
        0, 1, -1, 2047, -2048, 2048, -2049, 0x7FF, 0x800, 0xFFF, 0x1000, 0x12345,
        0x7FFFFFFF, -0x80000000, 0x80000000, 0xFFFFFFFF, 0x100000000, 0x7FFFFFFFFFFFFFFF,
        -0x8000000000000000, 0x8000000000000000 - 1, 0x0000080000000800, 0xFFFFFFFF00000000,
        0x00FF00FF00FF00FF, 0xDEADBEEFCAFEBABE, 0x123456789ABCDEF0,
    ]  # fmt: skip
    for _ in range(count):
        bits = rng.choice([12, 13, 20, 32, 33, 40, 52, 63, 64])
        value = rng.randrange(1 << bits)
        # Also sparse values (few set bits), which take the shift paths
        if rng.random() < 0.3:
            value = sum(1 << rng.randrange(64) for _ in range(rng.randint(1, 4)))
        values.append(value if rng.random() < 0.5 else -value)
    return values


def test_li():
    rng = random.Random(9)
    lines = []
    for value in interesting_constants(rng, n(120)):
        # GNU wants 64-bit constants in range for li
        if -(1 << 63) <= value < (1 << 64):
            lines.append(f"li {nonzero_reg(rng)}, {fmt_int(rng, value)}")
    assert_same(program(lines))


def test_register_pseudos():
    rng = random.Random(10)
    lines = []
    for m in ("mv", "not", "neg", "negw", "sext.w", "seqz", "snez", "sltz", "sgtz"):
        for _ in range(n(8)):
            lines.append(f"{m} {reg(rng)}, {reg(rng)}")
    assert_same(program(lines))


def test_addresses_and_symbol_access():
    rng = random.Random(11)
    lines = []
    for _ in range(n(8)):
        label = rng.choice(DATA_LABELS)
        offset = rng.choice(["", "+4", "+8", "-4"])
        lines += [
            f"la {nonzero_reg(rng)}, {label}{offset}",
            f"lla {nonzero_reg(rng)}, {label}",
            f"{rng.choice(list(LOADS))} {nonzero_reg(rng)}, {label}",
            f"{rng.choice(list(STORES))} {reg(rng)}, {label}, {nonzero_reg(rng)}",
            f"addi {nonzero_reg(rng)}, {reg(rng)}, %lo({label})",
            f"lw {nonzero_reg(rng)}, %lo({label})({reg(rng)})",
            f"lui {nonzero_reg(rng)}, %hi(SMALL{offset})",
            f"addi {nonzero_reg(rng)}, {reg(rng)}, %lo(SMALL{offset})",
        ]
    source = program(lines).replace(".text", ".equ SMALL, 0x12345678\n.text", 1)
    assert_same(source)


def test_register_forms_with_immediates():
    """GNU accepts e.g. 'add a0, a1, 5' as 'addi a0, a1, 5'."""
    rng = random.Random(12)
    lines = []
    for m in ("add", "and", "or", "xor", "slt", "sltu", "addw"):
        for _ in range(n(6)):
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, {signed(rng, 12)}")
    for m in ("sll", "srl", "sra"):
        for _ in range(n(4)):
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, {rng.randrange(64)}")
    for m in ("sllw", "srlw", "sraw"):
        for _ in range(n(4)):
            lines.append(f"{m} {reg(rng)}, {reg(rng)}, {rng.randrange(32)}")
    assert_same(program(lines))


def test_expressions_and_literals():
    source = program(
        [
            "addi a0, a0, 'A'",
            "addi a0, a0, '\\n'",
            "addi a0, a0, 0b1010",
            "addi a0, a0, -0x10",
            "li a0, SIZE",
            "li a1, SIZE*2" if False else "li a1, SIZE+2",
            "addi a2, a2, SIZE-1",
            "la a3, d3+16",
            "j end",
            "nop",
            "end:",
            "ret",
        ]
    ).replace(".text", ".equ SIZE, 100\n.text", 1)
    assert_same(source)


def test_whole_examples():
    """The bundled RISC-V examples assemble identically too."""
    from mapachespim.examples import list_examples

    for example in list_examples():
        if example.isa == "riscv" and example.source is not None:
            source = example.source.read_text().replace(".isa riscv64", "")
            assert_same(source)


# ---------------------------------------------------------------------------
# Invalid input: anything GNU rejects, we reject too
# ---------------------------------------------------------------------------

INVALID = [
    "addi a0, a1, 2048",
    "addi a0, a1, -2049",
    "slli a0, a1, 64",
    "slliw a0, a1, 32",
    "lw a0, 2048(a1)",
    "sw a0, -2049(a1)",
    "lui a0, 0x100000",
    "csrrwi a0, mscratch, 32",
    "add a0, a1",
    "add a0, a1, a2, a3",
    "addi a0, a1, a2",
    "lw a0, a1",
    "frobnicate a0",
    "add a0, a1, x32",
    "beq a0, a1, undefined_label",
    "ecall a0",
    "mv a0",
    # lui sign-extends on RV64, so %hi of an address >= 0x80000000 is invalid
    "lui a0, %hi(d0)",
]


@pytest.mark.parametrize("line", INVALID)
def test_invalid_rejected(line):
    source = program([line])
    assert not gnu_accepts(ISA, source), f"test assumption: GNU accepts {line!r}"
    _, errors, _ = ours_text(ISA, source)
    assert errors, f"MapacheSPIM accepted invalid input {line!r}"
