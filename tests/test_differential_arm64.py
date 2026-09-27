"""
Differential tests: the built-in ARM64 assembler against GNU as.

Random programs per instruction family (fixed seeds) must assemble to
byte-identical .text, including the literal pool used by 'ldr x0, =value'.

Skipped when aarch64-linux-gnu binutils are not installed.
Set MAPACHESPIM_FUZZ_SCALE=N to generate N times as many instructions.
"""

import random

import pytest

from mapachespim.toolchain.arm64 import CONDITIONS, encode_bitmask

from .gnu_reference import (
    FUZZ_SCALE,
    describe_mismatch,
    gnu_accepts,
    gnu_assemble,
    gnu_available,
    ours_text,
    trim_padding,
)

ISA = "arm64"
pytestmark = pytest.mark.skipif(not gnu_available(ISA), reason="GNU AArch64 binutils not installed")


def xreg(rng, zr=True):
    n = rng.randrange(32 if zr else 31)
    if n == 31:
        return "xzr"
    return rng.choice([f"x{n}"] * 4 + (["fp"] if n == 29 else []) + (["lr"] if n == 30 else []))


def wreg(rng, zr=True):
    n = rng.randrange(32 if zr else 31)
    return "wzr" if n == 31 else f"w{n}"


def reg(rng, is64, zr=True):
    return xreg(rng, zr) if is64 else wreg(rng, zr)


def sp_or_reg(rng, is64):
    if rng.random() < 0.2:
        return "sp" if is64 else "wsp"
    return reg(rng, is64, zr=False)


def imm(rng, lo, hi):
    return rng.choice([lo, hi, 0 if lo <= 0 <= hi else lo, rng.randint(lo, hi), rng.randint(lo, hi)])


def bitmask(rng, bits):
    """A random valid logical immediate."""
    while True:
        size = rng.choice([s for s in (2, 4, 8, 16, 32, 64) if s <= bits])
        ones = rng.randint(1, size - 1)
        rot = rng.randrange(size)
        elem = ((1 << ones) - 1)
        elem = ((elem >> rot) | (elem << (size - rot))) & ((1 << size) - 1)
        value = 0
        for i in range(bits // size):
            value |= elem << (i * size)
        if encode_bitmask(value, bits) is not None:
            return value


DATA = """
.data
d0: .word 1
.align 3
d1: .quad 2
.byte 9
d3: .byte 3
"""


def program(lines, labels=0, rng=None) -> str:
    body = list(lines)
    if labels and rng is not None:
        positions = sorted(rng.sample(range(len(body) + 1), labels))
        for i, pos in enumerate(reversed(positions)):
            body.insert(pos, f"L{labels - 1 - i}:")
    text = "\n".join(f"    {line}" if not line.endswith(":") else line for line in body)
    return f".text\n.globl _start\n_start:\n{text}\n{DATA}"


def assert_same_chunked(lines, labels, rng, chunk=1500) -> None:
    """Keep generated programs small enough for tbz's +/-32KB range."""
    for start in range(0, len(lines), chunk):
        assert_same(program(lines[start : start + chunk], labels, rng))


def assert_same(source: str) -> None:
    ours, errors, debug_lines = ours_text(ISA, source)
    assert not errors, f"MapacheSPIM rejected input: {errors[:3]}"
    gnu = trim_padding(gnu_assemble(ISA, source), ours)
    assert ours == gnu, describe_mismatch(ISA, source, ours, gnu, debug_lines)


def n(base):
    return base * FUZZ_SCALE


def test_add_sub():
    rng = random.Random(1)
    lines = []
    for m in ("add", "adds", "sub", "subs"):
        for _ in range(n(8)):
            is64 = rng.random() < 0.6
            s = m.endswith("s")
            rd = reg(rng, is64) if s else sp_or_reg(rng, is64)
            rn = sp_or_reg(rng, is64)
            lines.append(f"{m} {rd}, {rn}, #{imm(rng, 0, 4095)}")
            lines.append(f"{m} {rd}, {rn}, #{imm(rng, 1, 4095)}, lsl #12")
            lines.append(f"{m} {rd}, {rn}, #{rng.choice([-5, -4095, 0x5000, 4096])}")
            rn = reg(rng, is64, zr=False)
            rd = reg(rng, is64)
            shift = rng.choice(["", f", lsl #{rng.randrange(32)}", f", lsr #{rng.randrange(32)}", f", asr #{rng.randrange(32)}"])
            lines.append(f"{m} {rd}, {rn}, {reg(rng, is64)}{shift}")
            ext = rng.choice(["uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw"])
            lines.append(f"{m} {reg(rng, is64, False) if s else sp_or_reg(rng, is64)}, {sp_or_reg(rng, is64)}, {reg(rng, False)}, {ext} #{rng.randrange(5)}")
            if is64:
                # In the extended-register form, register 31 as destination is sp
                rd_ext = reg(rng, True, zr=False) if s else sp_or_reg(rng, True)
                lines.append(f"{m} {rd_ext}, {sp_or_reg(rng, True)}, {xreg(rng)}, {rng.choice(['uxtx', 'sxtx', 'lsl'])} #{rng.randrange(5)}")
    for m in ("cmp", "cmn"):
        for _ in range(n(6)):
            is64 = rng.random() < 0.6
            lines.append(f"{m} {sp_or_reg(rng, is64)}, #{imm(rng, 0, 4095)}")
            lines.append(f"{m} {reg(rng, is64, False)}, {reg(rng, is64)}")
            lines.append(f"{m} {reg(rng, is64, False)}, #-{rng.randint(1, 4095)}")
    for m in ("neg", "negs"):
        for _ in range(n(4)):
            is64 = rng.random() < 0.6
            lines.append(f"{m} {reg(rng, is64)}, {reg(rng, is64)}")
            lines.append(f"{m} {reg(rng, is64)}, {reg(rng, is64)}, lsl #{rng.randrange(32)}")
    for m in ("adc", "adcs", "sbc", "sbcs"):
        for _ in range(n(3)):
            is64 = rng.random() < 0.5
            lines.append(f"{m} {reg(rng, is64)}, {reg(rng, is64)}, {reg(rng, is64)}")
    assert_same(program(lines))


def test_logical():
    rng = random.Random(2)
    lines = []
    for m in ("and", "orr", "eor", "ands", "bic", "orn", "eon", "bics"):
        for _ in range(n(8)):
            is64 = rng.random() < 0.6
            bits = 64 if is64 else 32
            shift = rng.choice(["", f", lsl #{rng.randrange(bits)}", f", lsr #{rng.randrange(bits)}",
                                f", asr #{rng.randrange(bits)}", f", ror #{rng.randrange(bits)}"])
            lines.append(f"{m} {reg(rng, is64)}, {reg(rng, is64)}, {reg(rng, is64)}{shift}")
            if m in ("and", "orr", "eor", "ands"):
                rd = sp_or_reg(rng, is64) if m != "ands" else reg(rng, is64)
                lines.append(f"{m} {rd}, {reg(rng, is64)}, #{hex(bitmask(rng, bits))}")
    for _ in range(n(6)):
        is64 = rng.random() < 0.6
        bits = 64 if is64 else 32
        lines.append(f"tst {reg(rng, is64)}, #{hex(bitmask(rng, bits))}")
        lines.append(f"tst {reg(rng, is64)}, {reg(rng, is64)}")
        lines.append(f"mvn {reg(rng, is64)}, {reg(rng, is64)}")
    assert_same(program(lines))


def test_moves():
    rng = random.Random(3)
    lines = []
    for _ in range(n(12)):
        is64 = rng.random() < 0.6
        bits = 64 if is64 else 32
        rd = reg(rng, is64, zr=False)
        lines.append(f"mov {rd}, {reg(rng, is64)}")
        lines.append(f"mov {sp_or_reg(rng, is64)}, {'sp' if is64 else 'wsp'}")
        hw = rng.randrange(bits // 16)
        lines.append(f"mov {rd}, #{hex(rng.randrange(1 << 16) << (16 * hw))}")
        lines.append(f"mov {rd}, #{-rng.randrange(1, 1 << 16)}")
        lines.append(f"mov {rd}, #{hex(bitmask(rng, bits))}")
        for m in ("movz", "movn", "movk"):
            lines.append(f"{m} {rd}, #{rng.randrange(1 << 16)}, lsl #{16 * rng.randrange(bits // 16)}")
            lines.append(f"{m} {rd}, #{rng.randrange(1 << 16)}")
    assert_same(program(lines))


def test_multiply_divide_shift():
    rng = random.Random(4)
    lines = []
    for _ in range(n(8)):
        is64 = rng.random() < 0.6
        bits = 64 if is64 else 32
        r = lambda: reg(rng, is64)  # noqa: E731
        lines += [
            f"mul {r()}, {r()}, {r()}",
            f"mneg {r()}, {r()}, {r()}",
            f"madd {r()}, {r()}, {r()}, {r()}",
            f"msub {r()}, {r()}, {r()}, {r()}",
            f"sdiv {r()}, {r()}, {r()}",
            f"udiv {r()}, {r()}, {r()}",
            f"lsl {r()}, {r()}, #{rng.randrange(bits)}",
            f"lsr {r()}, {r()}, #{rng.randrange(bits)}",
            f"asr {r()}, {r()}, #{rng.randrange(bits)}",
            f"ror {r()}, {r()}, #{rng.randrange(bits)}",
            f"lsl {r()}, {r()}, {r()}",
            f"lsr {r()}, {r()}, {r()}",
            f"asr {r()}, {r()}, {r()}",
            f"ror {r()}, {r()}, {r()}",
            f"smull {xreg(rng)}, {wreg(rng)}, {wreg(rng)}",
            f"umull {xreg(rng)}, {wreg(rng)}, {wreg(rng)}",
            f"smaddl {xreg(rng)}, {wreg(rng)}, {wreg(rng)}, {xreg(rng)}",
            f"umaddl {xreg(rng)}, {wreg(rng)}, {wreg(rng)}, {xreg(rng)}",
            f"smulh {xreg(rng)}, {xreg(rng)}, {xreg(rng)}",
            f"umulh {xreg(rng)}, {xreg(rng)}, {xreg(rng)}",
        ]
    assert_same(program(lines))


def test_bitfield_and_extend():
    rng = random.Random(5)
    lines = []
    for _ in range(n(8)):
        is64 = rng.random() < 0.6
        bits = 64 if is64 else 32
        lsb = rng.randrange(bits)
        width = rng.randint(1, bits - lsb)
        r = lambda: reg(rng, is64)  # noqa: E731
        for m in ("ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil"):
            lines.append(f"{m} {r()}, {r()}, #{lsb}, #{width}")
        lines += [
            f"sxtb {r()}, {wreg(rng)}",
            f"sxth {r()}, {wreg(rng)}",
            f"sxtw {xreg(rng)}, {wreg(rng)}",
            f"uxtb {wreg(rng)}, {wreg(rng)}",
            f"uxth {wreg(rng)}, {wreg(rng)}",
            f"extr {r()}, {r()}, {r()}, #{rng.randrange(bits)}",
            f"ubfm {r()}, {r()}, #{rng.randrange(bits)}, #{rng.randrange(bits)}",
        ]
    assert_same(program(lines))


def test_conditional():
    rng = random.Random(6)
    conds = [c for c in CONDITIONS if c not in ("al", "nv")]
    lines = []
    for _ in range(n(8)):
        is64 = rng.random() < 0.6
        r = lambda: reg(rng, is64)  # noqa: E731
        c = rng.choice(conds)
        lines += [
            f"csel {r()}, {r()}, {r()}, {c}",
            f"csinc {r()}, {r()}, {r()}, {c}",
            f"csinv {r()}, {r()}, {r()}, {c}",
            f"csneg {r()}, {r()}, {r()}, {c}",
            f"cset {r()}, {c}",
            f"csetm {r()}, {c}",
            f"cinc {r()}, {r()}, {c}",
            f"cinv {r()}, {r()}, {c}",
            f"cneg {r()}, {r()}, {c}",
            f"ccmp {r()}, {r()}, #{rng.randrange(16)}, {c}",
            f"ccmn {r()}, #{rng.randrange(32)}, #{rng.randrange(16)}, {c}",
        ]
    assert_same(program(lines))


def test_loads_and_stores():
    rng = random.Random(7)
    lines = []
    forms = [("ldr", True, 8), ("str", True, 8), ("ldr", False, 4), ("str", False, 4),
             ("ldrb", False, 1), ("strb", False, 1), ("ldrh", False, 2), ("strh", False, 2),
             ("ldrsb", True, 1), ("ldrsb", False, 1), ("ldrsh", True, 2), ("ldrsh", False, 2),
             ("ldrsw", True, 4)]  # fmt: skip
    for m, is64, size in forms:
        for _ in range(n(4)):
            rt = reg(rng, is64)
            base = rng.choice(["sp", xreg(rng, zr=False)])
            scaled = rng.randrange(4096) * size
            lines += [
                f"{m} {rt}, [{base}]",
                f"{m} {rt}, [{base}, #{scaled}]",
                f"{m} {rt}, [{base}, #{rng.randint(-256, 255)}]",
                f"{m} {rt}, [{base}, #{rng.randint(-256, 255)}]!",
                f"{m} {rt}, [{base}], #{rng.randint(-256, 255)}",
                f"{m} {rt}, [{base}, {xreg(rng)}]",
                f"{m} {rt}, [{base}, {xreg(rng)}, lsl #{rng.choice([0, {1: 0, 2: 1, 4: 2, 8: 3}[size]])}]",
                f"{m} {rt}, [{base}, {wreg(rng)}, {rng.choice(['uxtw', 'sxtw'])}]",
                f"{m} {rt}, [{base}, {wreg(rng)}, sxtw #{ {1: 0, 2: 1, 4: 2, 8: 3}[size]}]",
            ]
    for m in ("ldur", "stur", "ldurb", "sturb", "ldurh", "sturh", "ldursw", "ldursb", "ldursh"):
        for _ in range(n(3)):
            is64 = m in ("ldursw",) or (m in ("ldur", "stur") and rng.random() < 0.5)
            lines.append(f"{m} {reg(rng, is64)}, [{xreg(rng, zr=False)}, #{rng.randint(-256, 255)}]")
    for m in ("ldp", "stp"):
        for _ in range(n(6)):
            is64 = rng.random() < 0.6
            size = 8 if is64 else 4
            a, b = rng.sample(range(31), 2)
            rt = (f"x{a}", f"x{b}") if is64 else (f"w{a}", f"w{b}")
            off = rng.randint(-64, 63) * size
            base = rng.choice(["sp", xreg(rng, zr=False)])
            lines += [
                f"{m} {rt[0]}, {rt[1]}, [{base}]",
                f"{m} {rt[0]}, {rt[1]}, [{base}, #{off}]",
                f"{m} {rt[0]}, {rt[1]}, [{base}, #{off}]!",
                f"{m} {rt[0]}, {rt[1]}, [{base}], #{off}",
            ]
    lines += ["stp x29, x30, [sp, #-16]!", "ldp x29, x30, [sp], #16"]
    assert_same(program(lines))


def test_branches():
    rng = random.Random(8)
    labels = 10
    lines = []
    for _ in range(n(8)):
        lines += [
            f"b L{rng.randrange(labels)}",
            f"bl L{rng.randrange(labels)}",
            f"b.{rng.choice(list(CONDITIONS))} L{rng.randrange(labels)}",
            f"cbz {reg(rng, rng.random() < 0.5)}, L{rng.randrange(labels)}",
            f"cbnz {reg(rng, rng.random() < 0.5)}, L{rng.randrange(labels)}",
            f"tbz {xreg(rng)}, #{rng.randrange(64)}, L{rng.randrange(labels)}",
            f"tbnz {wreg(rng)}, #{rng.randrange(32)}, L{rng.randrange(labels)}",
            f"br {xreg(rng)}",
            f"blr {xreg(rng)}",
            f"ret {xreg(rng)}",
            "ret",
            f"adr {xreg(rng)}, L{rng.randrange(labels)}",
            f"adrp {xreg(rng)}, L{rng.randrange(labels)}",
        ]
    rng.shuffle(lines)
    assert_same_chunked(lines, labels, rng)


def test_literals_and_addresses():
    rng = random.Random(9)
    lines = []
    for _ in range(n(6)):
        value = rng.choice([rng.randrange(1 << 64), rng.randrange(1 << 16), 0x123456789, 5])
        lines += [
            f"ldr {xreg(rng, zr=False)}, ={hex(value)}",
            f"ldr {wreg(rng, zr=False)}, ={rng.randrange(1 << 32)}",
            f"ldr {xreg(rng, zr=False)}, ={rng.choice(['d0', 'd1', 'd1+8', '_start'])}",
            f"ldrsw {xreg(rng, zr=False)}, ={rng.randrange(1 << 31)}",
            f"adrp {xreg(rng)}, {rng.choice(['d0', 'd1'])}",
            f"add {xreg(rng, zr=False)}, {xreg(rng, zr=False)}, :lo12:{rng.choice(['d0', 'd1'])}",
            f"ldr {xreg(rng)}, [{xreg(rng, zr=False)}, :lo12:d1]",
            f"ldr {wreg(rng)}, [{xreg(rng, zr=False)}, #:lo12:d0]",
        ]
    lines.insert(len(lines) // 2, ".ltorg")
    assert_same(program(lines))


def test_system():
    rng = random.Random(10)
    lines = ["nop", "svc #0", "brk #1", f"svc #{rng.randrange(1 << 16)}", "hlt #0"]
    assert_same(program(lines))


def test_whole_examples():
    from mapachespim.examples import list_examples

    for example in list_examples():
        if example.isa == "arm" and example.source is not None:
            assert_same(example.source.read_text().replace(".isa arm64", ""))


INVALID = [
    "add x0, x1, #4097",
    "add x0, x1, w2",
    "add x0, w1, x2",
    "mov x0, #0x123456789",
    "and x0, x1, #0",
    "and x0, x1, #5",
    "lsl x0, x1, #64",
    "ldr x0, [x1, #4]!x",
    "ldr x0, [x1, #1000]!",
    "ldr w0, [x1, #32768]",
    "ldr x0, [x1, :lo12:d3]",
    "ldp x0, x1, [sp, #4]",
    "b.xx L0",
    "cbz x0",
    "frobnicate x0",
    "mov x0, x32",
    "movz x0, #65536",
    "svc #65536",
    "adr x0, d0",
]


@pytest.mark.parametrize("line", INVALID)
def test_invalid_rejected(line):
    source = program([line, "L0:"])
    assert not gnu_accepts(ISA, source), f"test assumption: GNU accepts {line!r}"
    _, errors, _ = ours_text(ISA, source)
    assert errors, f"MapacheSPIM accepted invalid input {line!r}"
