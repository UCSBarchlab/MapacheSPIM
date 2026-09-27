"""
Differential tests: the built-in x86-64 assembler against GNU as.

Random programs per instruction family (fixed seeds) must assemble to
byte-identical .text, in AT&T syntax and in Intel syntax
(.intel_syntax noprefix), including GNU's choice of short/long jumps.

Skipped when x86_64-linux-gnu binutils are not installed.
Set MAPACHESPIM_FUZZ_SCALE=N to generate N times as many instructions.
"""

import random

import pytest

from mapachespim.toolchain.x86 import CONDITIONS

from .gnu_reference import (
    FUZZ_SCALE,
    describe_mismatch,
    gnu_accepts,
    gnu_assemble,
    gnu_available,
    ours_text,
    trim_padding,
)

ISA = "x86_64"
pytestmark = pytest.mark.skipif(not gnu_available(ISA), reason="GNU x86-64 binutils not installed")

R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]
R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"] + [f"r{i}d" for i in range(8, 16)]
R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"] + [f"r{i}w" for i in range(8, 16)]
R8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"] + [f"r{i}b" for i in range(8, 16)]
REGS = {8: R64, 4: R32, 2: R16, 1: R8}
SUFFIX = {8: "q", 4: "l", 2: "w", 1: "b"}
PTR = {8: "qword", 4: "dword", 2: "word", 1: "byte"}
DATA_LABELS = ["d0", "d1", "d2"]


def imm_for(rng, size, symbolic_ok=True):
    bits = 8 * min(size, 4)
    choice = rng.random()
    if symbolic_ok and size >= 4 and choice < 0.1:
        return rng.choice(DATA_LABELS)
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    return rng.choice([0, 1, -1, 127, -128, 128, -129, lo, hi, rng.randint(lo, hi), rng.randint(-200, 200)])


def att_mem(rng):
    """A random AT&T memory operand."""
    kind = rng.random()
    base = rng.choice(R64)
    index = rng.choice([r for r in R64 if r != "rsp"])
    scale = rng.choice([1, 2, 4, 8])
    disp = rng.choice(["", "0", "8", "-8", "127", "-128", "128", "4096", "-70000", rng.choice(DATA_LABELS)])
    if kind < 0.1:
        return f"{rng.choice(DATA_LABELS)}(%rip)"
    if kind < 0.15:
        return rng.choice(DATA_LABELS)
    if kind < 0.2:
        return f"{disp or '0'}(,%{index},{scale})"
    if kind < 0.6:
        return f"{disp}(%{base})"
    return f"{disp}(%{base},%{index},{scale})"


def intel_mem(rng, size):
    kind = rng.random()
    base = rng.choice(R64)
    index = rng.choice([r for r in R64 if r != "rsp"])
    scale = rng.choice([1, 2, 4, 8])
    disp = rng.choice(["", "+8", "-8", "+128", "-4096", f"+{rng.choice(DATA_LABELS)}"])
    if kind < 0.15:
        inner = f"rip+{rng.choice(DATA_LABELS)}"
    elif kind < 0.6:
        inner = f"{base}{disp}"
    else:
        inner = f"{base}+{index}*{scale}{disp}"
    return f"{PTR[size]} ptr [{inner}]"


DATA = """
.data
d0: .quad 1
d1: .quad 2
d2: .quad 3
"""


def program(lines, labels=0, rng=None, intel=False):
    body = list(lines)
    if labels and rng is not None:
        positions = sorted(rng.sample(range(len(body) + 1), labels))
        for i, pos in enumerate(reversed(positions)):
            body.insert(pos, f"L{labels - 1 - i}:")
    text = "\n".join(f"    {line}" if not line.endswith(":") else line for line in body)
    head = ".intel_syntax noprefix\n" if intel else ""
    return f"{head}.text\n.globl _start\n_start:\n{text}\n{DATA}"


def assert_same(source):
    ours, errors, debug_lines = ours_text(ISA, source)
    assert not errors, f"MapacheSPIM rejected input: {errors[:3]}"
    gnu = trim_padding(gnu_assemble(ISA, source), ours)
    if ours != gnu:
        # Report the first differing instruction by disassembling both
        from capstone import CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT, Cs

        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.syntax = CS_OPT_SYNTAX_ATT
        a = [(i.address, i.bytes.hex(), f"{i.mnemonic} {i.op_str}") for i in cs.disasm(ours, 0x400000)]
        b = [(i.address, i.bytes.hex(), f"{i.mnemonic} {i.op_str}") for i in cs.disasm(gnu, 0x400000)]
        for x, y in zip(a, b):
            if x != y:
                line_no = max((ln for addr, ln in debug_lines if addr <= x[0]), default=0)
                src = source.splitlines()[line_no - 1].strip() if line_no else "?"
                pytest.fail(f"at {x[0]:#x} ({src!r}): ours {x[1]} {x[2]} | GNU {y[1]} {y[2]}")
        pytest.fail(describe_mismatch(ISA, source, ours, gnu, debug_lines))


def n(base):
    return base * FUZZ_SCALE


def test_alu():
    rng = random.Random(1)
    lines = []
    for m in ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"):
        for _ in range(n(6)):
            size = rng.choice([8, 4, 2, 1])
            s = SUFFIX[size]
            r = lambda: rng.choice(REGS[size])  # noqa: E731
            lines += [
                f"{m}{s} %{r()}, %{r()}",
                f"{m}{s} ${imm_for(rng, size)}, %{r()}",
                f"{m}{s} ${imm_for(rng, size)}, %{REGS[size][0]}",
                f"{m}{s} {att_mem(rng)}, %{r()}",
                f"{m}{s} %{r()}, {att_mem(rng)}",
                f"{m}{s} ${imm_for(rng, size)}, {att_mem(rng)}",
                f"{m} %{r()}, %{r()}",
            ]
    assert_same(program(lines))


def test_mov():
    rng = random.Random(2)
    lines = []
    for _ in range(n(10)):
        size = rng.choice([8, 4, 2, 1])
        s = SUFFIX[size]
        r = lambda: rng.choice(REGS[size])  # noqa: E731
        lines += [
            f"mov{s} %{r()}, %{r()}",
            f"mov{s} ${imm_for(rng, size)}, %{r()}",
            f"mov{s} {att_mem(rng)}, %{r()}",
            f"mov{s} %{r()}, {att_mem(rng)}",
            f"mov{s} ${imm_for(rng, size)}, {att_mem(rng)}",
        ]
        big = rng.choice([0x80000000, 0x123456789, -0x80000001, 0xFFFFFFFF, 1 << 63])
        lines += [
            f"movq ${big}, %{rng.choice(R64)}",
            f"movabsq ${rng.randrange(1 << 64)}, %{rng.choice(R64)}",
            f"movq ${rng.choice(DATA_LABELS)}, %{rng.choice(R64)}",
            f"movl ${rng.choice(DATA_LABELS)}, %{rng.choice(R32)}",
            f"mov %{rng.choice(['ah', 'bh', 'ch', 'dh'])}, %{rng.choice(['al', 'bl', 'cl', 'dl'])}",
            f"leaq {att_mem(rng)}, %{rng.choice(R64)}",
            f"leal {att_mem(rng)}, %{rng.choice(R32)}",
        ]
    assert_same(program(lines))


def test_unary_and_multiply():
    rng = random.Random(3)
    lines = []
    for _ in range(n(6)):
        size = rng.choice([8, 4, 2, 1])
        s = SUFFIX[size]
        r = lambda: rng.choice(REGS[size])  # noqa: E731
        for m in ("inc", "dec", "neg", "not", "mul", "div", "idiv", "imul"):
            lines.append(f"{m}{s} %{r()}")
            lines.append(f"{m}{s} {att_mem(rng)}")
        if size > 1:
            lines += [
                f"imul{s} %{r()}, %{r()}",
                f"imul{s} {att_mem(rng)}, %{r()}",
                f"imul{s} ${imm_for(rng, size, False)}, %{r()}, %{r()}",
                f"imul{s} ${imm_for(rng, size, False)}, %{r()}",
                f"imul{s} ${imm_for(rng, size, False)}, {att_mem(rng)}, %{r()}",
            ]
        lines += [
            f"test{s} %{r()}, %{r()}",
            f"test{s} ${imm_for(rng, size, False)}, %{r()}",
            f"test{s} ${imm_for(rng, size, False)}, %{REGS[size][0]}",
            f"test{s} %{r()}, {att_mem(rng)}",
            f"test{s} ${imm_for(rng, size, False)}, {att_mem(rng)}",
        ]
    assert_same(program(lines))


def test_shifts():
    rng = random.Random(4)
    lines = []
    for m in ("rol", "ror", "rcl", "rcr", "shl", "sal", "shr", "sar"):
        for _ in range(n(4)):
            size = rng.choice([8, 4, 2, 1])
            s = SUFFIX[size]
            r = rng.choice(REGS[size])
            lines += [
                f"{m}{s} %{r}",
                f"{m}{s} $1, %{r}",
                f"{m}{s} ${rng.randrange(2, 64)}, %{r}",
                f"{m}{s} %cl, %{r}",
                f"{m}{s} ${rng.randrange(64)}, {att_mem(rng)}",
                f"{m}{s} %cl, {att_mem(rng)}",
            ]
    assert_same(program(lines))


def test_stack_exchange_extend():
    rng = random.Random(5)
    lines = []
    for _ in range(n(6)):
        lines += [
            f"push %{rng.choice(R64)}",
            f"pop %{rng.choice(R64)}",
            f"pushq ${imm_for(rng, 4, False)}",
            f"pushq {att_mem(rng)}",
            f"popq {att_mem(rng)}",
            f"pushw %{rng.choice(R16)}",
            f"xchg %{rng.choice(R64)}, %{rng.choice(R64)}",
            f"xchg %{rng.choice(R32)}, %{rng.choice(R32)}",
            f"xchg %{rng.choice(R8)}, %{rng.choice(R8)}",
            f"xchgq %{rng.choice(R64)}, {att_mem(rng)}",
            f"movzbl %{rng.choice(R8)}, %{rng.choice(R32)}",
            f"movzbq {att_mem(rng)}, %{rng.choice(R64)}",
            f"movzwl %{rng.choice(R16)}, %{rng.choice(R32)}",
            f"movzwq %{rng.choice(R16)}, %{rng.choice(R64)}",
            f"movsbl %{rng.choice(R8)}, %{rng.choice(R32)}",
            f"movsbq %{rng.choice(R8)}, %{rng.choice(R64)}",
            f"movswl {att_mem(rng)}, %{rng.choice(R32)}",
            f"movswq %{rng.choice(R16)}, %{rng.choice(R64)}",
            f"movslq %{rng.choice(R32)}, %{rng.choice(R64)}",
            f"movslq {att_mem(rng)}, %{rng.choice(R64)}",
        ]
    assert_same(program(lines))


def test_conditions():
    rng = random.Random(6)
    lines = []
    for cc in CONDITIONS:
        lines += [
            f"set{cc} %{rng.choice(R8)}",
            f"set{cc} {att_mem(rng)}",
            f"cmov{cc} %{rng.choice(R64)}, %{rng.choice(R64)}",
            f"cmov{cc}l {att_mem(rng)}, %{rng.choice(R32)}",
        ]
    assert_same(program(lines))


def test_jumps_and_relaxation():
    rng = random.Random(7)
    labels = 12
    lines = []
    conds = list(CONDITIONS)
    for _ in range(n(10)):
        lines += [
            f"jmp L{rng.randrange(labels)}",
            f"j{rng.choice(conds)} L{rng.randrange(labels)}",
            f"call L{rng.randrange(labels)}",
            f"jmp *%{rng.choice(R64)}",
            f"call *%{rng.choice(R64)}",
            f"jmp *{att_mem(rng)}",
            f"call *{att_mem(rng)}",
        ]
        # Filler so some jumps need rel32 and others fit in rel8
        lines += [f"movq $0x12345678, %{rng.choice(R64)}"] * rng.choice([0, 1, 5, 20])
    rng.shuffle(lines)
    assert_same(program(lines, labels, rng))


def test_misc():
    lines = ["ret", "ret $8", "leave", "nop", "hlt", "syscall", "int3", "int $0x80",
             "cbtw", "cwtl", "cltq", "cwtd", "cltd", "cqto", "cqo", "cdq", "cdqe", "cwde",
             "retq", "callq *%rax", "jmpq *%rax"]  # fmt: skip
    assert_same(program(lines))


def test_intel_syntax():
    rng = random.Random(8)
    lines = []
    for _ in range(n(10)):
        size = rng.choice([8, 4, 2, 1])
        r = lambda: rng.choice(REGS[size])  # noqa: E731
        m = rng.choice(["add", "sub", "and", "or", "xor", "cmp", "mov"])
        imm = imm_for(rng, size, False)
        lines += [
            f"{m} {r()}, {r()}",
            f"{m} {r()}, {imm}",
            f"{m} {r()}, {intel_mem(rng, size)}",
            f"{m} {intel_mem(rng, size)}, {r()}",
            f"{m} {intel_mem(rng, size)}, {imm}",
            f"lea {rng.choice(R64)}, [{rng.choice(R64)}+{rng.choice(['rcx', 'rdx'])}*4+16]",
            f"lea {rng.choice(R64)}, [rip+{rng.choice(DATA_LABELS)}]",
            f"push {rng.choice(R64)}",
            f"pop {rng.choice(R64)}",
            f"inc {intel_mem(rng, size)}",
            f"imul {rng.choice(R64)}, {rng.choice(R64)}, 10",
            f"shl {r()}, {rng.randrange(1, 8)}",
            f"movzx {rng.choice(R32)}, byte ptr [{rng.choice(R64)}]",
            f"movsxd {rng.choice(R64)}, {rng.choice(R32)}",
            f"mov {rng.choice(R64)}, offset {rng.choice(DATA_LABELS)}",
        ]
    lines += ["jmp L0", "je L0", "call L0", "jmp rax", "call qword ptr [rax]", "L0:", "ret"]
    assert_same(program(lines, intel=True))


def test_whole_examples():
    from mapachespim.examples import list_examples

    for example in list_examples():
        if example.isa == "x86_64" and example.source is not None:
            assert_same(example.source.read_text().replace(".isa x86_64", ""))


INVALID = [
    "movq %rax",
    "addq %rax, %ebx",
    "movb %ah, %sil",
    "movq (%rax), (%rbx)",
    "movq $0x123456789, (%rax)",
    "addq $0x123456789, %rax",
    "movl (%rax,%rsp,2), %eax",
    "movl (%rax,%rbx,3), %eax",
    "frobnicate %rax",
    "jmp",
    "shll %eax, %ebx",
    "pushl %eax",
]


@pytest.mark.parametrize("line", INVALID)
def test_invalid_rejected(line):
    source = program([line])
    assert not gnu_accepts(ISA, source), f"test assumption: GNU accepts {line!r}"
    _, errors, _ = ours_text(ISA, source)
    assert errors, f"MapacheSPIM accepted invalid input {line!r}"
