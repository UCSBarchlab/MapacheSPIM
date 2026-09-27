"""
The registers 'regs' shows beyond the general-purpose ones: MIPS hi/lo and
the condition flags of x86-64 (rflags) and ARM64 (nzcv).
"""

import io

import pytest

from mapachespim.console import MapacheSPIMConsole


def run_regs(tmp_path, source, steps):
    """Load source, step it, and return the output of 'regs'"""
    path = tmp_path / "prog.s"
    path.write_text(source)
    console = MapacheSPIMConsole(verbose=False)
    console.stdout = io.StringIO()
    console.onecmd(f"load {path}")
    console.onecmd(f"step {steps}")
    console.stdout = io.StringIO()
    console.onecmd("regs")
    return console, console.stdout.getvalue()


MIPS_MULT_DIV = """
.isa mips32
.text
_start:
    li   $t0, 6
    li   $t1, 7
    mult $t0, $t1
    li   $t2, 20
    div  $t2, $t0
"""


def test_mips_hi_lo_after_mult(tmp_path):
    console, out = run_regs(tmp_path, MIPS_MULT_DIV, 3)
    assert console.sim.get_special_regs() == [0, 42]
    assert " lo = 0x000000000000002a ★" in out


def test_mips_hi_lo_after_div(tmp_path):
    console, out = run_regs(tmp_path, MIPS_MULT_DIV, 5)
    assert console.sim.get_special_regs() == [2, 3]  # remainder, quotient
    assert " hi = 0x0000000000000002 ★" in out
    assert " lo = 0x0000000000000003 ★" in out


@pytest.mark.parametrize(
    "compare_with, expected",
    [
        (3, "nzcv: N=0 Z=1 C=1 V=0"),  # equal
        (5, "nzcv: N=1 Z=0 C=0 V=0"),  # less than
    ],
)
def test_arm64_nzcv(tmp_path, compare_with, expected):
    source = f".isa arm64\n.text\n_start:\n    mov x0, #3\n    cmp x0, #{compare_with}\n"
    _, out = run_regs(tmp_path, source, 2)
    assert expected in out


@pytest.mark.parametrize(
    "instructions, expected",
    [
        ("movq $3, %rax\n    cmpq $3, %rax", "rflags: CF=0 ZF=1 SF=0 OF=0"),
        ("movq $3, %rax\n    cmpq $5, %rax", "rflags: CF=1 ZF=0 SF=1 OF=0"),
        ("movq $0x7fffffffffffffff, %rax\n    addq $1, %rax", "rflags: CF=0 ZF=0 SF=1 OF=1"),
    ],
)
def test_x86_rflags(tmp_path, instructions, expected):
    source = f".isa x86_64\n.text\n_start:\n    {instructions}\n"
    _, out = run_regs(tmp_path, source, 2)
    assert expected in out


def test_flags_marked_only_when_changed(tmp_path):
    source = ".isa x86_64\n.text\n_start:\n    cmpq $0, %rax\n    movq $1, %rbx\n"
    console, out = run_regs(tmp_path, source, 1)
    assert "ZF=1 SF=0 OF=0 ★" in out
    console.onecmd("step")
    console.stdout = io.StringIO()
    console.onecmd("regs")
    assert "ZF=1 SF=0 OF=0\n" in console.stdout.getvalue()


def test_riscv_has_no_flags_or_special_registers(tmp_path):
    source = ".isa riscv64\n.text\n_start:\n    li a0, 1\n"
    console, out = run_regs(tmp_path, source, 1)
    assert console.sim.get_special_regs() == []
    assert console.sim.get_flags() is None
    assert "flags" not in out and "nzcv" not in out


def test_regs_without_a_program():
    console = MapacheSPIMConsole(verbose=False)
    console.stdout = io.StringIO()
    console.onecmd("regs")
    assert "No program loaded" in console.stdout.getvalue()
