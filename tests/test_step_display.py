"""
How the console shows code and values: the source line when stepping,
register widths that match the ISA, and x86-64 disassembly in the syntax
the program was written in.
"""

import io

from mapachespim.console import MapacheSPIMConsole
from mapachespim.toolchain import assemble
from mapachespim.toolchain.x86 import syntax_by_line


def load(tmp_path, source, name="prog.s"):
    """A console with source loaded, and its output cleared"""
    path = tmp_path / name
    path.write_text(source)
    console = MapacheSPIMConsole(verbose=False)
    console.stdout = io.StringIO()
    console.onecmd(f"load {path}")
    console.stdout = io.StringIO()
    return console


def run(console, command):
    """Run a console command and return what it printed"""
    console.stdout = io.StringIO()
    console.onecmd(command)
    return console.stdout.getvalue()


# --- Source lines when stepping ---

RISCV_LA = """.isa riscv64
.data
msg: .asciz "hi"
.text
_start:
    la   a0, msg        # two instructions
    li   a7, 10
    ecall
"""


def test_step_shows_source_line_before_its_instructions(tmp_path):
    console = load(tmp_path, RISCV_LA)
    lines = run(console, "step 3").splitlines()
    assert lines[0] == "prog.s:6: la   a0, msg        # two instructions"
    assert "auipc a0" in lines[1]
    assert lines[2].startswith("[0x80000004]")  # the rest of la: no repeated source line
    assert lines[3] == "prog.s:7: li   a7, 10"
    assert "addi a7, zero, 0xa" in lines[4]


def test_each_step_command_shows_its_source_line(tmp_path):
    console = load(tmp_path, RISCV_LA)
    run(console, "step")
    lines = run(console, "step").splitlines()
    assert lines[0] == "prog.s:6: la   a0, msg        # two instructions"
    assert lines[1].startswith("[0x80000004]")


# --- Register and address widths ---

MIPS_NEGATIVE = """.isa mips32
.text
_start:
    li $t0, -1
    li $t1, 5
"""


def test_mips32_registers_are_8_hex_digits(tmp_path):
    console = load(tmp_path, MIPS_NEGATIVE)
    run(console, "step 2")
    out = run(console, "regs")
    assert " t0 = 0xffffffff ★" in out
    assert " t1 = 0x00000005 ★" in out
    assert "pc = 0x00400008" in out
    assert run(console, "pc").strip() == "pc = 0x00400008"


def test_mips32_decimal_and_binary_are_32_bits(tmp_path):
    console = load(tmp_path, MIPS_NEGATIVE)
    run(console, "step 2")
    assert " t0 = .........-1 ★" in run(console, "regs decimal")
    assert " t0 = 0b" + "1" * 32 + " " in run(console, "regs binary")


def test_mips32_load_shows_8_digit_entry_point(tmp_path):
    path = tmp_path / "prog.s"
    path.write_text(MIPS_NEGATIVE)
    console = MapacheSPIMConsole(verbose=False)
    console.stdout = io.StringIO()
    console.onecmd(f"load {path}")
    assert "Entry point: 0x00400000\n" in console.stdout.getvalue()


def test_64_bit_registers_are_16_hex_digits(tmp_path):
    console = load(tmp_path, RISCV_LA)
    assert "pc = 0x0000000080000000" in run(console, "regs")


# --- x86-64 disassembly syntax ---

X86_ATT = """.isa x86_64
.text
_start:
    movq $5, %rdi
    call sq
    movq $10, %rax
    syscall
sq:
    movq %rdi, %rax
    ret
"""

X86_INTEL = """.isa x86_64
.text
_start:
    mov rdi, 5
    call sq
    mov rax, 10
    syscall
sq:
    mov rax, rdi
    ret
"""


def test_att_source_disassembles_as_att(tmp_path):
    console = load(tmp_path, X86_ATT)
    out = run(console, "step 3")
    assert "movq $5, %rdi" in out
    assert "callq 0x" in out  # a bare label, shown in the program's syntax
    assert "movq %rdi, %rax" in out
    assert "movq $0xa, %rax" in run(console, "disasm _start 3")


def test_intel_source_disassembles_as_intel(tmp_path):
    console = load(tmp_path, X86_INTEL)
    out = run(console, "step 3")
    assert "mov rdi, 5" in out
    assert "mov rax, rdi" in out
    assert "mov rax, 0xa" in run(console, "disasm _start 3")


def test_elf_without_source_disassembles_as_intel(tmp_path):
    result = assemble(X86_ATT, "x86_64")
    assert result.success, result.errors
    elf = tmp_path / "prog"
    elf.write_bytes(result.elf_bytes)
    console = MapacheSPIMConsole(verbose=False)
    console.stdout = io.StringIO()
    console.onecmd(f"load {elf}")
    assert "mov rdi, 5" in run(console, "step")


def test_syntax_by_line():
    source = """.isa x86_64
_start: movq $1, %rax        # 2: AT&T by its operands
    mov rax, 1                # 3: Intel by its operands
    jmp _start                # 4: reads the same either way
    ret                       # 5: no operands
.intel_syntax noprefix
    jmp _start                # 7: Intel by directive
.att_syntax
    imulq 8(%rsp)             # 9: AT&T by directive
"""
    assert syntax_by_line(source) == {2: "att", 3: "intel", 7: "intel", 9: "att"}
