"""
Conformance tests that every registered ISA must pass.

Each ISA in ``mapachespim.isa.ISA_SPECS`` supplies, below, a small program
that exercises every syscall and an instruction template that loads a
constant into a register. The tests assemble those with the built-in
assembler and run them on the simulator, so the whole pipeline (registry,
encoder, ELF writer, loader, engine binding, syscalls) is checked the same
way for every ISA. A new ISA fails ``test_every_isa_has_conformance_programs``
until it adds its entries here.
"""

from io import StringIO

import pytest

from mapachespim import ISA_SPECS, Simulator, StopReason
from mapachespim.toolchain import assemble

# Prints -5, '!', and "hi\n", echoes an integer and a character read from
# input, then exits with code 3.
SYSCALL_PROGRAMS = {
    "riscv64": """
        .isa riscv64
        .data
        msg: .asciz "hi\\n"
        .text
        .globl _start
        _start:
            li a0, -5
            li a7, 1
            ecall
            li a0, 33
            li a7, 11
            ecall
            la a0, msg
            li a7, 4
            ecall
            li a7, 5
            ecall
            li a7, 1
            ecall
            li a7, 12
            ecall
            li a7, 11
            ecall
            li a0, 3
            li a7, 17
            ecall
    """,
    "mips32": """
        .isa mips32
        .data
        msg: .asciz "hi\\n"
        .text
        .globl _start
        _start:
            li $a0, -5
            li $v0, 1
            syscall
            li $a0, 33
            li $v0, 11
            syscall
            la $a0, msg
            li $v0, 4
            syscall
            li $v0, 5
            syscall
            move $a0, $v0
            li $v0, 1
            syscall
            li $v0, 12
            syscall
            move $a0, $v0
            li $v0, 11
            syscall
            li $a0, 3
            li $v0, 17
            syscall
    """,
    "arm64": """
        .isa arm64
        .data
        msg: .asciz "hi\\n"
        .text
        .globl _start
        _start:
            mov x0, #-5
            mov x8, #1
            svc #0
            mov x0, #33
            mov x8, #11
            svc #0
            ldr x0, =msg
            mov x8, #4
            svc #0
            mov x8, #5
            svc #0
            mov x8, #1
            svc #0
            mov x8, #12
            svc #0
            mov x8, #11
            svc #0
            mov x0, #3
            mov x8, #17
            svc #0
    """,
    "x86_64": """
        .isa x86_64
        .data
        msg: .asciz "hi\\n"
        .text
        .globl _start
        _start:
            mov $-5, %rdi
            mov $1, %rax
            syscall
            mov $33, %rdi
            mov $11, %rax
            syscall
            leaq msg(%rip), %rdi
            mov $4, %rax
            syscall
            mov $5, %rax
            syscall
            mov %rax, %rdi
            mov $1, %rax
            syscall
            mov $12, %rax
            syscall
            mov %rax, %rdi
            mov $11, %rax
            syscall
            mov $3, %rdi
            mov $17, %rax
            syscall
    """,
}

# An instruction that sets register ``n`` (named ``name``) to ``value``
SET_REGISTER = {
    "riscv64": lambda n, name, value: f"li x{n}, {value}",
    "mips32": lambda n, name, value: f"li ${n}, {value}",
    "arm64": lambda n, name, value: f"mov x{n}, #{value}" if n < 31 else f"add sp, sp, #{value}",
    "x86_64": lambda n, name, value: f"mov ${value}, %{name}",
}

SPECS = pytest.mark.parametrize("spec", ISA_SPECS, ids=lambda spec: spec.name)


def _load(spec, source):
    result = assemble(source, isa=spec.name)
    assert result.success, result.errors
    sim = Simulator()
    elf = _write_temp(result.elf_bytes)
    sim.load_elf(elf)
    assert sim.spec is spec
    return sim


def _write_temp(data):
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".elf")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def test_every_isa_has_conformance_programs():
    for spec in ISA_SPECS:
        assert spec.name in SYSCALL_PROGRAMS, f"add a syscall program for {spec.name}"
        assert spec.name in SET_REGISTER, f"add a register template for {spec.name}"


@SPECS
def test_syscalls(spec):
    sim = _load(spec, SYSCALL_PROGRAMS[spec.name])
    sim.stdin = StringIO("41\nZ\n")
    sim.stdout = StringIO()
    result = sim.run_until(1000)
    assert result.reason == StopReason.EXIT, sim.last_error
    assert sim.exit_code == 3
    assert sim.stdout.getvalue() == "-5!hi\n41Z"


@SPECS
def test_every_register_is_mapped(spec):
    """Each register number reads the architectural register of that name."""
    regs = spec.registers
    lines = [f".isa {spec.name}", ".text", ".globl _start", "_start:"]
    expected = {}
    for n, name in enumerate(regs.names):
        if n == regs.zero_register:
            continue
        value = 100 + 8 * n  # small, positive, and 8-byte aligned for sp
        lines.append(SET_REGISTER[spec.name](n, name, value))
        expected[n] = value
    sim = _load(spec, "\n".join(lines))
    before = sim.get_all_regs()
    result = sim.run_until(len(expected))
    assert result.reason is None, sim.last_error
    after = sim.get_all_regs()
    for n, value in expected.items():
        if spec.name == "arm64" and n == 31:  # sp was incremented
            value += before[31]
        assert after[n] == value, f"{spec.name} register {n} ({regs.names[n]})"
    if regs.zero_register is not None:
        assert after[regs.zero_register] == 0


@SPECS
def test_register_api(spec):
    sim = Simulator(isa=spec.isa)
    assert sim.get_register_count() == spec.registers.count
    assert [sim.get_reg_name(n) for n in range(spec.registers.count)] == list(spec.registers.names)
    for n in range(spec.registers.count):
        if spec.registers.is_writable(n):
            sim.set_reg(n, 0x1234 + n)
            assert sim.get_reg(n) == 0x1234 + n
        else:
            with pytest.raises(ValueError):
                sim.set_reg(n, 1)
    with pytest.raises(ValueError):
        sim.get_reg(spec.registers.count)


@SPECS
def test_default_machine(spec):
    """Without an ELF file, code and data areas and the stack are mapped."""
    sim = Simulator(isa=spec.isa)
    layout = spec.layout
    assert sim.get_pc() == layout.text_base
    for addr in (layout.text_base, layout.data_base, layout.stack_top - 8):
        sim.write_mem(addr, b"\x5a")
        assert sim.read_mem(addr, 1) == b"\x5a"
    with pytest.raises(RuntimeError):
        sim.read_mem(0, 4)  # null stays unmapped


@SPECS
def test_unknown_syscall_is_an_error(spec):
    program = SYSCALL_PROGRAMS[spec.name]
    sim = _load(spec, program)
    sim.set_reg(spec.syscall_abi.number, 999)
    # Jump straight to the first syscall instruction
    pattern = spec.syscall_instruction
    addr = sim.get_pc()
    while not pattern.matches(int.from_bytes(sim.read_mem(addr, pattern.size), spec.byteorder)):
        addr += sim.disasm_with_size(addr)[1]
    sim.set_pc(addr)
    result = sim.run_until(1)
    assert result.reason == StopReason.ERROR
    assert "Unknown syscall number 999" in sim.last_error
