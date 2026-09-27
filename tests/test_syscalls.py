"""SyscallHandler and ProgramIO, tested without the emulator."""

from io import StringIO

import pytest

from mapachespim.isa import ISA_SPECS, get_spec
from mapachespim.syscalls import ProgramIO, Syscall, SyscallHandler, read_c_string


class FakeMachine:
    """Registers and a little memory, with the ISA's register rules."""

    def __init__(self, spec, memory=None, base=0x1000):
        self.spec = spec
        self.regs = [0] * spec.registers.count
        self.memory = bytes(memory or b"")
        self.base = base

    def get_reg(self, n):
        return self.regs[n]

    def set_reg(self, n, value):
        if not self.spec.registers.is_writable(n):
            raise ValueError(n)
        self.regs[n] = value & ((1 << self.spec.word_bits) - 1)

    def read_mem(self, addr, length):
        start = addr - self.base
        if start < 0 or start + length > len(self.memory):
            raise RuntimeError("unmapped")
        return self.memory[start : start + length]

    def request(self, number, arg0=0):
        abi = self.spec.syscall_abi
        self.regs[abi.number] = number
        self.regs[abi.arg0] = arg0 & ((1 << self.spec.word_bits) - 1)


def _handler(stdin=""):
    io = ProgramIO()
    io.stdout = StringIO()
    io.stdin = StringIO(stdin)
    return SyscallHandler(io), io


SPECS = pytest.mark.parametrize("spec", ISA_SPECS, ids=lambda spec: spec.name)


@SPECS
def test_print_int_is_signed_at_register_width(spec):
    handler, io = _handler()
    machine = FakeMachine(spec)
    machine.request(Syscall.PRINT_INT, -7)
    assert handler.handle(machine).exit_code is None
    assert io.stdout.getvalue() == "-7"
    assert io.output_needs_newline


@SPECS
def test_print_string_and_char(spec):
    handler, io = _handler()
    machine = FakeMachine(spec, b"hello\n\x00junk")
    machine.request(Syscall.PRINT_STRING, 0x1000)
    handler.handle(machine)
    machine.request(Syscall.PRINT_CHAR, ord("!") | 0x100)  # only the low byte counts
    handler.handle(machine)
    assert io.stdout.getvalue() == "hello\n!"


@SPECS
def test_read_int_and_char(spec):
    handler, io = _handler("  12 \nab\nnope\n")
    machine = FakeMachine(spec)
    result_reg = spec.syscall_abi.result
    machine.request(Syscall.READ_INT)
    handler.handle(machine)
    assert machine.regs[result_reg] == 12
    for expected in "ab\n":
        machine.request(Syscall.READ_CHAR)
        handler.handle(machine)
        assert machine.regs[result_reg] == ord(expected)
    machine.request(Syscall.READ_INT)
    handler.handle(machine)
    assert machine.regs[result_reg] == 0  # not a number
    machine.request(Syscall.READ_CHAR)
    handler.handle(machine)
    assert machine.regs[result_reg] == 0  # EOF


def test_read_int_uses_rest_of_a_partly_read_line():
    handler, io = _handler("x42\n")
    machine = FakeMachine(get_spec("riscv64"))
    machine.request(Syscall.READ_CHAR)
    handler.handle(machine)
    machine.request(Syscall.READ_INT)
    handler.handle(machine)
    assert machine.regs[10] == 42


def test_read_int_accepts_hex_and_negative():
    handler, io = _handler("0x10\n-3\n")
    machine = FakeMachine(get_spec("mips32"))
    for expected in (16, 0xFFFFFFFD):
        machine.request(Syscall.READ_INT)
        handler.handle(machine)
        assert machine.regs[2] == expected


@SPECS
def test_exits(spec):
    handler, io = _handler()
    machine = FakeMachine(spec)
    machine.request(Syscall.EXIT, 5)
    assert handler.handle(machine).exit_code == 0
    for number in (Syscall.EXIT2, Syscall.EXIT_CODE):
        machine.request(number, 300)
        result = handler.handle(machine)
        assert result.exited and result.exit_code == 300 & 0xFF
    machine.request(Syscall.EXIT2, -1)
    assert handler.handle(machine).exit_code == 255


@SPECS
def test_errors(spec):
    handler, io = _handler()
    machine = FakeMachine(spec)
    machine.request(-2)
    result = handler.handle(machine)
    assert not result.exited
    assert "Unknown syscall number -2" in result.error
    assert spec.registers.names[spec.syscall_abi.number] in result.error
    machine.request(Syscall.PRINT_STRING, 0x9999)
    assert "not mapped" in handler.handle(machine).error


def test_read_c_string_stops_at_end_of_memory():
    machine = FakeMachine(get_spec("riscv64"), b"abc", base=0x2000)
    assert read_c_string(machine, 0x2000) == "abc"
    assert read_c_string(machine, 0x2001) == "bc"
