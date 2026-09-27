"""
SPIM-compatible syscalls.

A program requests a service by putting a syscall number in its ISA's syscall
register and executing the syscall instruction (see
:class:`mapachespim.isa.SyscallABI`). The simulator stops at that instruction
and hands the request to :class:`SyscallHandler`, which works with any ISA:
it only reads and writes registers and memory through the small
:class:`Machine` interface.

To add a syscall, add its number to :class:`Syscall` and a handler method to
``SyscallHandler._handlers``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Dict, Optional, Protocol, TextIO

from .isa import ISASpec


class Machine(Protocol):
    """What a syscall needs from the simulator."""

    @property
    def spec(self) -> ISASpec: ...

    def get_reg(self, reg_num: int) -> int: ...

    def set_reg(self, reg_num: int, value: int) -> None: ...

    def read_mem(self, addr: int, length: int) -> bytes: ...


class Syscall(IntEnum):
    """Supported syscall numbers (SPIM's, plus Linux's exit on RISC-V)."""

    PRINT_INT = 1
    PRINT_STRING = 4
    READ_INT = 5
    EXIT = 10
    PRINT_CHAR = 11
    READ_CHAR = 12
    EXIT2 = 17
    EXIT_CODE = 93


@dataclass(frozen=True)
class SyscallResult:
    """Outcome of one syscall: the program continues unless it exited or failed."""

    exit_code: Optional[int] = None
    """Set if the program exited."""

    error: Optional[str] = None
    """Set if the syscall could not be performed."""

    @property
    def exited(self) -> bool:
        return self.exit_code is not None


CONTINUE = SyscallResult()


class ProgramIO:
    """The program's console: output from print syscalls and input for read syscalls.

    ``stdout`` and ``stdin`` default to the process streams (looked up at call
    time, so pytest's capsys and similar redirection work) and can be replaced,
    e.g. with StringIO objects for autograding.
    """

    stdout: Optional[TextIO]
    stdin: Optional[TextIO]

    def __init__(self) -> None:
        self.stdout = None
        self.stdin = None
        self.output_needs_newline = False
        """True if output so far did not end with a newline (consoles use this
        to keep their own messages off the program's output line)."""
        self._line_buffer = ""

    def clear_input(self) -> None:
        """Forget any partially consumed input line."""
        self._line_buffer = ""

    def write(self, text: str) -> None:
        if not text:
            return
        stream = self.stdout if self.stdout is not None else sys.stdout
        stream.write(text)
        stream.flush()
        self.output_needs_newline = not text.endswith("\n")

    def read_line(self) -> Optional[str]:
        """Read one line of input, without the newline (None on EOF)."""
        # Make sure any prompt the program printed is visible first
        (self.stdout if self.stdout is not None else sys.stdout).flush()
        # Pressing Enter echoes a newline, so the console is at a line start
        self.output_needs_newline = False
        if self.stdin is not None:
            line = self.stdin.readline()
            return None if line == "" else line.rstrip("\r\n")
        try:
            # input() gives line editing on interactive terminals
            return input()
        except EOFError:
            return None

    def read_int(self) -> int:
        """Read an integer from the next line (0 if it is not a number)."""
        # A partially consumed line (from read_char) is used first
        line = self._line_buffer if self._line_buffer.strip() else self.read_line()
        self._line_buffer = ""
        try:
            return int((line or "").strip(), 0)
        except ValueError:
            return 0

    def read_char(self) -> int:
        """Read one character (0 on EOF); "ab<Enter>" yields a, b, then newline."""
        if not self._line_buffer:
            line = self.read_line()
            self._line_buffer = "" if line is None else line + "\n"
        if not self._line_buffer:
            return 0
        char, self._line_buffer = self._line_buffer[0], self._line_buffer[1:]
        return ord(char) & 0xFF


def read_c_string(machine: Machine, addr: int, limit: int = 65536) -> str:
    """Read a NUL-terminated string from simulated memory."""
    data = bytearray()
    while len(data) < limit:
        # Read a chunk, shrinking near the end of a mapped region
        chunk = b""
        size = 256 - (addr % 256)
        while size > 0:
            try:
                chunk = machine.read_mem(addr, size)
                break
            except RuntimeError:
                size //= 2
        if not chunk:
            if not data:
                raise RuntimeError(f"print_string: address 0x{addr:x} is not mapped")
            break
        nul = chunk.find(0)
        if nul >= 0:
            data += chunk[:nul]
            break
        data += chunk
        addr += len(chunk)
    return data.decode("utf-8", errors="replace")


class SyscallHandler:
    """Performs syscalls for a :class:`Machine`, using a :class:`ProgramIO`."""

    def __init__(self, io: ProgramIO) -> None:
        self.io = io
        self._handlers: Dict[int, Callable[[Machine], SyscallResult]] = {
            Syscall.PRINT_INT: self._print_int,
            Syscall.PRINT_STRING: self._print_string,
            Syscall.READ_INT: self._read_int,
            Syscall.EXIT: self._exit,
            Syscall.PRINT_CHAR: self._print_char,
            Syscall.READ_CHAR: self._read_char,
            Syscall.EXIT2: self._exit_with_code,
            Syscall.EXIT_CODE: self._exit_with_code,
        }

    def handle(self, machine: Machine) -> SyscallResult:
        """Perform the syscall the machine's registers request."""
        abi = machine.spec.syscall_abi
        number = machine.get_reg(abi.number)
        handler = self._handlers.get(number)
        if handler is None:
            supported = ", ".join(str(int(n)) for n in Syscall)
            reg_name = machine.spec.registers.names[abi.number]
            return SyscallResult(
                error=f"Unknown syscall number {machine.spec.signed(number)} in {reg_name} "
                f"(supported: {supported})"
            )
        return handler(machine)

    @staticmethod
    def _arg0(machine: Machine) -> int:
        return machine.get_reg(machine.spec.syscall_abi.arg0)

    @staticmethod
    def _set_result(machine: Machine, value: int) -> None:
        machine.set_reg(machine.spec.syscall_abi.result, value & 0xFFFFFFFFFFFFFFFF)

    def _print_int(self, machine: Machine) -> SyscallResult:
        self.io.write(str(machine.spec.signed(self._arg0(machine))))
        return CONTINUE

    def _print_string(self, machine: Machine) -> SyscallResult:
        try:
            self.io.write(read_c_string(machine, self._arg0(machine)))
        except RuntimeError as e:
            return SyscallResult(error=str(e))
        return CONTINUE

    def _print_char(self, machine: Machine) -> SyscallResult:
        self.io.write(chr(self._arg0(machine) & 0xFF))
        return CONTINUE

    def _read_int(self, machine: Machine) -> SyscallResult:
        self._set_result(machine, self.io.read_int())
        return CONTINUE

    def _read_char(self, machine: Machine) -> SyscallResult:
        self._set_result(machine, self.io.read_char())
        return CONTINUE

    def _exit(self, machine: Machine) -> SyscallResult:
        return SyscallResult(exit_code=0)

    def _exit_with_code(self, machine: Machine) -> SyscallResult:
        return SyscallResult(exit_code=machine.spec.signed(self._arg0(machine)) & 0xFF)
