"""
The ISA registry: everything MapacheSPIM knows about each instruction set.

Each supported ISA is described once, by an :class:`ISASpec`, and every
other part of the package (simulator, disassembler, ELF loader and writer,
assembler, console, and command-line tools) reads its ISA-specific facts
from here instead of branching on the ISA itself.

This module is pure Python with no emulator dependencies, so the assembler
can use it without loading Unicorn or Capstone. The Unicorn and Capstone
constants for each ISA live in :mod:`mapachespim.engines`, and each ISA's
instruction encoder is registered in :mod:`mapachespim.toolchain.targets`.

Adding an ISA means adding an :class:`ISA` member and an :class:`ISASpec`
here, an engine binding, and an assembler target; see
``docs/dev/adding-an-isa.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Dict, Literal, Optional, Tuple, Union

from .memory_map import ARM64_LAYOUT, MIPS32_LAYOUT, RISCV64_LAYOUT, X86_64_LAYOUT, MemoryLayout


class ISA(IntEnum):
    """ISA types supported by the simulator"""

    RISCV = 0
    ARM = 1
    X86_64 = 2
    MIPS = 3
    UNKNOWN = -1


@dataclass(frozen=True)
class RegisterFile:
    """The general-purpose registers, numbered as the simulator API uses them."""

    names: Tuple[str, ...]
    """Conventional (ABI) name of each register, indexed by number."""

    zero_register: Optional[int] = None
    """Number of the hardwired-zero register, which cannot be written."""

    number_prefix: Optional[str] = None
    """Prefix for numbered display, e.g. "x" shows "x5 (t0)"; None shows only the name."""

    @property
    def count(self) -> int:
        return len(self.names)

    def is_writable(self, n: int) -> bool:
        return 0 <= n < self.count and n != self.zero_register


@dataclass(frozen=True)
class SyscallABI:
    """Registers used by the SPIM-style syscall interface (register numbers)."""

    number: int
    """Register holding the syscall number."""

    arg0: int
    """Register holding the first argument."""

    result: int
    """Register that receives the result."""


@dataclass(frozen=True)
class InstructionPattern:
    """A fixed instruction encoding: matches when ``word & mask == value``.

    ``word`` is the first ``size`` bytes at the instruction address, read in
    the ISA's byte order.
    """

    size: int
    mask: int
    value: int

    def matches(self, word: int) -> bool:
        return word & self.mask == self.value


@dataclass(frozen=True)
class AsmDialect:
    """How GNU as behaves for this ISA, where it differs between ISAs."""

    word_size: int = 4
    """Bytes emitted by ``.word`` (x86 uses 2, like ``.value``)."""

    align_in_bytes: bool = False
    """``.align N`` means N bytes (x86) rather than 2**N bytes."""

    auto_align_data: bool = False
    """``.half``/``.word``/``.dword`` are aligned to their size (MIPS)."""

    hash_comments_only_at_line_start: bool = False
    """'#' starts a comment only at the start of a line (ARM64, where '#' marks immediates)."""


def _no_trap(word: int) -> Optional[str]:
    return None


@dataclass(frozen=True)
class ISASpec:
    """Everything ISA-specific that is not tied to a particular emulator or encoder."""

    isa: ISA
    name: str
    """Canonical name, as used by ``--isa`` and ``.isa`` (e.g. "riscv64")."""

    display_name: str
    """Human-readable name (e.g. "RISC-V 64-bit")."""

    aliases: Tuple[str, ...]
    """Other accepted names (e.g. "riscv")."""

    examples_dir: str
    """Directory of the bundled examples for this ISA (e.g. "riscv")."""

    layout: MemoryLayout
    registers: RegisterFile
    syscall_abi: SyscallABI

    syscall_instruction: InstructionPattern
    """The instruction that performs a syscall (ecall, syscall, svc)."""

    min_instruction_size: int
    max_instruction_size: int

    elf_machine: int
    """ELF e_machine value."""

    elf_machine_name: str
    """pyelftools' name for ``elf_machine`` (e.g. "EM_RISCV")."""

    elf_flags: int = 0
    """ELF e_flags written by the assembler."""

    asm: AsmDialect = field(default_factory=AsmDialect)

    sign_extends_32bit_addresses: bool = False
    """Addresses built from 32-bit immediates are sign-extended to 64 bits (RV64's
    lui), so the simulator mirrors [0x80000000, 2**32) at 0xFFFFFFFF80000000."""

    describe_trap: Callable[[int], Optional[str]] = _no_trap
    """Explain the trap raised by the instruction word, or None if it is not a trap."""

    @property
    def word_bits(self) -> int:
        """Width of a general-purpose register."""
        return 64 if self.layout.is_64bit else 32

    @property
    def byteorder(self) -> Literal["little", "big"]:
        return "little" if self.layout.is_little_endian else "big"

    @property
    def fixed_width(self) -> bool:
        """True if every instruction has the same size."""
        return self.min_instruction_size == self.max_instruction_size

    def signed(self, value: int) -> int:
        """Interpret a register value as a signed integer of the register width."""
        bits = self.word_bits
        value &= (1 << bits) - 1
        return value - (1 << bits) if value & (1 << (bits - 1)) else value


# --- Trap descriptions (for runtime-check instructions that stop the program) ---


def _mips_trap(word: int) -> Optional[str]:
    """MIPS div/rem expand to code that runs 'break 7' on division by zero and
    'break 6' on overflow, as SPIM and GNU as do."""
    if word & 0xFC00003F != 0x0000000D:  # break
        return None
    code = (word >> 16) & 0x3FF
    if code == 7:
        return "Division by zero"
    if code == 6:
        return "Integer overflow in division (-2147483648 / -1)"
    return f"Break instruction executed (break {code})"


def _riscv_trap(word: int) -> Optional[str]:
    return "ebreak instruction executed" if word == 0x00100073 else None


def _arm64_trap(word: int) -> Optional[str]:
    if word & 0xFFE0001F == 0xD4200000:  # brk #imm
        return f"brk instruction executed (brk #{(word >> 5) & 0xFFFF})"
    return None


# --- The registry ---

_RISCV_REGISTERS = (
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
)  # fmt: skip

_MIPS_REGISTERS = (
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
)  # fmt: skip

_X86_64_REGISTERS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)  # fmt: skip

RISCV64 = ISASpec(
    isa=ISA.RISCV,
    name="riscv64",
    display_name="RISC-V 64-bit",
    aliases=("riscv",),
    examples_dir="riscv",
    layout=RISCV64_LAYOUT,
    registers=RegisterFile(
        names=_RISCV_REGISTERS,
        zero_register=0,
        number_prefix="x",
    ),
    syscall_abi=SyscallABI(number=17, arg0=10, result=10),  # a7, a0, a0
    syscall_instruction=InstructionPattern(4, 0xFFFFFFFF, 0x00000073),  # ecall
    min_instruction_size=4,
    max_instruction_size=4,
    elf_machine=243,
    elf_machine_name="EM_RISCV",
    describe_trap=_riscv_trap,
    sign_extends_32bit_addresses=True,
)

MIPS32 = ISASpec(
    isa=ISA.MIPS,
    name="mips32",
    display_name="MIPS32",
    aliases=("mips",),
    examples_dir="mips",
    layout=MIPS32_LAYOUT,
    registers=RegisterFile(
        names=_MIPS_REGISTERS,
        zero_register=0,
    ),
    syscall_abi=SyscallABI(number=2, arg0=4, result=2),  # $v0, $a0, $v0
    syscall_instruction=InstructionPattern(4, 0xFFFFFFFF, 0x0000000C),  # syscall
    min_instruction_size=4,
    max_instruction_size=4,
    elf_machine=8,
    elf_machine_name="EM_MIPS",
    elf_flags=0x50001000,  # MIPS32R2, O32 ABI
    asm=AsmDialect(auto_align_data=True),
    describe_trap=_mips_trap,
)

ARM64 = ISASpec(
    isa=ISA.ARM,
    name="arm64",
    display_name="ARM64",
    aliases=("aarch64",),
    examples_dir="arm",
    layout=ARM64_LAYOUT,
    # Register 31 is the stack pointer (in the encoding it is sp or xzr
    # depending on the instruction; the simulator API exposes sp).
    registers=RegisterFile(
        names=tuple(f"x{n}" for n in range(31)) + ("sp",),
        number_prefix="x",
    ),
    syscall_abi=SyscallABI(number=8, arg0=0, result=0),  # x8, x0, x0
    syscall_instruction=InstructionPattern(4, 0xFFE0001F, 0xD4000001),  # svc #imm
    min_instruction_size=4,
    max_instruction_size=4,
    elf_machine=183,
    elf_machine_name="EM_AARCH64",
    asm=AsmDialect(hash_comments_only_at_line_start=True),
    describe_trap=_arm64_trap,
)

X86_64 = ISASpec(
    isa=ISA.X86_64,
    name="x86_64",
    display_name="x86-64",
    aliases=("x64",),
    examples_dir="x86_64",
    layout=X86_64_LAYOUT,
    registers=RegisterFile(
        names=_X86_64_REGISTERS,
    ),
    syscall_abi=SyscallABI(number=0, arg0=7, result=0),  # rax, rdi, rax
    syscall_instruction=InstructionPattern(2, 0xFFFF, 0x050F),  # syscall (0f 05)
    min_instruction_size=1,
    max_instruction_size=15,
    elf_machine=62,
    elf_machine_name="EM_X86_64",
    asm=AsmDialect(word_size=2, align_in_bytes=True),
)

# In the order ISAs are listed to users
ISA_SPECS: Tuple[ISASpec, ...] = (RISCV64, MIPS32, ARM64, X86_64)

_BY_ISA: Dict[ISA, ISASpec] = {spec.isa: spec for spec in ISA_SPECS}
_BY_NAME: Dict[str, ISASpec] = {}
for _spec in ISA_SPECS:
    for _name in (_spec.name, *_spec.aliases):
        _BY_NAME[_name] = _spec


def _normalize(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def isa_names() -> Tuple[str, ...]:
    """Canonical names of all supported ISAs (e.g. for ``--isa`` choices)."""
    return tuple(spec.name for spec in ISA_SPECS)


def find_spec(isa: Union[str, ISA, ISASpec]) -> Optional[ISASpec]:
    """The spec for an ISA enum member, canonical name, or alias; None if unknown."""
    if isinstance(isa, ISASpec):
        return isa
    if isinstance(isa, ISA):
        return _BY_ISA.get(isa)
    return _BY_NAME.get(_normalize(isa))


def get_spec(isa: Union[str, ISA, ISASpec]) -> ISASpec:
    """Like :func:`find_spec`, but raises ValueError for an unknown ISA."""
    spec = find_spec(isa)
    if spec is None:
        raise ValueError(f"Unknown ISA: {isa!r}. Valid options: {', '.join(isa_names())}")
    return spec


def canonical_isa(name: str) -> str:
    """The canonical name for an ISA or one of its aliases (e.g. mips -> mips32).

    Unknown names are returned normalized but otherwise unchanged.
    """
    spec = find_spec(name)
    return spec.name if spec is not None else _normalize(name)


def spec_for_elf(machine_name: str, is_64bit: bool) -> Optional[ISASpec]:
    """The spec matching an ELF header's machine and class, or None."""
    for spec in ISA_SPECS:
        if spec.elf_machine_name == machine_name and spec.layout.is_64bit == is_64bit:
            return spec
    return None
