"""
ISA-specific memory layouts for MapacheSPIM.

Each ISA has different conventional memory layouts for bare-metal programs.
The assembler places sections at these addresses and the simulator uses the
same values for its default memory map and initial stack pointer. Each
layout is attached to its ISA in :mod:`mapachespim.isa`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MemoryLayout:
    """Memory layout configuration for an ISA."""

    text_base: int
    """Base address for .text (code) section."""

    data_base: int
    """Base address for .data section."""

    rodata_base: int
    """Base address for .rodata section."""

    bss_base: int
    """Base address for .bss section."""

    stack_top: int
    """Address just above the stack region (stack grows down).

    The simulator maps ``[stack_top - stack_size, stack_top)`` and starts the
    stack pointer at ``stack_top - 8``."""

    stack_size: int
    """Size of stack region."""

    is_64bit: bool
    """True for 64-bit ISA, False for 32-bit."""

    is_little_endian: bool
    """True for little-endian, False for big-endian."""

    def __str__(self) -> str:
        bits = "64-bit" if self.is_64bit else "32-bit"
        endian = "little-endian" if self.is_little_endian else "big-endian"
        return f"MemoryLayout({bits}, {endian}, text=0x{self.text_base:x})"


# ISA-specific memory layouts
# These match the linker.ld files in examples/*/

RISCV64_LAYOUT = MemoryLayout(
    text_base=0x80000000,  # Traditional RISC-V bare-metal
    data_base=0x80100000,
    rodata_base=0x80080000,
    bss_base=0x80180000,
    stack_top=0x83F00000,
    stack_size=0x100000,  # 1MB stack
    is_64bit=True,
    is_little_endian=True,
)

ARM64_LAYOUT = MemoryLayout(
    text_base=0x10000000,  # Unicorn default for ARM64
    data_base=0x10100000,
    rodata_base=0x10080000,
    bss_base=0x10180000,
    stack_top=0x13F00000,
    stack_size=0x100000,  # 1MB stack
    is_64bit=True,
    is_little_endian=True,
)

X86_64_LAYOUT = MemoryLayout(
    text_base=0x400000,  # Linux-like layout
    data_base=0x500000,
    rodata_base=0x480000,
    bss_base=0x580000,
    stack_top=0x7FFFFFFFE000,  # Near top of user space
    stack_size=0x100000,  # 1MB stack
    is_64bit=True,
    is_little_endian=True,
)

MIPS32_LAYOUT = MemoryLayout(
    text_base=0x00400000,  # Traditional MIPS user space
    data_base=0x10000000,
    rodata_base=0x00480000,
    bss_base=0x10080000,
    stack_top=0x80000000,  # Just below kernel space (kseg0)
    stack_size=0x100000,  # 1MB stack
    is_64bit=False,
    is_little_endian=False,  # MIPS is big-endian in MapacheSPIM
)


def get_layout(isa: str) -> MemoryLayout:
    """
    Get the memory layout for an ISA.

    Args:
        isa: ISA name or alias (e.g., "riscv64", "arm64", "x86_64", "mips32")

    Returns:
        MemoryLayout for the specified ISA.

    Raises:
        ValueError: If ISA is not recognized.
    """
    from .isa import get_spec  # the registry imports this module

    return get_spec(isa).layout
