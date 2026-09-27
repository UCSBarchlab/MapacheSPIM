"""
Re-export of :mod:`mapachespim.memory_map`.

The memory layout is shared by the assembler and the simulator, so it lives
at the package top level. This module is kept for backward compatibility.
"""

from ..memory_map import (
    ARM64_LAYOUT,
    MEMORY_LAYOUTS,
    MIPS32_LAYOUT,
    RISCV64_LAYOUT,
    X86_64_LAYOUT,
    MemoryLayout,
    get_layout,
)

__all__ = [
    "ARM64_LAYOUT",
    "MEMORY_LAYOUTS",
    "MIPS32_LAYOUT",
    "RISCV64_LAYOUT",
    "X86_64_LAYOUT",
    "MemoryLayout",
    "get_layout",
]
