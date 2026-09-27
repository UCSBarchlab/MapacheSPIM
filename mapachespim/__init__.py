"""
MapacheSPIM - Educational Multi-ISA Simulator using Unicorn Engine

A Python-based interactive simulator inspired by SPIM, supporting multiple ISAs
(RISC-V, MIPS, ARM64, x86-64) using the Unicorn CPU emulator framework.
"""

from .isa import ISA, ISA_SPECS, ISASpec, get_spec
from .unicorn_backend import (
    RunResult,
    StepResult,
    StopReason,
    UnicornSimulator,
    create_simulator,
    detect_elf_isa,
)

# Primary public API - use this name in new code
Simulator = UnicornSimulator

__version__ = "0.2.0"
__all__ = [
    "Simulator",
    "UnicornSimulator",
    "StepResult",
    "StopReason",
    "RunResult",
    "ISA",
    "ISASpec",
    "ISA_SPECS",
    "get_spec",
    "create_simulator",
    "detect_elf_isa",
]
