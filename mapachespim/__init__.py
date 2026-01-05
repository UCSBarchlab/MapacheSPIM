"""
MapacheSPIM - Educational Multi-ISA Simulator using Unicorn Engine

A Python-based interactive simulator inspired by SPIM, supporting multiple ISAs
(RISC-V, ARM, x86, etc.) using the Unicorn CPU emulator framework.
"""

from .unicorn_backend import UnicornSimulator, StepResult, ISA, create_simulator, detect_elf_isa

# Alias for backward compatibility
SailSimulator = UnicornSimulator

__version__ = "0.2.0-unicorn"
__all__ = ["UnicornSimulator", "SailSimulator", "StepResult", "ISA", "create_simulator", "detect_elf_isa"]
