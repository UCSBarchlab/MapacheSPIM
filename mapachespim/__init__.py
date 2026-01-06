"""
MapacheSPIM - Educational Multi-ISA Simulator using Unicorn Engine

A Python-based interactive simulator inspired by SPIM, supporting multiple ISAs
(RISC-V, ARM, x86-64) using the Unicorn CPU emulator framework.
"""

from .unicorn_backend import UnicornSimulator, StepResult, ISA, create_simulator, detect_elf_isa

# Primary public API - use this name in new code
Simulator = UnicornSimulator

# Deprecated aliases for backward compatibility
SailSimulator = UnicornSimulator  # Deprecated: use Simulator instead

__version__ = "0.2.0-unicorn"
__all__ = ["Simulator", "UnicornSimulator", "SailSimulator", "StepResult", "ISA", "create_simulator", "detect_elf_isa"]
