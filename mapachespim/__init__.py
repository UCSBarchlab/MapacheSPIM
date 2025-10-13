"""
MapacheSPIM - Educational Multi-ISA Simulator using Sail formal specifications

A Python-based interactive simulator inspired by SPIM, supporting both RISC-V
and ARM (AArch64) using the official Sail formal specifications as ISA backends.
"""

from .sail_backend import SailSimulator, StepResult, ISA, create_simulator, detect_elf_isa

__version__ = "0.1.0"
__all__ = ["SailSimulator", "StepResult", "ISA", "create_simulator", "detect_elf_isa"]
