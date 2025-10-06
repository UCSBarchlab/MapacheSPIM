"""
MapacheSail - Educational RISC-V Simulator using Sail formal specification

A Python-based interactive simulator similar to SPIM, but using the official
Sail RISC-V formal specification as the ISA backend.
"""

from .sail_backend import SailSimulator

__version__ = "0.1.0"
__all__ = ["SailSimulator"]
