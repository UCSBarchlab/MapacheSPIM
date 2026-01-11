"""
MapacheSPIM Toolchain - Pure Python assembler and ELF generator

This module provides a complete toolchain for assembling source files
to ELF executables, eliminating the need for external cross-compilers.

Supports: RISC-V 64-bit, ARM64, x86-64, MIPS32
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

from .assembler import Assembler
from .elf_builder import ELFBuilder
from .memory_map import MEMORY_LAYOUTS, MemoryLayout

__all__ = [
    "assemble",
    "assemble_file",
    "AssemblyResult",
    "Assembler",
    "ELFBuilder",
    "MemoryLayout",
    "MEMORY_LAYOUTS",
]


@dataclass
class AssemblyResult:
    """Result of an assembly operation."""

    elf_bytes: bytes
    """The assembled ELF file as bytes."""

    symbols: Dict[str, int] = field(default_factory=dict)
    """Map of symbol names to addresses."""

    errors: List[str] = field(default_factory=list)
    """List of error messages (empty if successful)."""

    warnings: List[str] = field(default_factory=list)
    """List of warning messages."""

    isa: str = ""
    """The ISA used for assembly."""

    entry_point: int = 0
    """Entry point address."""

    @property
    def success(self) -> bool:
        """Return True if assembly succeeded (no errors)."""
        return len(self.errors) == 0 and len(self.elf_bytes) > 0


def assemble(
    source: str,
    isa: str,
    entry_symbol: str = "_start",
) -> AssemblyResult:
    """
    Assemble source code into an ELF executable.

    Args:
        source: Assembly source code as a string.
        isa: Target ISA - one of "riscv64", "arm64", "x86_64", "mips32".
        entry_symbol: Entry point symbol name (default: "_start").

    Returns:
        AssemblyResult containing the ELF bytes, symbols, and any errors.

    Example:
        >>> result = assemble('''
        ... .text
        ... .globl _start
        ... _start:
        ...     addi x5, x0, 42
        ...     ecall
        ... ''', isa="riscv64")
        >>> if result.success:
        ...     with open("program.elf", "wb") as f:
        ...         f.write(result.elf_bytes)
    """
    try:
        assembler = Assembler(isa)
        return assembler.assemble(source, entry_symbol=entry_symbol)
    except Exception as e:
        return AssemblyResult(
            elf_bytes=b"",
            errors=[str(e)],
            isa=isa,
        )


def assemble_file(
    source_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    isa: Optional[str] = None,
    entry_symbol: str = "_start",
) -> AssemblyResult:
    """
    Assemble a source file into an ELF executable.

    Args:
        source_path: Path to the assembly source file.
        output_path: Path for the output ELF file. If None, uses source
                     path with .elf extension.
        isa: Target ISA. If None, looks for .isa directive in source.
        entry_symbol: Entry point symbol name (default: "_start").

    Returns:
        AssemblyResult containing the ELF bytes, symbols, and any errors.
        If output_path is provided, also writes the ELF to disk.

    Example:
        >>> result = assemble_file("program.s", "program.elf", isa="riscv64")
        >>> if result.success:
        ...     print(f"Assembled to {result.entry_point:#x}")
    """
    from .directives import DirectiveParser

    source_path = Path(source_path)

    if not source_path.exists():
        return AssemblyResult(
            elf_bytes=b"",
            errors=[f"Source file not found: {source_path}"],
        )

    # Read source file
    try:
        source = source_path.read_text()
    except Exception as e:
        return AssemblyResult(
            elf_bytes=b"",
            errors=[f"Failed to read source file: {e}"],
        )

    # If ISA not specified via flag, check for .isa directive in source
    if isa is None:
        isa = _detect_isa_from_directive(source)
        if isa is None:
            return AssemblyResult(
                elf_bytes=b"",
                errors=[_isa_not_specified_error()],
            )

    # Assemble
    result = assemble(source, isa=isa, entry_symbol=entry_symbol)

    # Write output if successful and path provided
    if result.success and output_path is not None:
        output_path = Path(output_path)
        try:
            output_path.write_bytes(result.elf_bytes)
        except Exception as e:
            result.errors.append(f"Failed to write output file: {e}")

    return result


def _detect_isa_from_directive(source: str) -> Optional[str]:
    """
    Look for .isa directive in source code.

    Returns the ISA if found, None otherwise.
    """
    from .directives import DirectiveParser

    # Quick scan for .isa directive without full parse
    for line in source.splitlines():
        line = line.strip()
        # Skip empty lines and comments
        if not line or line.startswith('#') or line.startswith('//') or line.startswith(';'):
            continue
        # Check for .isa directive
        if line.lower().startswith('.isa'):
            parts = line.split(None, 1)
            if len(parts) >= 2:
                isa_value = parts[1].strip().lower().replace("-", "_")
                if isa_value in DirectiveParser.VALID_ISAS:
                    return isa_value
        # Stop after first non-empty, non-comment, non-.isa line
        # (the .isa directive should be at the top of the file)
        if not line.startswith('.'):
            break

    return None


def _isa_not_specified_error() -> str:
    """Generate helpful error message when ISA is not specified."""
    return """ISA not specified

Please specify the target architecture using one of:

  1. Command-line flag:
     mapachespim-as program.s --isa riscv64

  2. File directive (add at start of file):
     .isa riscv64

Supported ISAs: arm64, mips32, riscv64, x86_64"""
