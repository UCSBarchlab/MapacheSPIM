#!/usr/bin/env python3
"""
MapacheSPIM Assembler CLI

Command-line interface for assembling source files to ELF executables.

Usage:
    mapachespim-as program.s -o program.elf --isa riscv64
    mapachespim-as program.s  # Auto-detect ISA, output to program.elf
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(args: list[str] | None = None) -> int:
    """Main entry point for mapachespim-as CLI."""
    parser = argparse.ArgumentParser(
        prog="mapachespim-as",
        description="Assemble source files to ELF executables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    mapachespim-as program.s -o program.elf --isa riscv64
    mapachespim-as hello.s --isa arm64
    mapachespim-as test.s  # Auto-detect ISA from source

Supported ISAs:
    riscv64  - RISC-V 64-bit
    arm64    - ARM AArch64
    x86_64   - Intel/AMD 64-bit
    mips32   - MIPS 32-bit (big-endian)
""",
    )

    parser.add_argument(
        "source",
        type=Path,
        help="Assembly source file (.s or .S)",
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output ELF file (default: source with .elf extension)",
    )

    parser.add_argument(
        "--isa",
        type=str,
        choices=["riscv64", "arm64", "x86_64", "mips32"],
        default=None,
        help="Target ISA (auto-detected if not specified)",
    )

    parser.add_argument(
        "--entry",
        type=str,
        default="_start",
        help="Entry point symbol (default: _start)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    parsed = parser.parse_args(args)

    # Import here to avoid slow startup
    from . import assemble_file

    source_path = parsed.source
    output_path = parsed.output

    # Default output path
    if output_path is None:
        output_path = source_path.with_suffix(".elf")

    # Check source exists
    if not source_path.exists():
        print(f"Error: Source file not found: {source_path}", file=sys.stderr)
        return 1

    if parsed.verbose:
        print(f"Assembling: {source_path}")
        if parsed.isa:
            print(f"Target ISA: {parsed.isa}")
        print(f"Output: {output_path}")

    # Assemble
    result = assemble_file(
        source_path,
        output_path=output_path,
        isa=parsed.isa,
        entry_symbol=parsed.entry,
    )

    # Report warnings
    for warning in result.warnings:
        print(f"Warning: {warning}", file=sys.stderr)

    # Check for errors
    if not result.success:
        for error in result.errors:
            print(f"Error: {error}", file=sys.stderr)
        return 1

    # Success
    if parsed.verbose or True:  # Always show success message
        isa_name = result.isa.upper() if result.isa else "Unknown"
        size = len(result.elf_bytes)
        symbols = len(result.symbols)
        print(f"Assembled: {output_path} ({isa_name}, {size} bytes, {symbols} symbols)")
        print(f"Entry point: 0x{result.entry_point:08x}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
