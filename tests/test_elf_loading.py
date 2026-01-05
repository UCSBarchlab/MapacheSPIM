#!/usr/bin/env python3
"""
Test ELF loading with ISA auto-detection
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from mapachespim import create_simulator, detect_elf_isa, ISA

def test_riscv_elf():
    """Test loading a RISC-V ELF file"""
    import pytest

    # Find a RISC-V test binary
    riscv_test = Path("backends/riscv/sail-riscv/build/test/2025-07-16/riscv-tests/rv64ui-v-or")

    if not riscv_test.exists():
        pytest.skip(f"Test binary not found: {riscv_test}")

    # Detect ISA
    isa = detect_elf_isa(str(riscv_test))
    assert isa == ISA.RISCV, f"Expected RISC-V, got {isa.name}"

    # Create simulator with auto-detection
    sim = create_simulator(str(riscv_test))
    assert sim.get_pc() != 0, "Entry PC should not be zero"

    # Try to execute a few instructions
    for i in range(10):
        sim.step()

def main():
    print("MapacheSPIM ELF Loading Test\n")
    print("=" * 50)
    print()

    riscv_ok = test_riscv_elf()

    print("=" * 50)
    print("\nTest Summary:")
    print(f"  RISC-V ELF Loading: {'✓ PASS' if riscv_ok else '✗ FAIL'}")

    return 0 if riscv_ok else 1

if __name__ == "__main__":
    sys.exit(main())
