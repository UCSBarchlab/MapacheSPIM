#!/usr/bin/env python3
"""
Test script for multi-ISA Python bindings
Tests both RISC-V and ARM simulator creation
"""

import sys
from pathlib import Path

# Add mapachespim to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import ISA, SailSimulator, detect_elf_isa

def test_isa_detection():
    """Test ISA detection without loading a file"""
    print("=== Testing ISA Detection ===\n")

    # Test with RISC-V binaries
    riscv_dir = Path("backends/riscv/sail-riscv/test/riscv-tests")
    if riscv_dir.exists():
        riscv_tests = list(riscv_dir.glob("rv64ui-p-*"))
        if riscv_tests:
            test_file = riscv_tests[0]
            print(f"Detecting ISA from: {test_file.name}")
            isa = detect_elf_isa(str(test_file))
            print(f"Detected ISA: {isa.name}")
            assert isa == ISA.RISCV, f"Expected RISC-V, got {isa.name}"
            print("✓ RISC-V detection works\n")

def test_riscv_simulator():
    """Test RISC-V simulator creation"""
    # Create RISC-V simulator explicitly
    sim = SailSimulator(isa=ISA.RISCV)

    # Test basic operations
    pc = sim.get_pc()
    assert isinstance(pc, int), "PC should be an integer"

    # Test register access
    sim.set_reg(1, 0x42)
    val = sim.get_reg(1)
    assert val == 0x42, f"Register write/read failed: expected 0x42, got 0x{val:x}"

def test_arm_simulator():
    """Test ARM simulator creation"""
    # Create ARM simulator explicitly
    sim = SailSimulator(isa=ISA.ARM)

    # Test basic operations
    pc = sim.get_pc()
    assert isinstance(pc, int), "PC should be an integer"

    # Test register access
    sim.set_reg(1, 0x1234567890ABCDEF)
    val = sim.get_reg(1)
    assert val == 0x1234567890ABCDEF, f"Register write/read failed"

def main():
    print("MapacheSPIM Multi-ISA Python Bindings Test\n")
    print("=" * 50)
    print()

    # Test ISA detection
    try:
        test_isa_detection()
    except Exception as e:
        print(f"ISA detection test error: {e}\n")

    # Test RISC-V
    riscv_ok = test_riscv_simulator()

    # Test ARM
    arm_ok = test_arm_simulator()

    # Summary
    print("=" * 50)
    print("\nTest Summary:")
    print(f"  RISC-V: {'✓ PASS' if riscv_ok else '✗ FAIL'}")
    print(f"  ARM:    {'✓ PASS' if arm_ok else '✗ FAIL'}")

    if riscv_ok and arm_ok:
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
