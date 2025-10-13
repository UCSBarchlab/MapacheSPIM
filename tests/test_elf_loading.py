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
    print("=== Testing RISC-V ELF Loading ===\n")

    # Find a RISC-V test binary
    riscv_test = Path("backends/riscv/sail-riscv/build/test/2025-07-16/riscv-tests/rv64ui-v-or")

    if not riscv_test.exists():
        print(f"✗ Test binary not found: {riscv_test}")
        return False

    try:
        # Detect ISA
        print(f"Testing file: {riscv_test.name}")
        isa = detect_elf_isa(str(riscv_test))
        print(f"Detected ISA: {isa.name}")
        assert isa == ISA.RISCV, f"Expected RISC-V, got {isa.name}"

        # Create simulator with auto-detection
        print("Creating simulator with auto-detection...")
        sim = create_simulator(str(riscv_test))

        print(f"✓ Simulator created and ELF loaded")
        print(f"  Entry PC: 0x{sim.get_pc():x}")

        # Try to execute a few instructions
        print("Executing first 10 instructions...")
        for i in range(10):
            pc = sim.get_pc()
            result = sim.step()
            print(f"  [{i}] PC=0x{pc:08x} -> result={result.name}")

        print("✓ RISC-V ELF test passed\n")
        return True

    except Exception as e:
        print(f"✗ RISC-V ELF test failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False

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
