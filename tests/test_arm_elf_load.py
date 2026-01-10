#!/usr/bin/env python3
"""
Test ARM ELF loading
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import create_simulator

def test_arm_elf():
    """Test loading and examining an ARM ELF"""
    elf_path = "examples/arm/fibonacci/fibonacci"

    print("=== ARM ELF Load Test ===\n")
    print(f"Loading: {elf_path}")

    # Create simulator and load ELF
    sim = create_simulator(elf_path)
    pc = sim.get_pc()
    print(f"PC after load: 0x{pc:08x}")

    # Read the instruction at PC
    instr_bytes = sim.read_mem(pc, 4)
    instr = int.from_bytes(instr_bytes, byteorder='little')
    print(f"Instruction at PC: 0x{instr:08x}")

    # Check if it matches expected first instruction (mov x5, #10 = 0xd2800145)
    expected = 0xd2800145
    if instr == expected:
        print(f"✓ Matches expected first instruction")
    else:
        print(f"✗ Expected 0x{expected:08x}, got 0x{instr:08x}")

    # Try to step
    print("\nAttempting to execute...")
    try:
        x5_before = sim.get_reg(5)
        print(f"X5 before: 0x{x5_before:016x}")

        result = sim.step()
        print(f"Step result: {result.name}")

        x5_after = sim.get_reg(5)
        pc_after = sim.get_pc()
        print(f"X5 after:  0x{x5_after:016x}")
        print(f"PC after:  0x{pc_after:08x}")

        if x5_after == 10:
            print("✓ X5 correctly set to 10")
        else:
            print(f"✗ X5 should be 10, got {x5_after}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_arm_elf()
