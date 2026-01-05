#!/usr/bin/env python3
"""
Test ARM instruction decoding
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import ISA, SailSimulator

def test_arm_decode():
    """Test ARM model with simple instruction"""
    print("=== ARM Decode Test ===\n")

    # Create ARM simulator
    sim = SailSimulator(isa=ISA.ARM)
    print(f"Initial PC: 0x{sim.get_pc():08x}")

    # Write a NOP instruction (0xd503201f) to memory at PC
    nop_instr = 0xd503201f
    pc = sim.get_pc()

    print(f"Writing NOP instruction (0x{nop_instr:08x}) to address 0x{pc:08x}")
    sim.write_mem(pc, nop_instr.to_bytes(4, byteorder='little'))

    # Read it back to verify
    mem_data = sim.read_mem(pc, 4)
    instr_read = int.from_bytes(mem_data, byteorder='little')
    print(f"Read back: 0x{instr_read:08x}")

    # Try to execute
    print("\nAttempting to execute NOP instruction...")
    try:
        result = sim.step()
        print(f"Step result: {result.name}")
        print(f"PC after step: 0x{sim.get_pc():08x}")
    except Exception as e:
        print(f"Error during step: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_arm_decode()
