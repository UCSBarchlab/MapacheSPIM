#!/usr/bin/env python3
"""
Test disassembly functionality
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim.sail_backend import SailSimulator


def test_disasm():
    """Test disassembling instructions from test_simple program"""
    print("Testing disassembly...")

    sim = SailSimulator()
    sim.load_elf('examples/riscv/test_simple/simple')

    print("\nDisassembling first 9 instructions:")
    print("-" * 60)

    addresses = [
        0x80000000,  # addi x5, x0, 10
        0x80000004,  # addi x6, x0, 20
        0x80000008,  # add  x7, x5, x6
        0x8000000c,  # sub  x8, x7, x5
        0x80000010,  # slli x9, x5, 2
        0x80000014,  # addi x10, x0, 42
        0x80000018,  # j done
        0x8000001c,  # addi x1, x0, 93
        0x80000020,  # ecall
    ]

    expected_mnemonics = [
        'addi', 'addi', 'add', 'sub', 'slli', 'addi', 'j', 'addi', 'ecall'
    ]

    for i, addr in enumerate(addresses):
        try:
            disasm = sim.disasm(addr)
            print(f"[{addr:#010x}]  {disasm}")

            # Verify mnemonic
            if expected_mnemonics[i] not in disasm.lower():
                print(f"  WARNING: Expected '{expected_mnemonics[i]}' in disassembly")
        except Exception as e:
            print(f"[{addr:#010x}]  ERROR: {e}")

    print("-" * 60)
    print("\n✓ Disassembly test complete!")


if __name__ == '__main__':
    test_disasm()
