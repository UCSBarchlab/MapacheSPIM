#!/usr/bin/env python3
"""Test matching run_arm_example structure"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import create_simulator, ISA

def run_program(elf_path):
    print(f"Loading: {elf_path}")
    sim = create_simulator(str(elf_path))
    print(f"PC: 0x{sim.get_pc():08x}")
    return True

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf_file>")
        return 1

    elf_path = Path(sys.argv[1])
    if not elf_path.exists():
        print(f"Error: File not found: {elf_path}")
        return 1

    try:
        run_program(elf_path)
        return 0
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
