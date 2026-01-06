#!/usr/bin/env python3
"""
Simplified version to debug the crash
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import Simulator, ISA

def run_arm_program(elf_path, max_steps=1000):
    """Run an ARM program and show results"""
    print(f"Loading ARM program: {elf_path}")

    # Create ARM simulator directly (bypass detect_elf_isa)
    sim = Simulator(isa=ISA.ARM)
    print("DEBUG PYTHON: About to call load_elf")
    sim.load_elf(str(elf_path))
    print("DEBUG PYTHON: load_elf returned successfully")
    print("Simulator created and ELF loaded successfully")

    # Show initial state
    print(f"Entry PC: 0x{sim.get_pc():08x}")
    print()

    # Test: one executed step, one commented
    result1 = sim.step()
    print(f"Step 1: {result1.name}")

    result2 = sim.step()
    print(f"Step 2: {result2.name}")

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
        run_arm_program(elf_path)
        return 0
    except Exception as e:
        print(f"Error running program: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
