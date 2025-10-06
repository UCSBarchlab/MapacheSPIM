#!/usr/bin/env python3
"""
Basic test to verify simple program execution
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachesail.sail_backend import SailSimulator, StepResult


def test_basic_execution():
    """Test basic execution of simple program"""
    print("Initializing simulator...")
    sim = SailSimulator()

    print("Loading simple program...")
    sim.load_elf('examples/test_simple/simple')

    pc = sim.get_pc()
    print(f"Entry point: {pc:#x}")
    assert pc == 0x80000000, f"Expected PC=0x80000000, got {pc:#x}"

    # Step through first 3 instructions
    print("\nStep 1: addi x5, x0, 10")
    result = sim.step()
    pc = sim.get_pc()
    regs = sim.get_all_regs()
    print(f"  PC = {pc:#x}, x5 = {regs[5]}")
    assert pc == 0x80000004, f"Expected PC=0x80000004, got {pc:#x}"
    assert regs[5] == 10, f"Expected x5=10, got {regs[5]}"

    print("\nStep 2: addi x6, x0, 20")
    result = sim.step()
    pc = sim.get_pc()
    regs = sim.get_all_regs()
    print(f"  PC = {pc:#x}, x6 = {regs[6]}")
    assert pc == 0x80000008, f"Expected PC=0x80000008, got {pc:#x}"
    assert regs[6] == 20, f"Expected x6=20, got {regs[6]}"

    print("\nStep 3: add x7, x5, x6")
    result = sim.step()
    pc = sim.get_pc()
    regs = sim.get_all_regs()
    print(f"  PC = {pc:#x}, x7 = {regs[7]}")
    assert pc == 0x8000000c, f"Expected PC=0x8000000c, got {pc:#x}"
    assert regs[7] == 30, f"Expected x7=30, got {regs[7]}"

    print("\n✓ Basic execution test passed!")

    # Now test running to completion with a limit
    print("\nResetting and running with step limit...")
    sim.reset()
    sim.load_elf('examples/test_simple/simple')

    steps = 0
    max_steps = 100  # Safety limit
    while steps < max_steps:
        result = sim.step()
        steps += 1

        if result == StepResult.HALT:
            print(f"Program halted after {steps} steps")
            break
        elif result == StepResult.ERROR:
            print(f"Error at step {steps}")
            break

    if steps >= max_steps:
        print(f"WARNING: Hit max step limit ({max_steps})")

    # Check final register state
    regs = sim.get_all_regs()
    print(f"\nFinal state after {steps} steps:")
    print(f"  x1 (ra) = {regs[1]:#x}")
    print(f"  x5 (t0) = {regs[5]:#x}")
    print(f"  x6 (t1) = {regs[6]:#x}")
    print(f"  x7 (t2) = {regs[7]:#x}")
    print(f"  x8 (s0) = {regs[8]:#x}")
    print(f"  x9 (s1) = {regs[9]:#x}")
    print(f"  x10 (a0) = {regs[10]:#x}")

    print("\n✓ All tests passed!")


if __name__ == '__main__':
    test_basic_execution()
