#!/usr/bin/env python3
"""
Test running simple program to completion
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachesail.sail_backend import SailSimulator, StepResult


def test_run_to_completion():
    """Test running program to completion"""
    print("Initializing simulator...")
    sim = SailSimulator()

    print("Loading simple program...")
    sim.load_elf('examples/test_simple/simple')

    pc = sim.get_pc()
    print(f"Entry point: {pc:#x}")

    # Run program step by step
    steps = 0
    max_steps = 20  # Program should complete in 9 steps

    print("\nExecuting program:")
    while steps < max_steps:
        pc = sim.get_pc()
        result = sim.step()
        steps += 1

        print(f"Step {steps}: PC was {pc:#x}, result = {result}")

        if result == StepResult.HALT:
            print(f"\n✓ Program halted after {steps} steps")
            break
        elif result == StepResult.ERROR:
            print(f"\n✗ Error at step {steps}")
            break
        elif result == StepResult.OK:
            continue
        else:
            print(f"\n? Unknown result: {result}")
            break

    if steps >= max_steps:
        print(f"\n✗ Hit max step limit ({max_steps}) without halting")
        pc = sim.get_pc()
        print(f"Final PC: {pc:#x}")

    # Check final register state
    regs = sim.get_all_regs()
    print(f"\nFinal register state:")
    print(f"  x1 (ra) = {regs[1]:3d} (0x{regs[1]:02x}) - expected 93 (0x5d)")
    print(f"  x5 (t0) = {regs[5]:3d} (0x{regs[5]:02x}) - expected 10 (0x0a)")
    print(f"  x6 (t1) = {regs[6]:3d} (0x{regs[6]:02x}) - expected 20 (0x14)")
    print(f"  x7 (t2) = {regs[7]:3d} (0x{regs[7]:02x}) - expected 30 (0x1e)")
    print(f"  x8 (s0) = {regs[8]:3d} (0x{regs[8]:02x}) - expected 20 (0x14)")
    print(f"  x9 (s1) = {regs[9]:3d} (0x{regs[9]:02x}) - expected 40 (0x28)")
    print(f"  x10 (a0) = {regs[10]:3d} (0x{regs[10]:02x}) - expected 42 (0x2a)")

    # Validate
    if steps < max_steps and result == StepResult.HALT:
        assert regs[1] == 93, f"Expected ra=93, got {regs[1]}"
        assert regs[5] == 10, f"Expected t0=10, got {regs[5]}"
        assert regs[6] == 20, f"Expected t1=20, got {regs[6]}"
        assert regs[7] == 30, f"Expected t2=30, got {regs[7]}"
        assert regs[8] == 20, f"Expected s0=20, got {regs[8]}"
        assert regs[9] == 40, f"Expected s1=40, got {regs[9]}"
        assert regs[10] == 42, f"Expected a0=42, got {regs[10]}"
        print("\n✓ All register values match expected!")


if __name__ == '__main__':
    test_run_to_completion()
