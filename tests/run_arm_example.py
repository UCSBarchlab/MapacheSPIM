#!/usr/bin/env python3
"""
Run ARM assembly examples with MapacheSPIM
"""

import sys
print("DEBUG: Starting script", file=sys.stderr)
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
print("DEBUG: About to import mapachespim", file=sys.stderr)

from mapachespim import create_simulator, ISA
print("DEBUG: Import successful", file=sys.stderr)

def run_arm_program(elf_path, max_steps=1000):
    """Run an ARM program and show results"""
    print(f"DEBUG: run_arm_program called with {elf_path}", file=sys.stderr)
    print(f"Loading ARM program: {elf_path}")

    # Create simulator with auto-detection
    print(f"DEBUG: About to call create_simulator", file=sys.stderr)
    sim = create_simulator(str(elf_path))
    print("Simulator created and ELF loaded successfully")

    # Show initial state
    print(f"Entry PC: 0x{sim.get_pc():08x}")
    print()

    # Execute instructions
    step = 0
    while step < max_steps:
        try:
            pc = sim.get_pc()

            # Read instruction at PC for debugging
            if step < 5:
                instr_bytes = sim.read_mem(pc, 4)
                instr = int.from_bytes(instr_bytes, byteorder='little')
                print(f"Step {step:3d}: PC=0x{pc:08x}  instr=0x{instr:08x}", end="")

            result = sim.step()

            if step < 20:  # Show first 20 steps
                # Show key register values (x0-x8)
                x0 = sim.get_reg(0)
                x5 = sim.get_reg(5)
                x6 = sim.get_reg(6)
                x7 = sim.get_reg(7)
                x8 = sim.get_reg(8)
                print(f"  X0={x0:016x}  X5={x5:016x}  X6={x6:016x}  X7={x7:016x}  X8={x8:016x}")

            if result.name != "OK":
                print(f"\nProgram finished after {step+1} steps: {result.name}")
                break

        except Exception as e:
            print(f"\n\nError at step {step}: {e}")
            print(f"PC was: 0x{pc:08x}")
            import traceback
            traceback.print_exc()
            return False

        step += 1
    else:
        print(f"\nReached maximum steps ({max_steps})")

    # Show final register state
    print("\nFinal Register State:")
    print("-" * 60)
    for i in range(0, 31, 4):
        regs = []
        for j in range(4):
            if i + j < 31:
                reg_name = f"X{i+j}"
                val = sim.get_reg(i + j)
                regs.append(f"{reg_name:3s}=0x{val:016x}")
        print("  ".join(regs))

    # Show PC
    print()
    print(f"PC =0x{sim.get_pc():016x}")

    return True

def main():
    print("DEBUG: In main()", file=sys.stderr)
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf_file>")
        return 1

    print(f"DEBUG: argv[1] = {sys.argv[1]}", file=sys.stderr)
    elf_path = Path(sys.argv[1])
    if not elf_path.exists():
        print(f"Error: File not found: {elf_path}")
        return 1

    print(f"DEBUG: About to call run_arm_program", file=sys.stderr)
    try:
        run_arm_program(elf_path)
        return 0
    except Exception as e:
        print(f"Error running program: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    print("DEBUG: __name__ == __main__", file=sys.stderr)
    sys.exit(main())
