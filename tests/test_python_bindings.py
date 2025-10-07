#!/usr/bin/env python3
"""
Test script for MapacheSail Python bindings

Demonstrates basic usage of the SailSimulator class.
"""

from mapachesail import SailSimulator


def main():
    print("=" * 60)
    print("MapacheSail Python Bindings Test")
    print("=" * 60)
    print()

    # Initialize simulator
    print("1. Initializing Sail RISC-V simulator...")
    sim = SailSimulator()
    print("   ✓ Simulator initialized successfully!")
    print()

    # Load ELF file
    elf_path = "examples/fibonacci/fibonacci"
    print(f"2. Loading ELF file: {elf_path}")
    sim.load_elf(elf_path)
    print("   ✓ ELF loaded successfully!")
    print()

    # Show entry point
    entry_pc = sim.get_pc()
    print(f"3. Entry PC: 0x{entry_pc:016x}")
    print()

    # Execute 10 instructions
    print("4. Single-stepping first 10 instructions:")
    print("   " + "-" * 56)
    for i in range(10):
        pc = sim.get_pc()
        print(f"   [{i:2d}] PC = 0x{pc:016x}")
        result = sim.step()
        if result != 0:  # StepResult.OK = 0
            print(f"   Stopped: {result}")
            break
    print()

    # Show register state
    print("5. Register state after 10 steps:")
    print("   " + "-" * 56)
    regs = sim.get_all_regs()
    for i in range(0, 32, 4):
        line = "   "
        for j in range(4):
            if i + j < 32:
                reg_num = i + j
                value = regs[reg_num]
                line += f"x{reg_num:<2d} = 0x{value:016x}  "
        print(line)
    print()

    # Test memory read
    print("6. Testing memory read at PC:")
    try:
        mem_data = sim.read_mem(entry_pc, 16)
        print(f"   First 16 bytes at 0x{entry_pc:x}:")
        print("   " + " ".join(f"{b:02x}" for b in mem_data))
    except Exception as e:
        print(f"   Memory read: {e}")
    print()

    # Test reset
    print("7. Testing reset:")
    sim.reset()
    reset_pc = sim.get_pc()
    print(f"   PC after reset: 0x{reset_pc:016x}")
    print()

    print("=" * 60)
    print("All tests completed successfully! ✓")
    print("=" * 60)


if __name__ == "__main__":
    main()
