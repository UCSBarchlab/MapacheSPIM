#!/usr/bin/env python3
"""
Test ELF loading with ISA auto-detection
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import create_simulator, detect_elf_isa, ISA


def test_riscv_elf_detection():
    """Test ISA detection for RISC-V ELF file"""
    riscv_elf = Path("examples/riscv/fibonacci/fibonacci")
    assert riscv_elf.exists(), f"Test file not found: {riscv_elf}"

    isa = detect_elf_isa(str(riscv_elf))
    assert isa == ISA.RISCV, f"Expected RISC-V, got {isa.name}"


def test_arm_elf_detection():
    """Test ISA detection for ARM ELF file"""
    arm_elf = Path("examples/arm/fibonacci/fibonacci")
    assert arm_elf.exists(), f"Test file not found: {arm_elf}"

    isa = detect_elf_isa(str(arm_elf))
    assert isa == ISA.ARM, f"Expected ARM, got {isa.name}"


def test_create_simulator_riscv():
    """Test create_simulator with RISC-V ELF"""
    riscv_elf = "examples/riscv/fibonacci/fibonacci"
    sim = create_simulator(riscv_elf)

    # Verify simulator was created and ELF loaded
    pc = sim.get_pc()
    assert pc != 0, "Entry PC should not be zero"

    # Execute a few instructions to verify it works
    for _ in range(5):
        sim.step()


def test_create_simulator_arm():
    """Test create_simulator with ARM ELF"""
    arm_elf = "examples/arm/fibonacci/fibonacci"
    sim = create_simulator(arm_elf)

    # Verify simulator was created and ELF loaded
    pc = sim.get_pc()
    assert pc != 0, "Entry PC should not be zero"

    # Execute a few instructions to verify it works
    for _ in range(5):
        sim.step()


def test_mips_elf_detection():
    """Test ISA detection for MIPS ELF file"""
    mips_elf = Path("examples/mips/guess_game/guess_game")
    assert mips_elf.exists(), f"Test file not found: {mips_elf}"

    isa = detect_elf_isa(str(mips_elf))
    assert isa == ISA.MIPS, f"Expected MIPS, got {isa.name}"


def test_create_simulator_mips():
    """Test create_simulator with MIPS ELF"""
    mips_elf = "examples/mips/guess_game/guess_game"
    sim = create_simulator(mips_elf)

    # Verify simulator was created and ELF loaded
    pc = sim.get_pc()
    assert pc != 0, "Entry PC should not be zero"

    # Verify it's a MIPS simulator
    assert sim.get_isa_name() == "MIPS", "Should be MIPS simulator"

    # Execute a few instructions to verify it works
    for _ in range(5):
        sim.step()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
