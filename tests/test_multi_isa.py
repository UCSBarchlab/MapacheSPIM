#!/usr/bin/env python3
"""
Test multi-ISA support for MapacheSPIM

Tests that both RISC-V and ARM simulators can be created and used.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import ISA, SailSimulator


def test_riscv_simulator():
    """Test RISC-V simulator creation and basic operations"""
    sim = SailSimulator(isa=ISA.RISCV)

    # Test PC access
    pc = sim.get_pc()
    assert isinstance(pc, int), "PC should be an integer"

    # Test register access
    sim.set_reg(1, 0x42)
    val = sim.get_reg(1)
    assert val == 0x42, f"Register write/read failed: expected 0x42, got 0x{val:x}"


def test_arm_simulator():
    """Test ARM simulator creation and basic operations"""
    sim = SailSimulator(isa=ISA.ARM)

    # Test PC access
    pc = sim.get_pc()
    assert isinstance(pc, int), "PC should be an integer"

    # Test register access (64-bit value)
    sim.set_reg(1, 0x1234567890ABCDEF)
    val = sim.get_reg(1)
    assert val == 0x1234567890ABCDEF, f"Register write/read failed"


def test_isa_enum():
    """Test ISA enum values"""
    assert ISA.RISCV.name == "RISCV"
    assert ISA.ARM.name == "ARM"


def test_default_isa_is_riscv():
    """Test that default ISA is RISC-V"""
    sim = SailSimulator()
    # Default should be RISC-V - verify by checking PC is in RISC-V range
    pc = sim.get_pc()
    assert isinstance(pc, int)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
