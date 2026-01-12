#!/usr/bin/env python3
"""
MIPS backend tests for MapacheSPIM

Tests the MIPS support by directly testing the simulator internals
without requiring a MIPS ELF toolchain.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim.unicorn_backend import ISA, MIPSConfig, UnicornSimulator


class TestMIPSConfig(unittest.TestCase):
    """Test MIPS configuration"""

    def test_mips_config_exists(self):
        """Test that MIPSConfig class exists"""
        config = MIPSConfig()
        self.assertIsNotNone(config)

    def test_mips_register_names(self):
        """Test MIPS register names"""
        config = MIPSConfig()
        expected_names = [
            "zero", "at", "v0", "v1",  # $0-$3
            "a0", "a1", "a2", "a3",    # $4-$7
            "t0", "t1", "t2", "t3",    # $8-$11
            "t4", "t5", "t6", "t7",    # $12-$15
            "s0", "s1", "s2", "s3",    # $16-$19
            "s4", "s5", "s6", "s7",    # $20-$23
            "t8", "t9",                # $24-$25
            "k0", "k1",                # $26-$27
            "gp", "sp", "fp", "ra",    # $28-$31
        ]
        for i, expected in enumerate(expected_names):
            self.assertEqual(config.get_reg_name(i), expected)


class TestMIPSSimulator(unittest.TestCase):
    """Test MIPS simulator functionality"""

    def test_create_mips_simulator(self):
        """Test creating a MIPS simulator"""
        sim = UnicornSimulator(isa=ISA.MIPS)
        self.assertIsNotNone(sim)

    def test_mips_registers_count(self):
        """Test MIPS has 32 registers"""
        sim = UnicornSimulator(isa=ISA.MIPS)
        regs = sim.get_all_regs()
        self.assertEqual(len(regs), 32, "MIPS should have 32 GPRs")

    def test_mips_read_write_register(self):
        """Test reading and writing MIPS registers"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # Set $t0 (register 8) to a value
        test_val = 0x12345678
        sim.set_reg(8, test_val)
        result = sim.get_reg(8)
        self.assertEqual(result, test_val)

    def test_mips_zero_register_readonly(self):
        """Test that $zero ($0) always reads as 0"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # $zero should always be 0 - trying to write to it should raise an error
        # (same behavior as RISC-V x0)
        with self.assertRaises(ValueError):
            sim.set_reg(0, 0x12345678)

        # Reading $zero should return 0
        result = sim.get_reg(0)
        self.assertEqual(result, 0, "$zero register should always be 0")

    def test_mips_sp_register(self):
        """Test MIPS stack pointer register ($sp = $29)"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # Set $sp
        test_val = 0x7FFFFFF0
        sim.set_reg(29, test_val)
        result = sim.get_reg(29)
        self.assertEqual(result, test_val)

    def test_mips_register_bounds(self):
        """Test MIPS register bounds checking"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # Valid registers 0-31
        for i in range(32):
            val = sim.get_reg(i)
            self.assertIsInstance(val, int)


class TestMIPSMachineCode(unittest.TestCase):
    """Test executing MIPS machine code directly"""

    # MIPS user-space address (0x80000000 is kernel space)
    MIPS_CODE_ADDR = 0x00400000

    def test_execute_add(self):
        """Test MIPS ADD instruction"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # Set up registers for ADD $t2, $t0, $t1 (t0=5, t1=3)
        sim.set_reg(8, 5)   # $t0 = 5
        sim.set_reg(9, 3)   # $t1 = 3

        # ADD $t2, $t0, $t1: 000000 01000 01001 01010 00000 100000
        # = 0x01095020 (big-endian MIPS)
        add_instr = bytes([0x01, 0x09, 0x50, 0x20])

        # Write instruction and set PC
        sim.write_mem(self.MIPS_CODE_ADDR, add_instr)
        sim.set_pc(self.MIPS_CODE_ADDR)

        # Execute one step
        result = sim.step()

        # Check result
        self.assertEqual(sim.get_reg(10), 8, "$t2 should be 5+3=8")

    def test_execute_addi(self):
        """Test MIPS ADDI instruction"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # ADDI $t0, $zero, 42: 001000 00000 01000 0000000000101010
        # = 0x2008002A (big-endian MIPS)
        addi_instr = bytes([0x20, 0x08, 0x00, 0x2A])

        # Write instruction and set PC
        sim.write_mem(self.MIPS_CODE_ADDR, addi_instr)
        sim.set_pc(self.MIPS_CODE_ADDR)

        # Execute one step
        result = sim.step()

        # Check result
        self.assertEqual(sim.get_reg(8), 42, "$t0 should be 42")

    def test_execute_ori(self):
        """Test MIPS ORI instruction"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # ORI $t0, $zero, 0x1234: 001101 00000 01000 0001001000110100
        # = 0x34081234 (big-endian MIPS)
        ori_instr = bytes([0x34, 0x08, 0x12, 0x34])

        # Write instruction and set PC
        sim.write_mem(self.MIPS_CODE_ADDR, ori_instr)
        sim.set_pc(self.MIPS_CODE_ADDR)

        # Execute one step
        result = sim.step()

        # Check result
        self.assertEqual(sim.get_reg(8), 0x1234, "$t0 should be 0x1234")


class TestMIPSSyscall(unittest.TestCase):
    """Test MIPS syscall detection"""

    # MIPS user-space address
    MIPS_CODE_ADDR = 0x00400000

    def test_syscall_detection(self):
        """Test that syscall instruction is detected"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # SYSCALL: 000000 00000 00000 00000 00000 001100
        # = 0x0000000C (big-endian MIPS)
        syscall_instr = bytes([0x00, 0x00, 0x00, 0x0C])

        # Write instruction and set PC
        sim.write_mem(self.MIPS_CODE_ADDR, syscall_instr)
        sim.set_pc(self.MIPS_CODE_ADDR)

        # Set up syscall for exit (syscall 10)
        sim.set_reg(2, 10)  # $v0 = 10 (exit syscall)

        # Execute one step
        from mapachespim.unicorn_backend import StepResult

        result = sim.step()
        self.assertEqual(result, StepResult.SYSCALL, "Syscall should be detected")


class TestMIPSDisassembly(unittest.TestCase):
    """Test MIPS disassembly"""

    # MIPS user-space address
    MIPS_CODE_ADDR = 0x00400000

    def test_disasm_addi(self):
        """Test disassembly of ADDI instruction"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # ADDI $t0, $zero, 42
        addi_instr = bytes([0x20, 0x08, 0x00, 0x2A])

        sim.write_mem(self.MIPS_CODE_ADDR, addi_instr)

        disasm = sim.disasm(self.MIPS_CODE_ADDR)
        self.assertIn("addi", disasm.lower())

    def test_disasm_add(self):
        """Test disassembly of ADD instruction"""
        sim = UnicornSimulator(isa=ISA.MIPS)

        # ADD $t2, $t0, $t1
        add_instr = bytes([0x01, 0x09, 0x50, 0x20])

        sim.write_mem(self.MIPS_CODE_ADDR, add_instr)

        disasm = sim.disasm(self.MIPS_CODE_ADDR)
        self.assertIn("add", disasm.lower())


class TestMIPSISAEnum(unittest.TestCase):
    """Test MIPS ISA enum"""

    def test_mips_in_isa_enum(self):
        """Test that MIPS is in the ISA enum"""
        self.assertEqual(ISA.MIPS, 3)

    def test_isa_names(self):
        """Test ISA enum values"""
        sim = UnicornSimulator(isa=ISA.MIPS)
        self.assertEqual(sim.get_isa_name(), "MIPS")


class TestMIPSELFLoading(unittest.TestCase):
    """Test MIPS ELF file loading"""

    def test_mips_elf_loads_and_steps(self):
        """Test that MIPS ELF files load and PC advances when stepping

        This is a regression test for a Unicorn quirk where MIPS PC
        doesn't advance if emu_start end_address equals pc + 4.
        """
        from pathlib import Path
        from mapachespim import create_simulator

        mips_elf = Path("examples/mips/guess_game/guess_game")
        if not mips_elf.exists():
            self.skipTest(f"MIPS test binary not found: {mips_elf}")

        sim = create_simulator(str(mips_elf))
        self.assertEqual(sim.get_isa_name(), "MIPS")

        # PC must advance after stepping
        pc_before = sim.get_pc()
        sim.step()
        pc_after = sim.get_pc()

        self.assertNotEqual(pc_before, pc_after,
            f"MIPS PC should advance after step: was 0x{pc_before:x}, still 0x{pc_after:x}")
        self.assertEqual(pc_after, pc_before + 4,
            f"MIPS PC should advance by 4 bytes: expected 0x{pc_before+4:x}, got 0x{pc_after:x}")

    def test_mips_multiple_steps(self):
        """Test stepping through multiple MIPS instructions"""
        from pathlib import Path
        from mapachespim import create_simulator

        mips_elf = Path("examples/mips/guess_game/guess_game")
        if not mips_elf.exists():
            self.skipTest(f"MIPS test binary not found: {mips_elf}")

        sim = create_simulator(str(mips_elf))
        entry_pc = sim.get_pc()

        # Step 5 times
        for i in range(5):
            pc_before = sim.get_pc()
            result = sim.step()
            pc_after = sim.get_pc()

            # PC should advance (unless we hit a branch)
            self.assertNotEqual(pc_before, pc_after,
                f"Step {i+1}: PC should advance from 0x{pc_before:x}")


if __name__ == "__main__":
    unittest.main()
