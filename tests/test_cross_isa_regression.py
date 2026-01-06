#!/usr/bin/env python3
"""
Cross-ISA regression tests for MapacheSPIM

Tests that verify consistent behavior across different ISAs.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import Simulator, ISA


class TestCrossISASimplePrograms(unittest.TestCase):
    """Test that simple programs behave consistently across ISAs"""

    RISCV_SIMPLE = 'examples/riscv/test_simple/simple'
    ARM_SIMPLE = 'examples/arm/test_simple/simple'

    @classmethod
    def setUpClass(cls):
        """Check that both examples exist"""
        cls.riscv_exists = Path(cls.RISCV_SIMPLE).exists()
        cls.arm_exists = Path(cls.ARM_SIMPLE).exists()
        if not (cls.riscv_exists or cls.arm_exists):
            raise unittest.SkipTest("No ISA examples found")

    def test_both_isas_detected_correctly(self):
        """Test ISA detection works for both RISC-V and ARM"""
        if self.riscv_exists:
            sim = Simulator()
            sim.load_elf(self.RISCV_SIMPLE)
            self.assertEqual(sim.get_isa(), ISA.RISCV)
            self.assertEqual(sim.get_isa_name(), "RISCV")

        if self.arm_exists:
            sim = Simulator()
            sim.load_elf(self.ARM_SIMPLE)
            self.assertEqual(sim.get_isa(), ISA.ARM)
            self.assertEqual(sim.get_isa_name(), "ARM")

    def test_both_isas_complete_simple_program(self):
        """Test both ISAs can run simple programs to completion"""
        results = {}

        if self.riscv_exists:
            sim = Simulator()
            sim.load_elf(self.RISCV_SIMPLE)
            steps = sim.run(max_steps=100)
            results['RISCV'] = steps
            self.assertLess(steps, 100, "RISC-V should complete")

        if self.arm_exists:
            sim = Simulator()
            sim.load_elf(self.ARM_SIMPLE)
            steps = sim.run(max_steps=100)
            results['ARM'] = steps
            self.assertLess(steps, 100, "ARM should complete")

        # Both should complete in a reasonable number of steps
        for isa, steps in results.items():
            self.assertGreater(steps, 0, f"{isa} should execute steps")

    def test_register_count_consistency(self):
        """Test both RISC-V and ARM have 32 registers"""
        if self.riscv_exists:
            sim = Simulator()
            sim.load_elf(self.RISCV_SIMPLE)
            self.assertEqual(sim.get_register_count(), 32)
            self.assertEqual(len(sim.get_all_regs()), 32)

        if self.arm_exists:
            sim = Simulator()
            sim.load_elf(self.ARM_SIMPLE)
            self.assertEqual(sim.get_register_count(), 32)
            self.assertEqual(len(sim.get_all_regs()), 32)


class TestISAAPIConsistency(unittest.TestCase):
    """Test that the ISA API behaves consistently across architectures"""

    RISCV_SIMPLE = 'examples/riscv/test_simple/simple'
    ARM_SIMPLE = 'examples/arm/test_simple/simple'

    @classmethod
    def setUpClass(cls):
        cls.riscv_exists = Path(cls.RISCV_SIMPLE).exists()
        cls.arm_exists = Path(cls.ARM_SIMPLE).exists()
        if not (cls.riscv_exists or cls.arm_exists):
            raise unittest.SkipTest("No ISA examples found")

    def _test_isa_api(self, path, expected_isa, expected_name, expected_reg_count):
        """Helper to test ISA API for a given binary"""
        sim = Simulator()
        sim.load_elf(path)

        # Test get_isa()
        self.assertEqual(sim.get_isa(), expected_isa)

        # Test get_isa_name()
        self.assertEqual(sim.get_isa_name(), expected_name)

        # Test get_register_count()
        self.assertEqual(sim.get_register_count(), expected_reg_count)

        # Test get_reg_name() returns something for all registers
        for i in range(expected_reg_count):
            name = sim.get_reg_name(i)
            self.assertIsInstance(name, str)
            self.assertGreater(len(name), 0)

        # Test get_all_regs() returns correct count
        regs = sim.get_all_regs()
        self.assertEqual(len(regs), expected_reg_count)

    def test_riscv_api(self):
        """Test ISA API works correctly for RISC-V"""
        if not self.riscv_exists:
            self.skipTest("RISC-V example not found")
        self._test_isa_api(self.RISCV_SIMPLE, ISA.RISCV, "RISCV", 32)

    def test_arm_api(self):
        """Test ISA API works correctly for ARM"""
        if not self.arm_exists:
            self.skipTest("ARM example not found")
        self._test_isa_api(self.ARM_SIMPLE, ISA.ARM, "ARM", 32)


class TestCrossISAExecution(unittest.TestCase):
    """Test execution behavior across ISAs"""

    RISCV_SIMPLE = 'examples/riscv/test_simple/simple'
    ARM_SIMPLE = 'examples/arm/test_simple/simple'

    @classmethod
    def setUpClass(cls):
        cls.riscv_exists = Path(cls.RISCV_SIMPLE).exists()
        cls.arm_exists = Path(cls.ARM_SIMPLE).exists()
        if not (cls.riscv_exists or cls.arm_exists):
            raise unittest.SkipTest("No ISA examples found")

    def test_step_advances_pc(self):
        """Test that stepping advances PC on all ISAs"""
        if self.riscv_exists:
            sim = Simulator()
            sim.load_elf(self.RISCV_SIMPLE)
            pc_before = sim.get_pc()
            sim.step()
            pc_after = sim.get_pc()
            self.assertGreater(pc_after, pc_before, "RISC-V PC should advance")

        if self.arm_exists:
            sim = Simulator()
            sim.load_elf(self.ARM_SIMPLE)
            pc_before = sim.get_pc()
            sim.step()
            pc_after = sim.get_pc()
            self.assertGreater(pc_after, pc_before, "ARM PC should advance")

    def test_reset_restores_state(self):
        """Test that reset works consistently across ISAs"""
        if self.riscv_exists:
            sim = Simulator()
            sim.load_elf(self.RISCV_SIMPLE)
            initial_pc = sim.get_pc()
            sim.step()
            sim.step()
            sim.reset()
            reset_pc = sim.get_pc()
            self.assertEqual(reset_pc, initial_pc, "RISC-V reset should restore PC")

        if self.arm_exists:
            sim = Simulator()
            sim.load_elf(self.ARM_SIMPLE)
            initial_pc = sim.get_pc()
            sim.step()
            sim.step()
            sim.reset()
            reset_pc = sim.get_pc()
            self.assertEqual(reset_pc, initial_pc, "ARM reset should restore PC")


def run_tests():
    """Run all cross-ISA tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestCrossISASimplePrograms))
    suite.addTests(loader.loadTestsFromTestCase(TestISAAPIConsistency))
    suite.addTests(loader.loadTestsFromTestCase(TestCrossISAExecution))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
