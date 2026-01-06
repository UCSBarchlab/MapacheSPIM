#!/usr/bin/env python3
"""
ARM64 program correctness tests for MapacheSPIM

Tests that ARM64 example programs execute correctly and produce expected results.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import Simulator, ISA


class TestARMSimpleCorrectness(unittest.TestCase):
    """Test ARM64 test_simple program executes correctly"""

    SIMPLE_PATH = 'examples/arm/test_simple/simple'

    @classmethod
    def setUpClass(cls):
        """Check if ARM simple example exists"""
        if not Path(cls.SIMPLE_PATH).exists():
            raise unittest.SkipTest(f"ARM simple example not found: {cls.SIMPLE_PATH}")

    def test_arm_simple_loads(self):
        """Test ARM simple program loads correctly"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)
        self.assertEqual(sim.get_isa(), ISA.ARM)

    def test_arm_simple_entry_point(self):
        """Test ARM simple has correct entry point"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)
        pc = sim.get_pc()
        # Entry point should be non-zero and in a reasonable range
        self.assertGreater(pc, 0)
        self.assertLess(pc, 0xFFFFFFFF)

    def test_arm_simple_executes(self):
        """Test ARM simple program executes some instructions"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)

        initial_pc = sim.get_pc()
        sim.step()
        new_pc = sim.get_pc()

        # PC should advance (ARM64 instructions are 4 bytes)
        self.assertEqual(new_pc, initial_pc + 4)

    def test_arm_simple_completes(self):
        """Test ARM simple program runs to completion"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)

        steps = sim.run(max_steps=100)
        # Should complete in reasonable number of steps
        self.assertLess(steps, 100, "Program should complete within 100 steps")
        self.assertGreater(steps, 0, "Program should execute at least one step")


class TestARMRegisterAccess(unittest.TestCase):
    """Test ARM64 register access"""

    SIMPLE_PATH = 'examples/arm/test_simple/simple'

    @classmethod
    def setUpClass(cls):
        if not Path(cls.SIMPLE_PATH).exists():
            raise unittest.SkipTest(f"ARM simple example not found: {cls.SIMPLE_PATH}")

    def test_arm_has_32_registers(self):
        """Test ARM64 has 32 general-purpose registers"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)

        regs = sim.get_all_regs()
        self.assertEqual(len(regs), 32)

    def test_arm_register_names(self):
        """Test ARM64 register names are correct"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)

        # Check ARM64 register names
        self.assertEqual(sim.get_reg_name(0), "x0")
        self.assertEqual(sim.get_reg_name(29), "x29")  # Frame pointer (x29)
        self.assertEqual(sim.get_reg_name(30), "x30")  # Link register (x30)
        self.assertEqual(sim.get_reg_name(31), "sp")   # Stack pointer


class TestARMISADetection(unittest.TestCase):
    """Test ARM64 ISA detection"""

    SIMPLE_PATH = 'examples/arm/test_simple/simple'

    @classmethod
    def setUpClass(cls):
        if not Path(cls.SIMPLE_PATH).exists():
            raise unittest.SkipTest(f"ARM simple example not found: {cls.SIMPLE_PATH}")

    def test_arm_isa_detection(self):
        """Test ISA is correctly detected as ARM"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)

        self.assertEqual(sim.get_isa(), ISA.ARM)
        self.assertEqual(sim.get_isa_name(), "ARM")

    def test_arm_register_count(self):
        """Test ARM has correct register count"""
        sim = Simulator()
        sim.load_elf(self.SIMPLE_PATH)

        self.assertEqual(sim.get_register_count(), 32)


def run_tests():
    """Run all ARM64 correctness tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestARMSimpleCorrectness))
    suite.addTests(loader.loadTestsFromTestCase(TestARMRegisterAccess))
    suite.addTests(loader.loadTestsFromTestCase(TestARMISADetection))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
