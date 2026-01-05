#!/usr/bin/env python3
"""
Unit tests for MapacheSPIM simulator

Tests the Python API with multiple RISC-V programs and edge cases.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import SailSimulator, StepResult


class TestSimulatorBasic(unittest.TestCase):
    """Basic simulator initialization and lifecycle tests"""

    def test_init_no_config(self):
        """Test initialization with default config"""
        sim = SailSimulator()
        self.assertIsNotNone(sim)

    def test_init_with_context_manager(self):
        """Test context manager support"""
        with SailSimulator() as sim:
            self.assertIsNotNone(sim)
            pc = sim.get_pc()
            self.assertIsInstance(pc, int)

    def test_get_pc_after_init(self):
        """Test getting PC after initialization"""
        sim = SailSimulator()
        pc = sim.get_pc()
        self.assertIsInstance(pc, int)


class TestFibonacci(unittest.TestCase):
    """Tests using the fibonacci example"""

    def setUp(self):
        self.sim = SailSimulator()
        self.elf_path = "examples/riscv/fibonacci/fibonacci"

    def test_load_fibonacci(self):
        """Test loading fibonacci ELF file"""
        result = self.sim.load_elf(self.elf_path)
        self.assertTrue(result)

    def test_fibonacci_entry_point(self):
        """Test fibonacci has correct entry point"""
        self.sim.load_elf(self.elf_path)
        pc = self.sim.get_pc()
        self.assertEqual(pc, 0x80000000, "Entry point should be 0x80000000")

    def test_fibonacci_single_step(self):
        """Test single-stepping fibonacci"""
        self.sim.load_elf(self.elf_path)
        initial_pc = self.sim.get_pc()

        result = self.sim.step()
        self.assertEqual(result, StepResult.OK)

        new_pc = self.sim.get_pc()
        self.assertNotEqual(initial_pc, new_pc, "PC should change after step")
        self.assertEqual(new_pc, initial_pc + 4, "PC should advance by 4 bytes")

    def test_fibonacci_multiple_steps(self):
        """Test executing multiple steps"""
        self.sim.load_elf(self.elf_path)
        initial_pc = self.sim.get_pc()

        for i in range(10):
            result = self.sim.step()
            if result != StepResult.OK:
                break

        final_pc = self.sim.get_pc()
        self.assertNotEqual(initial_pc, final_pc, "PC should change after 10 steps")

    def test_fibonacci_run(self):
        """Test running fibonacci for N steps"""
        self.sim.load_elf(self.elf_path)
        steps_executed = self.sim.run(max_steps=100)
        self.assertGreater(steps_executed, 0, "Should execute at least some steps")
        self.assertLessEqual(steps_executed, 100, "Should not exceed max_steps")


class TestMatrixMultiply(unittest.TestCase):
    """Tests using the matrix_multiply example"""

    def setUp(self):
        self.sim = SailSimulator()
        self.elf_path = "examples/riscv/matrix_multiply/matrix_mult"

    def test_load_matrix(self):
        """Test loading matrix multiply ELF file"""
        result = self.sim.load_elf(self.elf_path)
        self.assertTrue(result)

    def test_matrix_entry_point(self):
        """Test matrix multiply has correct entry point"""
        self.sim.load_elf(self.elf_path)
        pc = self.sim.get_pc()
        self.assertEqual(pc, 0x80000000, "Entry point should be 0x80000000")

    def test_matrix_single_step(self):
        """Test single-stepping matrix multiply"""
        self.sim.load_elf(self.elf_path)
        initial_pc = self.sim.get_pc()

        result = self.sim.step()
        self.assertEqual(result, StepResult.OK)

        new_pc = self.sim.get_pc()
        self.assertNotEqual(initial_pc, new_pc, "PC should change after step")

    def test_matrix_run(self):
        """Test running matrix multiply"""
        self.sim.load_elf(self.elf_path)
        steps_executed = self.sim.run(max_steps=100)
        self.assertGreater(steps_executed, 0, "Should execute at least some steps")


class TestRegisterAccess(unittest.TestCase):
    """Tests for register read/write operations"""

    def setUp(self):
        self.sim = SailSimulator()
        self.sim.load_elf("examples/riscv/fibonacci/fibonacci")

    def test_get_all_registers(self):
        """Test getting all 32 registers"""
        regs = self.sim.get_all_regs()
        self.assertEqual(len(regs), 32, "Should return 32 registers")
        self.assertIsInstance(regs[0], int)

    def test_get_register_x0_always_zero(self):
        """Test that x0 is always 0"""
        self.assertEqual(self.sim.get_reg(0), 0, "x0 must always be 0")

    def test_get_valid_register(self):
        """Test reading valid register"""
        for i in range(32):
            val = self.sim.get_reg(i)
            self.assertIsInstance(val, int)
            self.assertGreaterEqual(val, 0)

    def test_get_register_invalid_low(self):
        """Test reading invalid register number (negative)"""
        with self.assertRaises(ValueError):
            self.sim.get_reg(-1)

    def test_get_register_invalid_high(self):
        """Test reading invalid register number (>31)"""
        with self.assertRaises(ValueError):
            self.sim.get_reg(32)

    def test_set_register(self):
        """Test setting a register value"""
        test_val = 0x1234567890ABCDEF
        self.sim.set_reg(10, test_val)
        result = self.sim.get_reg(10)
        self.assertEqual(result, test_val, "Register value should match what was set")

    def test_set_register_x0_fails(self):
        """Test that setting x0 raises an error"""
        with self.assertRaises(ValueError):
            self.sim.set_reg(0, 123)

    def test_set_register_overflow(self):
        """Test setting register with overflow (65-bit value)"""
        # Should mask to 64 bits
        big_val = 0x1FFFFFFFFFFFFFFFF  # 65 bits
        self.sim.set_reg(5, big_val)
        result = self.sim.get_reg(5)
        self.assertEqual(result, big_val & 0xFFFFFFFFFFFFFFFF)


class TestMemoryAccess(unittest.TestCase):
    """Tests for memory read/write operations"""

    def setUp(self):
        self.sim = SailSimulator()
        self.sim.load_elf("examples/riscv/fibonacci/fibonacci")

    def test_read_memory_at_pc(self):
        """Test reading memory at program counter"""
        pc = self.sim.get_pc()
        data = self.sim.read_mem(pc, 16)
        self.assertEqual(len(data), 16, "Should read 16 bytes")
        self.assertIsInstance(data, bytes)

    def test_read_memory_instruction(self):
        """Test that we can read the first instruction"""
        pc = self.sim.get_pc()
        data = self.sim.read_mem(pc, 4)
        self.assertEqual(len(data), 4, "Instruction should be 4 bytes")

    def test_write_and_read_memory(self):
        """Test writing then reading memory"""
        # Write to a safe location (high memory)
        addr = 0x83F00000
        test_data = b'\x01\x02\x03\x04\x05\x06\x07\x08'

        self.sim.write_mem(addr, test_data)
        result = self.sim.read_mem(addr, len(test_data))

        self.assertEqual(result, test_data, "Read should match what was written")

    def test_write_string_to_memory(self):
        """Test writing string (auto-converts to bytes)"""
        addr = 0x83F00000
        test_str = "Hello"

        self.sim.write_mem(addr, test_str)
        result = self.sim.read_mem(addr, len(test_str))

        self.assertEqual(result, test_str.encode('utf-8'))


class TestPCAccess(unittest.TestCase):
    """Tests for program counter operations"""

    def setUp(self):
        self.sim = SailSimulator()
        self.sim.load_elf("examples/riscv/fibonacci/fibonacci")

    def test_get_pc(self):
        """Test getting program counter"""
        pc = self.sim.get_pc()
        self.assertIsInstance(pc, int)
        self.assertEqual(pc, 0x80000000)

    def test_set_pc(self):
        """Test setting program counter"""
        new_pc = 0x80001000
        self.sim.set_pc(new_pc)
        result = self.sim.get_pc()
        self.assertEqual(result, new_pc)

    def test_pc_advances_on_step(self):
        """Test that PC advances after stepping"""
        initial = self.sim.get_pc()
        self.sim.step()
        new_pc = self.sim.get_pc()
        self.assertNotEqual(initial, new_pc, "PC should change after step")


class TestReset(unittest.TestCase):
    """Tests for simulator reset"""

    def setUp(self):
        self.sim = SailSimulator()
        self.sim.load_elf("examples/riscv/fibonacci/fibonacci")

    def test_reset_clears_state(self):
        """Test that reset clears simulator state"""
        # Execute some instructions
        self.sim.run(max_steps=10)
        modified_pc = self.sim.get_pc()

        # Reset
        self.sim.reset()
        reset_pc = self.sim.get_pc()

        # PC should be different after reset
        self.assertNotEqual(modified_pc, reset_pc)


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling"""

    def test_load_nonexistent_file(self):
        """Test loading a file that doesn't exist"""
        sim = SailSimulator()
        with self.assertRaises((FileNotFoundError, RuntimeError)):
            sim.load_elf("nonexistent.elf")

    def test_step_before_load(self):
        """Test stepping before loading a program"""
        sim = SailSimulator()
        # Should work but probably won't execute meaningful code
        result = sim.step()
        self.assertIsInstance(result, StepResult)

    def test_run_zero_steps(self):
        """Test running with max_steps=0 (unlimited)"""
        sim = SailSimulator()
        sim.load_elf("examples/riscv/fibonacci/fibonacci")
        # This would run forever, so we don't actually test it
        # Just verify the function signature accepts 0
        # steps = sim.run(max_steps=0)


def run_tests():
    """Run all tests and return results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSimulatorBasic))
    suite.addTests(loader.loadTestsFromTestCase(TestFibonacci))
    suite.addTests(loader.loadTestsFromTestCase(TestMatrixMultiply))
    suite.addTests(loader.loadTestsFromTestCase(TestRegisterAccess))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryAccess))
    suite.addTests(loader.loadTestsFromTestCase(TestPCAccess))
    suite.addTests(loader.loadTestsFromTestCase(TestReset))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
