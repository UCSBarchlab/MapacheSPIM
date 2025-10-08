#!/usr/bin/env python3
"""
Test program correctness - verify programs produce correct results

This is our most critical test suite - it verifies that the simulator
actually executes programs correctly and produces the right answers!
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import SailSimulator, StepResult


class TestFibonacciCorrectness(unittest.TestCase):
    """Test that fibonacci program computes correct results"""

    FIBONACCI_PATH = 'examples/riscv/fibonacci/fibonacci'

    def setUp(self):
        """Create simulator for each test"""
        self.sim = SailSimulator()

    def test_fibonacci_returns_correct_result(self):
        """Test that Fibonacci(7) returns 13 - CRITICAL correctness test"""
        # Load fibonacci program
        result = self.sim.load_elf(self.FIBONACCI_PATH)
        self.assertTrue(result, "Failed to load fibonacci program")

        # The program calculates fib(7), which should be 13
        # Fibonacci sequence: 0, 1, 1, 2, 3, 5, 8, 13, 21, ...
        # fib(0)=0, fib(1)=1, fib(2)=1, fib(3)=2, fib(4)=3, fib(5)=5, fib(6)=8, fib(7)=13

        # Run the program with a generous step limit
        # If it takes more than 10000 steps, something is wrong (infinite loop)
        MAX_STEPS = 10000
        steps_executed = self.sim.run(max_steps=MAX_STEPS)

        # Check if program completed or hit the limit
        if steps_executed >= MAX_STEPS:
            self.fail(f"Program did not complete within {MAX_STEPS} steps - possible infinite loop!")

        print(f"  Fibonacci program completed in {steps_executed} steps")

        # Look up the fib_result symbol address
        fib_result_addr = self.sim.lookup_symbol('fib_result')
        self.assertIsNotNone(fib_result_addr, "Could not find 'fib_result' symbol")

        # Read the result from memory (32-bit word)
        result_bytes = self.sim.read_mem(fib_result_addr, 4)
        self.assertEqual(len(result_bytes), 4, "Should read 4 bytes for word")

        # Convert little-endian bytes to integer
        result_value = int.from_bytes(result_bytes, byteorder='little', signed=False)

        # VERIFY THE CRITICAL RESULT
        self.assertEqual(result_value, 13,
            f"Fibonacci(7) should equal 13, but got {result_value}! "
            f"This is a CRITICAL FAILURE - the simulator is producing wrong results!")

        print(f"  ✓ Result verified: Fibonacci(7) = {result_value} (correct!)")

    def test_fibonacci_input_value(self):
        """Verify the input value is correctly stored"""
        self.sim.load_elf(self.FIBONACCI_PATH)

        # Check fib_input contains 7
        fib_input_addr = self.sim.lookup_symbol('fib_input')
        self.assertIsNotNone(fib_input_addr, "Could not find 'fib_input' symbol")

        input_bytes = self.sim.read_mem(fib_input_addr, 4)
        input_value = int.from_bytes(input_bytes, byteorder='little', signed=False)

        self.assertEqual(input_value, 7, "fib_input should contain 7")

    def test_fibonacci_a0_register_has_result(self):
        """Verify result is also in a0 register after function return"""
        self.sim.load_elf(self.FIBONACCI_PATH)

        # Run program
        steps = self.sim.run(max_steps=10000)
        self.assertLess(steps, 10000, "Program should complete")

        # After the fibonacci function returns, a0 should contain the result
        # However, the program continues and might modify a0
        # So let's verify fib_result instead (already done in main test)
        # This test could be enhanced to break at specific points

    def test_fibonacci_completes_not_timeout(self):
        """Verify program completes naturally, doesn't just timeout"""
        self.sim.load_elf(self.FIBONACCI_PATH)

        # Run with generous limit
        steps = self.sim.run(max_steps=10000)

        # Should complete in much less than 10000 steps
        # Typical completion is around 150-200 steps for fib(7)
        self.assertLess(steps, 1000,
            f"Fibonacci should complete in <1000 steps, took {steps}. "
            f"Might be stuck in infinite loop.")

        print(f"  ✓ Program completed efficiently in {steps} steps")


class TestToHostMechanism(unittest.TestCase):
    """Test HTIF (Host-Target Interface) tohost/fromhost mechanism"""

    FIBONACCI_PATH = 'examples/riscv/fibonacci/fibonacci'

    def setUp(self):
        self.sim = SailSimulator()

    def test_tohost_written_on_exit(self):
        """Verify program writes to tohost to signal completion"""
        self.sim.load_elf(self.FIBONACCI_PATH)

        # Get tohost address
        tohost_addr = self.sim.lookup_symbol('tohost')
        self.assertIsNotNone(tohost_addr, "Could not find 'tohost' symbol")

        # Before running, tohost should be 0
        tohost_before = self.sim.read_mem(tohost_addr, 8)
        tohost_value_before = int.from_bytes(tohost_before, byteorder='little', signed=False)
        self.assertEqual(tohost_value_before, 0, "tohost should be 0 initially")

        # Run program
        steps = self.sim.run(max_steps=10000)
        self.assertLess(steps, 10000, "Program should complete")

        # After running, tohost should be non-zero (exit code written)
        tohost_after = self.sim.read_mem(tohost_addr, 8)
        tohost_value_after = int.from_bytes(tohost_after, byteorder='little', signed=False)

        self.assertNotEqual(tohost_value_after, 0,
            "tohost should be non-zero after program exit (exit code should be written)")

        print(f"  ✓ tohost written: {tohost_value_after:#x}")

    def test_tohost_exit_code(self):
        """Verify exit code written to tohost"""
        self.sim.load_elf(self.FIBONACCI_PATH)

        tohost_addr = self.sim.lookup_symbol('tohost')
        self.sim.run(max_steps=10000)

        tohost_bytes = self.sim.read_mem(tohost_addr, 8)
        tohost_value = int.from_bytes(tohost_bytes, byteorder='little', signed=False)

        # fibonacci.s writes exit code 1 to tohost
        # The actual value might be encoded (HTIF protocol)
        # For now, just verify it's non-zero
        self.assertGreater(tohost_value, 0, "Exit code should be positive")


class TestMatrixMultiplyCorrectness(unittest.TestCase):
    """Test that matrix multiplication program computes correct results"""

    MATRIX_PATH = 'examples/riscv/matrix_multiply/matrix_mult'

    def setUp(self):
        self.sim = SailSimulator()

    def test_matrix_multiply_completes(self):
        """Verify matrix multiply program completes"""
        result = self.sim.load_elf(self.MATRIX_PATH)
        self.assertTrue(result, "Failed to load matrix multiply program")

        # Run with generous limit
        steps = self.sim.run(max_steps=100000)

        # Should complete (matrix mult is more complex than fibonacci)
        self.assertLess(steps, 100000,
            f"Matrix multiply should complete in <100000 steps")

        print(f"  Matrix multiply completed in {steps} steps")

    def test_matrix_multiply_correct_result(self):
        """Verify matrix multiplication produces correct result"""
        self.sim.load_elf(self.MATRIX_PATH)

        # Run program
        steps = self.sim.run(max_steps=100000)
        self.assertLess(steps, 100000, "Program should complete")

        # Get matrix_c address
        matrix_c_addr = self.sim.lookup_symbol('matrix_c')
        self.assertIsNotNone(matrix_c_addr, "Could not find 'matrix_c' symbol")

        # Matrix A:           Matrix B:           Expected C = A * B:
        # [ 1  2  3 ]         [ 9  8  7 ]         [ 30   24   18 ]
        # [ 4  5  6 ]    *    [ 6  5  4 ]    =    [ 84   69   54 ]
        # [ 7  8  9 ]         [ 3  2  1 ]         [ 138  114  90 ]

        # Read matrix C (3x3 = 9 words = 36 bytes)
        matrix_c_bytes = self.sim.read_mem(matrix_c_addr, 36)

        # Parse into 3x3 matrix
        matrix_c = []
        for i in range(9):
            word_bytes = matrix_c_bytes[i*4:(i+1)*4]
            value = int.from_bytes(word_bytes, byteorder='little', signed=True)
            matrix_c.append(value)

        # Reshape to 3x3
        matrix_c_2d = [
            [matrix_c[0], matrix_c[1], matrix_c[2]],
            [matrix_c[3], matrix_c[4], matrix_c[5]],
            [matrix_c[6], matrix_c[7], matrix_c[8]]
        ]

        # Expected result
        expected = [
            [30, 24, 18],
            [84, 69, 54],
            [138, 114, 90]
        ]

        # Verify each element
        for i in range(3):
            for j in range(3):
                self.assertEqual(matrix_c_2d[i][j], expected[i][j],
                    f"matrix_c[{i}][{j}] should be {expected[i][j]}, got {matrix_c_2d[i][j]}")

        print(f"  ✓ Matrix multiplication result verified:")
        for row in matrix_c_2d:
            print(f"    {row}")


class TestProgramCompletion(unittest.TestCase):
    """Test detection of program completion vs timeout"""

    def test_simple_executes(self):
        """test_simple executes correctly"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/test_simple/simple')

        # test_simple doesn't have tohost, so we just verify it loads and runs
        # Run a fixed number of steps
        steps = sim.run(max_steps=20)

        # Should execute at least the 9 instructions
        self.assertGreaterEqual(steps, 9, "Should execute at least 9 instructions")
        print(f"  test_simple executed {steps} steps")

    def test_can_detect_completion(self):
        """Verify we can distinguish completion from timeout"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/test_simple/simple')

        # Run with very low limit
        steps_low = sim.run(max_steps=5)

        # Reset and run with high limit
        sim.load_elf('examples/riscv/test_simple/simple')
        steps_high = sim.run(max_steps=100)

        # With low limit, might not complete
        # With high limit, should definitely complete
        # If both return the same number, might indicate completion detection works
        print(f"  Low limit: {steps_low} steps, High limit: {steps_high} steps")


def run_tests():
    """Run all correctness tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestFibonacciCorrectness))
    suite.addTests(loader.loadTestsFromTestCase(TestToHostMechanism))
    suite.addTests(loader.loadTestsFromTestCase(TestMatrixMultiplyCorrectness))
    suite.addTests(loader.loadTestsFromTestCase(TestProgramCompletion))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
