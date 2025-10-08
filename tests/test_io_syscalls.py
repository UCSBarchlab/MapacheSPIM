#!/usr/bin/env python3
"""
Test SPIM-compatible I/O syscalls

Tests print_string, print_int, print_char, and exit syscalls.
"""

import sys
import unittest
from pathlib import Path
from io import StringIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import SailSimulator


class TestPrintStringSyscall(unittest.TestCase):
    """Test syscall 4 (print_string)"""

    HELLO_PATH = 'examples/riscv/hello_world/hello'

    def test_hello_world_prints_correctly(self):
        """Verify hello world program prints correct string"""
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()

        try:
            sim = SailSimulator()
            sim.load_elf(self.HELLO_PATH)
            steps = sim.run(max_steps=100)

            output = captured_output.getvalue()

            # Verify output
            self.assertEqual(output, "Hello, World!\n",
                "Hello world should print 'Hello, World!\\n'")

            # Verify program completed quickly
            self.assertLess(steps, 100,
                f"Hello world should complete in <100 steps, took {steps}")

        finally:
            sys.stdout = old_stdout

    def test_program_exits_cleanly(self):
        """Verify program exits via syscall 10 (exit)"""
        sim = SailSimulator()
        sim.load_elf(self.HELLO_PATH)

        # Suppress output
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            steps = sim.run(max_steps=1000)
        finally:
            sys.stdout = old_stdout

        # Should complete well before limit
        self.assertLess(steps, 100,
            "Program should exit cleanly via syscall, not hit limit")


class TestSyscallDetection(unittest.TestCase):
    """Test that syscalls are properly detected and handled"""

    def test_syscall_detected_as_step_result(self):
        """Verify ecall instructions return SYSCALL step result"""
        from mapachespim import StepResult

        sim = SailSimulator()
        sim.load_elf('examples/riscv/hello_world/hello')

        # Suppress output
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        try:
            # Step until we hit first ecall
            syscall_found = False
            for _ in range(50):
                result = sim.step()
                if result == StepResult.SYSCALL:
                    syscall_found = True
                    break
        finally:
            sys.stdout = old_stdout

        self.assertTrue(syscall_found,
            "Should detect at least one syscall in first 50 instructions")


class TestFibonacciStillWorks(unittest.TestCase):
    """Verify existing programs still work with syscall changes"""

    def test_fibonacci_still_produces_correct_result(self):
        """Ensure fibonacci program still works correctly"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        steps = sim.run(max_steps=10000)

        # Should still complete
        self.assertLess(steps, 10000,
            "Fibonacci should still complete")

        # Should still produce correct result
        fib_result_addr = sim.lookup_symbol('fib_result')
        result_bytes = sim.read_mem(fib_result_addr, 4)
        result_value = int.from_bytes(result_bytes, byteorder='little', signed=False)

        self.assertEqual(result_value, 13,
            "Fibonacci(7) should still equal 13 after syscall changes")


def run_tests():
    """Run all I/O syscall tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestPrintStringSyscall))
    suite.addTests(loader.loadTestsFromTestCase(TestSyscallDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestFibonacciStillWorks))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
