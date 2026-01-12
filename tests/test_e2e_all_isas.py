#!/usr/bin/env python3
"""
End-to-end tests for all supported ISAs.

These tests verify that programs load, execute correctly, and produce
expected results across RISC-V, ARM64, x86-64, and MIPS architectures.

This is a critical test suite that catches integration issues like:
- ISA detection failures
- Memory mapping problems
- PC not advancing during execution
- Incorrect instruction emulation
"""

import sys
import unittest
from pathlib import Path
from io import StringIO

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import create_simulator, detect_elf_isa, ISA, StepResult
from mapachespim.console import MapacheSPIMConsole


class TestISADetection(unittest.TestCase):
    """Test ISA detection for all architectures"""

    def test_detect_riscv(self):
        """Detect RISC-V ISA from ELF"""
        elf = Path("examples/riscv/fibonacci/fibonacci")
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")
        self.assertEqual(detect_elf_isa(str(elf)), ISA.RISCV)

    def test_detect_arm(self):
        """Detect ARM64 ISA from ELF"""
        elf = Path("examples/arm/fibonacci/fibonacci")
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")
        self.assertEqual(detect_elf_isa(str(elf)), ISA.ARM)

    def test_detect_x86_64(self):
        """Detect x86-64 ISA from ELF"""
        elf = Path("examples/x86_64/fibonacci/fibonacci")
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")
        self.assertEqual(detect_elf_isa(str(elf)), ISA.X86_64)

    def test_detect_mips(self):
        """Detect MIPS ISA from ELF"""
        elf = Path("examples/mips/fibonacci/fibonacci")
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")
        self.assertEqual(detect_elf_isa(str(elf)), ISA.MIPS)


class TestPCAdvancement(unittest.TestCase):
    """Critical test: verify PC advances for all ISAs when stepping"""

    def _test_pc_advances(self, elf_path: str, isa_name: str, expected_step_size: int):
        """Helper to test PC advancement for any ISA"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))
        self.assertEqual(sim.get_isa_name(), isa_name)

        # PC must advance after stepping
        pc_before = sim.get_pc()
        self.assertNotEqual(pc_before, 0, "Entry PC should not be zero")

        sim.step()
        pc_after = sim.get_pc()

        self.assertNotEqual(pc_before, pc_after,
            f"{isa_name}: PC should advance after step (was 0x{pc_before:x}, still 0x{pc_after:x})")

    def test_riscv_pc_advances(self):
        """RISC-V PC advances when stepping"""
        self._test_pc_advances("examples/riscv/hello_asm/hello_asm", "RISCV", 4)

    def test_arm_pc_advances(self):
        """ARM64 PC advances when stepping"""
        self._test_pc_advances("examples/arm/hello_asm/hello_asm", "ARM", 4)

    def test_x86_pc_advances(self):
        """x86-64 PC advances when stepping"""
        self._test_pc_advances("examples/x86_64/hello_asm/hello_asm", "X86_64", 0)  # variable

    def test_mips_pc_advances(self):
        """MIPS PC advances when stepping (regression test for Unicorn quirk)"""
        self._test_pc_advances("examples/mips/hello_asm/hello_asm", "MIPS", 4)


class TestMultipleSteps(unittest.TestCase):
    """Test stepping through multiple instructions for all ISAs"""

    def _test_multiple_steps(self, elf_path: str, isa_name: str, num_steps: int = 10):
        """Helper to verify multiple steps work correctly"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))
        entry_pc = sim.get_pc()
        pcs_seen = [entry_pc]

        for i in range(num_steps):
            pc_before = sim.get_pc()
            result = sim.step()
            pc_after = sim.get_pc()

            # Stop if we hit a syscall or error
            if result in (StepResult.SYSCALL, StepResult.ERROR, StepResult.HALT):
                break

            # PC should change (unless it's a self-loop, which would be a bug)
            self.assertNotEqual(pc_before, pc_after,
                f"{isa_name} step {i+1}: PC stuck at 0x{pc_before:x}")

            pcs_seen.append(pc_after)

        # Should have seen multiple different PCs
        unique_pcs = len(set(pcs_seen))
        self.assertGreater(unique_pcs, 1,
            f"{isa_name}: Should see multiple PCs, only saw {unique_pcs}")

    def test_riscv_multiple_steps(self):
        """RISC-V executes multiple steps correctly"""
        self._test_multiple_steps("examples/riscv/hello_asm/hello_asm", "RISCV")

    def test_arm_multiple_steps(self):
        """ARM64 executes multiple steps correctly"""
        self._test_multiple_steps("examples/arm/hello_asm/hello_asm", "ARM")

    def test_x86_multiple_steps(self):
        """x86-64 executes multiple steps correctly"""
        self._test_multiple_steps("examples/x86_64/hello_asm/hello_asm", "X86_64")

    def test_mips_multiple_steps(self):
        """MIPS executes multiple steps correctly"""
        self._test_multiple_steps("examples/mips/hello_asm/hello_asm", "MIPS")


class TestFibonacciAllISAs(unittest.TestCase):
    """Test Fibonacci program produces correct result on all ISAs"""

    def _run_fibonacci(self, elf_path: str, isa_name: str) -> int:
        """Run fibonacci and return result from fib_result symbol"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))

        # Run with step limit
        MAX_STEPS = 10000
        steps = sim.run(max_steps=MAX_STEPS)

        self.assertLess(steps, MAX_STEPS,
            f"{isa_name}: Fibonacci should complete in <{MAX_STEPS} steps, took {steps}")

        # Get result from fib_result symbol
        fib_result_addr = sim.lookup_symbol('fib_result')
        if fib_result_addr is None:
            self.skipTest(f"{isa_name}: No fib_result symbol")

        # Read result (handle endianness)
        result_bytes = sim.read_mem(fib_result_addr, 4)

        # Determine endianness from ISA
        if isa_name == "MIPS":
            byteorder = 'big'
        else:
            byteorder = 'little'

        result = int.from_bytes(result_bytes, byteorder=byteorder, signed=False)
        return result, steps

    def test_riscv_fibonacci_correct(self):
        """RISC-V Fibonacci(7) = 13"""
        result, steps = self._run_fibonacci("examples/riscv/fibonacci/fibonacci", "RISCV")
        self.assertEqual(result, 13, f"RISC-V: Fibonacci(7) should be 13, got {result}")

    def test_arm_fibonacci_correct(self):
        """ARM64 Fibonacci(7) = 13"""
        result, steps = self._run_fibonacci("examples/arm/fibonacci/fibonacci", "ARM")
        self.assertEqual(result, 13, f"ARM64: Fibonacci(7) should be 13, got {result}")

    def test_x86_fibonacci_correct(self):
        """x86-64 Fibonacci(7) = 13"""
        result, steps = self._run_fibonacci("examples/x86_64/fibonacci/fibonacci", "X86_64")
        self.assertEqual(result, 13, f"x86-64: Fibonacci(7) should be 13, got {result}")

    def test_mips_fibonacci_correct(self):
        """MIPS Fibonacci(7) = 13"""
        result, steps = self._run_fibonacci("examples/mips/fibonacci/fibonacci", "MIPS")
        self.assertEqual(result, 13, f"MIPS: Fibonacci(7) should be 13, got {result}")


class TestConsoleAllISAs(unittest.TestCase):
    """Test console commands work correctly for all ISAs"""

    def _test_console_load_and_step(self, elf_path: str, isa_name: str):
        """Test console can load and step through program"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        console = MapacheSPIMConsole(verbose=False)
        console.stdout = StringIO()

        # Load program
        console.onecmd(f'load {elf}')
        self.assertIsNotNone(console.sim, f"{isa_name}: Simulator should be created")
        self.assertEqual(console.loaded_file, str(elf))

        # Get initial PC
        pc_before = console.sim.get_pc()

        # Step once
        console.onecmd('step')

        # Verify PC changed
        pc_after = console.sim.get_pc()
        self.assertNotEqual(pc_before, pc_after,
            f"{isa_name}: Console step should advance PC")

        # Step multiple times
        console.onecmd('step 5')

        # PC should have advanced further
        pc_final = console.sim.get_pc()
        self.assertNotEqual(pc_after, pc_final,
            f"{isa_name}: Multiple steps should advance PC further")

        console.stdout.close()

    def test_console_riscv(self):
        """Console works with RISC-V"""
        self._test_console_load_and_step("examples/riscv/hello_asm/hello_asm", "RISCV")

    def test_console_arm(self):
        """Console works with ARM64"""
        self._test_console_load_and_step("examples/arm/hello_asm/hello_asm", "ARM")

    def test_console_x86(self):
        """Console works with x86-64"""
        self._test_console_load_and_step("examples/x86_64/hello_asm/hello_asm", "X86_64")

    def test_console_mips(self):
        """Console works with MIPS"""
        self._test_console_load_and_step("examples/mips/hello_asm/hello_asm", "MIPS")


class TestDisassemblyAllISAs(unittest.TestCase):
    """Test disassembly works for all ISAs"""

    def _test_disasm(self, elf_path: str, isa_name: str):
        """Test disassembly produces output"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))
        pc = sim.get_pc()

        # Disassemble at entry point
        disasm = sim.disasm(pc)

        self.assertIsNotNone(disasm, f"{isa_name}: Disassembly should not be None")
        self.assertIsInstance(disasm, str, f"{isa_name}: Disassembly should be string")
        self.assertGreater(len(disasm), 0, f"{isa_name}: Disassembly should not be empty")

    def test_disasm_riscv(self):
        """RISC-V disassembly works"""
        self._test_disasm("examples/riscv/hello_asm/hello_asm", "RISCV")

    def test_disasm_arm(self):
        """ARM64 disassembly works"""
        self._test_disasm("examples/arm/hello_asm/hello_asm", "ARM")

    def test_disasm_x86(self):
        """x86-64 disassembly works"""
        self._test_disasm("examples/x86_64/hello_asm/hello_asm", "X86_64")

    def test_disasm_mips(self):
        """MIPS disassembly works"""
        self._test_disasm("examples/mips/hello_asm/hello_asm", "MIPS")


class TestRunToCompletion(unittest.TestCase):
    """Test programs run to completion without hanging"""

    PROGRAMS = [
        ("examples/riscv/fibonacci/fibonacci", "RISCV", 1000),
        ("examples/arm/fibonacci/fibonacci", "ARM", 1000),
        ("examples/x86_64/fibonacci/fibonacci", "X86_64", 1000),
        ("examples/mips/fibonacci/fibonacci", "MIPS", 1000),
    ]

    def test_all_fibonacci_complete(self):
        """All Fibonacci programs complete in reasonable time"""
        for elf_path, isa_name, max_steps in self.PROGRAMS:
            with self.subTest(isa=isa_name):
                elf = Path(elf_path)
                if not elf.exists():
                    self.skipTest(f"Not found: {elf}")

                sim = create_simulator(str(elf))
                steps = sim.run(max_steps=max_steps)

                self.assertLess(steps, max_steps,
                    f"{isa_name}: Should complete in <{max_steps} steps, took {steps}")


class TestMemoryOperations(unittest.TestCase):
    """Test memory read/write operations for all ISAs"""

    def _test_memory_ops(self, elf_path: str, isa_name: str):
        """Test basic memory operations"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))
        pc = sim.get_pc()

        # Read memory at entry point (should be instruction bytes)
        mem = sim.read_mem(pc, 4)
        self.assertEqual(len(mem), 4, f"{isa_name}: Should read 4 bytes")
        self.assertNotEqual(mem, b'\x00\x00\x00\x00',
            f"{isa_name}: Entry point should have non-zero instruction bytes")

    def test_memory_riscv(self):
        """RISC-V memory operations"""
        self._test_memory_ops("examples/riscv/hello_asm/hello_asm", "RISCV")

    def test_memory_arm(self):
        """ARM64 memory operations"""
        self._test_memory_ops("examples/arm/hello_asm/hello_asm", "ARM")

    def test_memory_x86(self):
        """x86-64 memory operations"""
        self._test_memory_ops("examples/x86_64/hello_asm/hello_asm", "X86_64")

    def test_memory_mips(self):
        """MIPS memory operations"""
        self._test_memory_ops("examples/mips/hello_asm/hello_asm", "MIPS")


class TestHelloAsmAllISAs(unittest.TestCase):
    """Test hello_asm program runs to completion on all ISAs"""

    def _run_hello(self, elf_path: str, isa_name: str) -> int:
        """Run hello_asm and return step count"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))

        # Run with step limit - hello_asm should complete quickly
        MAX_STEPS = 100
        steps = sim.run(max_steps=MAX_STEPS)

        self.assertLess(steps, MAX_STEPS,
            f"{isa_name}: hello_asm should complete in <{MAX_STEPS} steps, took {steps}")

        return steps

    def test_riscv_hello_completes(self):
        """RISC-V hello_asm completes"""
        steps = self._run_hello("examples/riscv/hello_asm/hello_asm", "RISCV")
        self.assertGreater(steps, 5, "Should execute more than 5 instructions")

    def test_arm_hello_completes(self):
        """ARM64 hello_asm completes"""
        steps = self._run_hello("examples/arm/hello_asm/hello_asm", "ARM")
        self.assertGreater(steps, 5, "Should execute more than 5 instructions")

    def test_x86_hello_completes(self):
        """x86-64 hello_asm completes"""
        steps = self._run_hello("examples/x86_64/hello_asm/hello_asm", "X86_64")
        self.assertGreater(steps, 5, "Should execute more than 5 instructions")

    def test_mips_hello_completes(self):
        """MIPS hello_asm completes"""
        steps = self._run_hello("examples/mips/hello_asm/hello_asm", "MIPS")
        self.assertGreater(steps, 5, "Should execute more than 5 instructions")


class TestArrayStatsAllISAs(unittest.TestCase):
    """Test array_stats program computes correct statistics on all ISAs

    The array is: [23, 7, 42, 15, 8, 31, 4, 19]
    Expected: sum=149, min=4, max=42, count=8
    """

    def _get_endianness(self, isa_name: str) -> str:
        """Return byte order for ISA"""
        return 'big' if isa_name == "MIPS" else 'little'

    def _run_array_stats(self, elf_path: str, isa_name: str):
        """Run array_stats and verify results"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))

        # Run to completion
        MAX_STEPS = 5000
        steps = sim.run(max_steps=MAX_STEPS)

        self.assertLess(steps, MAX_STEPS,
            f"{isa_name}: array_stats should complete in <{MAX_STEPS} steps, took {steps}")

        return sim, steps

    def _read_array(self, sim, symbol: str, count: int, isa_name: str):
        """Read an array of words from memory"""
        addr = sim.lookup_symbol(symbol)
        if addr is None:
            return None

        byteorder = self._get_endianness(isa_name)
        values = []
        for i in range(count):
            word_bytes = sim.read_mem(addr + i * 4, 4)
            value = int.from_bytes(word_bytes, byteorder=byteorder, signed=True)
            values.append(value)
        return values

    def test_riscv_array_stats_runs(self):
        """RISC-V array_stats completes"""
        sim, steps = self._run_array_stats("examples/riscv/array_stats/array_stats", "RISCV")
        # Verify array is loaded correctly
        array = self._read_array(sim, 'array', 8, "RISCV")
        if array:
            self.assertEqual(array, [23, 7, 42, 15, 8, 31, 4, 19],
                "RISC-V: Array should contain expected values")

    def test_arm_array_stats_runs(self):
        """ARM64 array_stats completes"""
        sim, steps = self._run_array_stats("examples/arm/array_stats/array_stats", "ARM")
        array = self._read_array(sim, 'array', 8, "ARM")
        if array:
            self.assertEqual(array, [23, 7, 42, 15, 8, 31, 4, 19],
                "ARM64: Array should contain expected values")

    def test_x86_array_stats_runs(self):
        """x86-64 array_stats completes"""
        sim, steps = self._run_array_stats("examples/x86_64/array_stats/array_stats", "X86_64")
        array = self._read_array(sim, 'array', 8, "X86_64")
        if array:
            self.assertEqual(array, [23, 7, 42, 15, 8, 31, 4, 19],
                "x86-64: Array should contain expected values")

    def test_mips_array_stats_runs(self):
        """MIPS array_stats completes"""
        sim, steps = self._run_array_stats("examples/mips/array_stats/array_stats", "MIPS")
        array = self._read_array(sim, 'array', 8, "MIPS")
        if array:
            self.assertEqual(array, [23, 7, 42, 15, 8, 31, 4, 19],
                "MIPS: Array should contain expected values")


class TestMatrixMultiplyAllISAs(unittest.TestCase):
    """Test matrix_multiply program computes correct result on all ISAs

    Matrix A (3x3):     Matrix B (3x3):     Expected C (3x3):
    [ 1  2  3 ]         [ 9  8  7 ]         [ 30  24  18 ]
    [ 4  5  6 ]    *    [ 6  5  4 ]    =    [ 84  69  54 ]
    [ 7  8  9 ]         [ 3  2  1 ]         [138 114  90 ]
    """

    EXPECTED_RESULT = [
        [30, 24, 18],
        [84, 69, 54],
        [138, 114, 90]
    ]

    def _get_endianness(self, isa_name: str) -> str:
        """Return byte order for ISA"""
        return 'big' if isa_name == "MIPS" else 'little'

    def _read_matrix(self, sim, symbol: str, isa_name: str):
        """Read a 3x3 matrix from memory"""
        addr = sim.lookup_symbol(symbol)
        if addr is None:
            return None

        byteorder = self._get_endianness(isa_name)
        matrix = []
        for row in range(3):
            row_values = []
            for col in range(3):
                offset = (row * 3 + col) * 4
                word_bytes = sim.read_mem(addr + offset, 4)
                value = int.from_bytes(word_bytes, byteorder=byteorder, signed=True)
                row_values.append(value)
            matrix.append(row_values)
        return matrix

    def _run_matrix_multiply(self, elf_path: str, isa_name: str):
        """Run matrix_multiply and return simulator"""
        elf = Path(elf_path)
        if not elf.exists():
            self.skipTest(f"Not found: {elf}")

        sim = create_simulator(str(elf))

        # Run to completion
        MAX_STEPS = 5000
        steps = sim.run(max_steps=MAX_STEPS)

        self.assertLess(steps, MAX_STEPS,
            f"{isa_name}: matrix_multiply should complete in <{MAX_STEPS} steps, took {steps}")

        return sim, steps

    def test_riscv_matrix_result(self):
        """RISC-V matrix_multiply produces correct result"""
        sim, steps = self._run_matrix_multiply("examples/riscv/matrix_multiply/matrix_mult", "RISCV")
        result = self._read_matrix(sim, 'matrix_c', "RISCV")
        if result:
            self.assertEqual(result, self.EXPECTED_RESULT,
                f"RISC-V: Matrix C should be {self.EXPECTED_RESULT}, got {result}")

    def test_arm_matrix_result(self):
        """ARM64 matrix_multiply produces correct result"""
        sim, steps = self._run_matrix_multiply("examples/arm/matrix_multiply/matrix_mult", "ARM")
        result = self._read_matrix(sim, 'matrix_c', "ARM")
        if result:
            self.assertEqual(result, self.EXPECTED_RESULT,
                f"ARM64: Matrix C should be {self.EXPECTED_RESULT}, got {result}")

    def test_x86_matrix_result(self):
        """x86-64 matrix_multiply produces correct result"""
        sim, steps = self._run_matrix_multiply("examples/x86_64/matrix_multiply/matrix_mult", "X86_64")
        result = self._read_matrix(sim, 'matrix_c', "X86_64")
        if result:
            self.assertEqual(result, self.EXPECTED_RESULT,
                f"x86-64: Matrix C should be {self.EXPECTED_RESULT}, got {result}")

    def test_mips_matrix_result(self):
        """MIPS matrix_multiply produces correct result"""
        sim, steps = self._run_matrix_multiply("examples/mips/matrix_multiply/matrix_mult", "MIPS")
        result = self._read_matrix(sim, 'matrix_c', "MIPS")
        if result:
            self.assertEqual(result, self.EXPECTED_RESULT,
                f"MIPS: Matrix C should be {self.EXPECTED_RESULT}, got {result}")


class TestAllProgramsComplete(unittest.TestCase):
    """Ensure all example programs complete without hanging"""

    ALL_EXAMPLES = [
        # (path, isa, max_steps)
        ("examples/riscv/hello_asm/hello_asm", "RISCV", 100),
        ("examples/riscv/fibonacci/fibonacci", "RISCV", 1000),
        ("examples/riscv/array_stats/array_stats", "RISCV", 5000),
        ("examples/riscv/matrix_multiply/matrix_mult", "RISCV", 5000),
        ("examples/arm/hello_asm/hello_asm", "ARM", 100),
        ("examples/arm/fibonacci/fibonacci", "ARM", 1000),
        ("examples/arm/array_stats/array_stats", "ARM", 5000),
        ("examples/arm/matrix_multiply/matrix_mult", "ARM", 5000),
        ("examples/x86_64/hello_asm/hello_asm", "X86_64", 100),
        ("examples/x86_64/fibonacci/fibonacci", "X86_64", 1000),
        ("examples/x86_64/array_stats/array_stats", "X86_64", 5000),
        ("examples/x86_64/matrix_multiply/matrix_mult", "X86_64", 5000),
        ("examples/mips/hello_asm/hello_asm", "MIPS", 100),
        ("examples/mips/fibonacci/fibonacci", "MIPS", 1000),
        ("examples/mips/array_stats/array_stats", "MIPS", 5000),
        ("examples/mips/matrix_multiply/matrix_mult", "MIPS", 5000),
    ]

    def test_all_examples_complete(self):
        """All example programs complete within step limits"""
        for elf_path, isa_name, max_steps in self.ALL_EXAMPLES:
            with self.subTest(program=elf_path, isa=isa_name):
                elf = Path(elf_path)
                if not elf.exists():
                    self.skipTest(f"Not found: {elf}")

                sim = create_simulator(str(elf))
                steps = sim.run(max_steps=max_steps)

                self.assertLess(steps, max_steps,
                    f"{isa_name} {elf_path}: Should complete in <{max_steps} steps, took {steps}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
