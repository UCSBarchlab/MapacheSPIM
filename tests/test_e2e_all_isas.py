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


if __name__ == "__main__":
    unittest.main(verbosity=2)
