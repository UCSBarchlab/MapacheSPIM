#!/usr/bin/env python3
"""
x86-64 backend tests for MapacheSPIM

Tests the x86-64 support by directly testing the simulator internals
without requiring an x86-64 ELF toolchain.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim.unicorn_backend import (
    UnicornSimulator, ISA, StepResult, X86_64Config
)


class TestX86Config(unittest.TestCase):
    """Test x86-64 configuration"""

    def test_x86_config_exists(self):
        """Test that X86_64Config class exists"""
        config = X86_64Config()
        self.assertIsNotNone(config)

    def test_x86_register_names(self):
        """Test x86-64 register names"""
        config = X86_64Config()
        expected_names = [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        ]
        for i, expected in enumerate(expected_names):
            self.assertEqual(config.get_reg_name(i), expected)


class TestX86Simulator(unittest.TestCase):
    """Test x86-64 simulator functionality"""

    def test_create_x86_simulator(self):
        """Test creating an x86-64 simulator"""
        sim = UnicornSimulator(isa=ISA.X86_64)
        self.assertIsNotNone(sim)

    def test_x86_registers_count(self):
        """Test x86-64 has 16 registers"""
        sim = UnicornSimulator(isa=ISA.X86_64)
        regs = sim.get_all_regs()
        self.assertEqual(len(regs), 16, "x86-64 should have 16 GPRs")

    def test_x86_read_write_register(self):
        """Test reading and writing x86-64 registers"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        # Set rax (register 0) to a value
        test_val = 0x12345678ABCDEF00
        sim.set_reg(0, test_val)
        result = sim.get_reg(0)
        self.assertEqual(result, test_val)

    def test_x86_all_registers_writable(self):
        """Test that all x86-64 registers are writable (unlike RISC-V x0)"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        for i in range(16):
            val = 0x100 + i
            sim.set_reg(i, val)
            result = sim.get_reg(i)
            self.assertEqual(result, val, f"Register {i} should be writable")

    def test_x86_register_bounds(self):
        """Test x86-64 register bounds checking"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        # Valid registers 0-15
        for i in range(16):
            val = sim.get_reg(i)
            self.assertIsInstance(val, int)

        # Invalid register 16 should raise
        with self.assertRaises(ValueError):
            sim.get_reg(16)


class TestX86MachineCode(unittest.TestCase):
    """Test executing x86-64 machine code"""

    def test_execute_mov_immediate(self):
        """Test executing MOV with immediate"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        # Write machine code: mov rax, 42 (0x48 0xC7 0xC0 0x2A 0x00 0x00 0x00)
        # This is: REX.W MOV r/m64, imm32
        code = bytes([0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00])

        # Write at default x86 load address
        addr = 0x400000
        sim.write_mem(addr, code)
        sim.set_pc(addr)

        # Execute one instruction
        result = sim.step()
        self.assertEqual(result, StepResult.OK)

        # Check rax = 42
        rax = sim.get_reg(0)
        self.assertEqual(rax, 42, f"rax should be 42, got {rax}")

    def test_execute_add(self):
        """Test executing ADD instruction"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        # Set up initial register values
        sim.set_reg(0, 10)  # rax = 10
        sim.set_reg(1, 20)  # rcx = 20

        # Write machine code: add rax, rcx (0x48 0x01 0xC8)
        # This is: REX.W ADD r/m64, r64
        code = bytes([0x48, 0x01, 0xC8])

        addr = 0x400000
        sim.write_mem(addr, code)
        sim.set_pc(addr)

        result = sim.step()
        self.assertEqual(result, StepResult.OK)

        # Check rax = 30
        rax = sim.get_reg(0)
        self.assertEqual(rax, 30, f"rax should be 30, got {rax}")

    def test_execute_sub(self):
        """Test executing SUB instruction"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        sim.set_reg(0, 50)  # rax = 50
        sim.set_reg(1, 20)  # rcx = 20

        # Write machine code: sub rax, rcx (0x48 0x29 0xC8)
        code = bytes([0x48, 0x29, 0xC8])

        addr = 0x400000
        sim.write_mem(addr, code)
        sim.set_pc(addr)

        result = sim.step()
        self.assertEqual(result, StepResult.OK)

        rax = sim.get_reg(0)
        self.assertEqual(rax, 30, f"rax should be 30, got {rax}")


class TestX86Syscall(unittest.TestCase):
    """Test x86-64 syscall detection"""

    def test_syscall_detection(self):
        """Test that syscall instruction is detected"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        # Set up exit syscall: rax=10 (SPIM exit)
        sim.set_reg(0, 10)  # rax = syscall number

        # Write syscall instruction: 0x0F 0x05
        code = bytes([0x0F, 0x05])

        addr = 0x400000
        sim.write_mem(addr, code)
        sim.set_pc(addr)

        result = sim.step()
        self.assertEqual(result, StepResult.SYSCALL)


class TestX86Disassembly(unittest.TestCase):
    """Test x86-64 disassembly"""

    def test_disasm_mov(self):
        """Test disassembling MOV instruction"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        # mov rax, 42
        code = bytes([0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00])

        addr = 0x400000
        sim.write_mem(addr, code)

        disasm = sim.disasm(addr)
        self.assertIn("mov", disasm.lower())
        self.assertIn("rax", disasm.lower())

    def test_disasm_add(self):
        """Test disassembling ADD instruction"""
        sim = UnicornSimulator(isa=ISA.X86_64)

        # add rax, rcx
        code = bytes([0x48, 0x01, 0xC8])

        addr = 0x400000
        sim.write_mem(addr, code)

        disasm = sim.disasm(addr)
        self.assertIn("add", disasm.lower())


class TestX86ISAEnum(unittest.TestCase):
    """Test ISA enum has x86-64"""

    def test_x86_in_isa_enum(self):
        """Test X86_64 is in ISA enum"""
        self.assertEqual(ISA.X86_64, 2)

    def test_isa_names(self):
        """Test ISA enum names"""
        self.assertEqual(ISA.RISCV.name, "RISCV")
        self.assertEqual(ISA.ARM.name, "ARM")
        self.assertEqual(ISA.X86_64.name, "X86_64")


def run_tests():
    """Run all x86-64 tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestX86Config))
    suite.addTests(loader.loadTestsFromTestCase(TestX86Simulator))
    suite.addTests(loader.loadTestsFromTestCase(TestX86MachineCode))
    suite.addTests(loader.loadTestsFromTestCase(TestX86Syscall))
    suite.addTests(loader.loadTestsFromTestCase(TestX86Disassembly))
    suite.addTests(loader.loadTestsFromTestCase(TestX86ISAEnum))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
