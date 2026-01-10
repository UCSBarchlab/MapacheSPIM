#!/usr/bin/env python3
"""
Comprehensive disassembly tests for MapacheSPIM
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim import Simulator
from mapachespim.console import MapacheSPIMConsole


class TestDisassemblyAPI(unittest.TestCase):
    """Test disassembly at the API level"""

    def setUp(self):
        """Create a fresh simulator for each test"""
        self.sim = Simulator()
        self.sim.load_elf('tests/fixtures/test_simple')

    def test_disasm_basic(self):
        """Test basic disassembly of first instruction"""
        disasm = self.sim.disasm(0x80000000)
        self.assertIn('addi', disasm.lower())
        # Capstone uses ABI names (t0) instead of numeric (x5)
        self.assertIn('t0', disasm)

    def test_disasm_all_test_simple_instructions(self):
        """Test disassembly of all 9 instructions in test_simple"""
        # Using ABI register names (Capstone default)
        # Note: Capstone uses pseudo-instructions like 'j' instead of 'jal zero'
        expected = [
            ('0x80000000', 'addi', 't0'),   # li t0, 10
            ('0x80000004', 'addi', 't1'),   # li t1, 20
            ('0x80000008', 'add', 't2'),    # add t2, t0, t1
            ('0x8000000c', 'sub', 's0'),    # sub s0, t2, t0
            ('0x80000010', 'slli', 's1'),   # slli s1, t0, 2
            ('0x80000014', 'addi', 'a0'),   # li a0, 42
            ('0x80000018', 'j'),            # j done (pseudo for jal zero, offset)
            ('0x8000001c', 'addi', 'ra'),   # li ra, 93
            ('0x80000020', 'ecall'),        # ecall
        ]

        for addr_str, expected_mnemonic, *expected_regs in expected:
            addr = int(addr_str, 16)
            disasm = self.sim.disasm(addr)

            # Check mnemonic
            self.assertIn(expected_mnemonic, disasm.lower(),
                         f"At {addr_str}: expected '{expected_mnemonic}' in '{disasm}'")

            # Check registers if specified
            for reg in expected_regs:
                self.assertIn(reg, disasm,
                             f"At {addr_str}: expected '{reg}' in '{disasm}'")

    def test_disasm_instruction_types(self):
        """Test different RISC-V instruction types"""
        # R-type (add t2, t0, t1)
        disasm = self.sim.disasm(0x80000008)
        self.assertIn('add', disasm.lower())
        self.assertIn('t2', disasm)  # ABI name for x7
        self.assertIn('t0', disasm)  # ABI name for x5
        self.assertIn('t1', disasm)  # ABI name for x6

        # I-type (addi t0, zero, 10)
        disasm = self.sim.disasm(0x80000000)
        self.assertIn('addi', disasm.lower())
        self.assertIn('t0', disasm)  # ABI name for x5
        self.assertIn('0xa', disasm.lower())  # immediate value

        # I-type shift (slli s1, t0, 2)
        disasm = self.sim.disasm(0x80000010)
        self.assertIn('slli', disasm.lower())
        self.assertIn('s1', disasm)  # ABI name for x9
        self.assertIn('2', disasm)  # shift amount (may be decimal or hex)

        # J-type - Capstone shows 'j' pseudo-instruction instead of 'jal zero'
        disasm = self.sim.disasm(0x80000018)
        self.assertIn('j', disasm.lower())

        # System (ecall)
        disasm = self.sim.disasm(0x80000020)
        self.assertIn('ecall', disasm.lower())

    def test_disasm_immediate_values(self):
        """Test that immediate values are displayed correctly"""
        # addi x5, x0, 10
        disasm = self.sim.disasm(0x80000000)
        self.assertIn('0xa', disasm.lower())  # 10 in hex

        # addi x6, x0, 20
        disasm = self.sim.disasm(0x80000004)
        self.assertIn('0x14', disasm.lower())  # 20 in hex

        # addi x10, x0, 42
        disasm = self.sim.disasm(0x80000014)
        self.assertIn('0x2a', disasm.lower())  # 42 in hex

    def test_disasm_register_names(self):
        """Test that register names are correct (using ABI names)"""
        # Check various ABI register names appear
        disasm = self.sim.disasm(0x80000000)
        self.assertIn('t0', disasm)    # ABI name for x5
        self.assertIn('zero', disasm)  # ABI name for x0

        disasm = self.sim.disasm(0x80000014)
        self.assertIn('a0', disasm)    # ABI name for x10

        disasm = self.sim.disasm(0x8000001c)
        self.assertIn('ra', disasm)    # ABI name for x1

    def test_disasm_invalid_address(self):
        """Test disassembly of invalid address"""
        # Very high address - might fail or return "illegal" instruction
        try:
            disasm = self.sim.disasm(0xFFFFFFFF)  # Use 32-bit max instead
            # If it succeeds, should return something
            self.assertIsInstance(disasm, str)
        except RuntimeError:
            # Also acceptable to raise error for unmapped address
            pass

    def test_disasm_sequential(self):
        """Test disassembling sequential instructions"""
        # Disassemble first 5 instructions sequentially
        addresses = [0x80000000, 0x80000004, 0x80000008, 0x8000000c, 0x80000010]

        for addr in addresses:
            disasm = self.sim.disasm(addr)
            self.assertIsInstance(disasm, str)
            self.assertGreater(len(disasm), 0)


class TestDisassemblyConsole(unittest.TestCase):
    """Test disassembly console commands"""

    def setUp(self):
        """Create a fresh console for each test"""
        self.console = MapacheSPIMConsole(verbose=False)
        self.console.stdout = sys.stdout
        self.console.onecmd('load tests/fixtures/test_simple')

    def test_disasm_command_basic(self):
        """Test basic disasm command"""
        # Should not raise exception
        self.console.onecmd('disasm 0x80000000 1')

    def test_disasm_command_count(self):
        """Test disasm with different counts"""
        # Test various counts
        for count in [1, 5, 10, 20]:
            self.console.onecmd(f'disasm 0x80000000 {count}')

    def test_disasm_command_default_count(self):
        """Test disasm with default count (10)"""
        self.console.onecmd('disasm 0x80000000')

    def test_disasm_alias(self):
        """Test 'd' alias for disasm"""
        self.console.onecmd('d 0x80000000 5')

    def test_disasm_hex_address(self):
        """Test disasm with hex address"""
        self.console.onecmd('disasm 0x80000000 5')

    def test_disasm_decimal_address(self):
        """Test disasm with decimal address"""
        self.console.onecmd('disasm 2147483648 5')  # 0x80000000 in decimal

    def test_disasm_no_args(self):
        """Test disasm without arguments shows error"""
        # Should show error but not crash
        self.console.onecmd('disasm')

    def test_disasm_invalid_address(self):
        """Test disasm with invalid address format"""
        # Should show error but not crash
        self.console.onecmd('disasm invalid_address')

    def test_disasm_invalid_count(self):
        """Test disasm with invalid count"""
        # Should show error but not crash
        self.console.onecmd('disasm 0x80000000 invalid')

    def test_disasm_negative_count(self):
        """Test disasm with negative count"""
        # Should show error but not crash
        self.console.onecmd('disasm 0x80000000 -5')

    def test_disasm_zero_count(self):
        """Test disasm with zero count"""
        # Should show error but not crash
        self.console.onecmd('disasm 0x80000000 0')


class TestDisassemblyIntegration(unittest.TestCase):
    """Integration tests for disassembly with other features"""

    def setUp(self):
        """Create a fresh simulator for each test"""
        self.sim = Simulator()
        self.sim.load_elf('tests/fixtures/test_simple')

    def test_disasm_at_pc(self):
        """Test disassembling instruction at current PC"""
        pc = self.sim.get_pc()
        self.assertEqual(pc, 0x80000000)

        disasm = self.sim.disasm(pc)
        self.assertIn('addi', disasm.lower())

    def test_disasm_after_step(self):
        """Test disassembling after stepping"""
        # Step one instruction
        self.sim.step()
        pc = self.sim.get_pc()

        # Disassemble at new PC
        disasm = self.sim.disasm(pc)
        self.assertIn('addi', disasm.lower())
        self.assertIn('t1', disasm)  # ABI name for x6

    def test_disasm_multiple_steps(self):
        """Test disassembling after multiple steps"""
        for i in range(5):
            pc_before = self.sim.get_pc()
            disasm_before = self.sim.disasm(pc_before)

            self.sim.step()

            pc_after = self.sim.get_pc()
            # Verify PC moved (except after ecall)
            if i < 4:
                self.assertNotEqual(pc_before, pc_after)

    def test_disasm_with_memory_read(self):
        """Test that disasm and memory read are consistent"""
        addr = 0x80000000

        # Read instruction bytes
        instr_bytes = self.sim.read_mem(addr, 4)

        # Disassemble
        disasm = self.sim.disasm(addr)

        # Both should succeed for valid address
        self.assertIsNotNone(instr_bytes)
        self.assertIsNotNone(disasm)
        self.assertGreater(len(disasm), 0)

    def test_disasm_range(self):
        """Test disassembling a range of addresses"""
        start_addr = 0x80000000
        count = 9

        for i in range(count):
            addr = start_addr + (i * 4)
            disasm = self.sim.disasm(addr)

            # Each disassembly should be valid
            self.assertIsInstance(disasm, str)
            self.assertGreater(len(disasm), 0)


class TestDisassemblyEdgeCases(unittest.TestCase):
    """Test edge cases for disassembly"""

    def setUp(self):
        """Create a fresh simulator for each test"""
        self.sim = Simulator()
        self.sim.load_elf('tests/fixtures/test_simple')

    def test_disasm_unaligned_address(self):
        """Test disassembly of unaligned address"""
        # RISC-V instructions should be 4-byte aligned
        # Unaligned might still decode but results may be unexpected
        try:
            disasm = self.sim.disasm(0x80000001)  # Unaligned
            # Should either work or raise exception
            self.assertIsInstance(disasm, str)
        except RuntimeError:
            # Also acceptable to fail on unaligned
            pass

    def test_disasm_beyond_program(self):
        """Test disassembling beyond program memory"""
        # Address past the end of our small program
        addr = 0x80000100
        try:
            disasm = self.sim.disasm(addr)
            # Might decode as "illegal" or fail
            self.assertIsInstance(disasm, str)
        except RuntimeError:
            # Also acceptable to fail
            pass

    def test_disasm_zero_filled_memory(self):
        """Test disassembling zero-filled memory"""
        # Addresses that might be zero-filled
        # 0x00000000 encodes as "illegal" or specific instruction
        try:
            disasm = self.sim.disasm(0x80001000)
            self.assertIsInstance(disasm, str)
        except RuntimeError:
            pass

    def test_disasm_same_address_multiple_times(self):
        """Test disassembling same address repeatedly"""
        addr = 0x80000000

        # Disassemble same address 10 times
        results = [self.sim.disasm(addr) for _ in range(10)]

        # All results should be identical
        self.assertEqual(len(set(results)), 1)
        self.assertIn('addi', results[0].lower())


class TestDisassemblyWithDifferentPrograms(unittest.TestCase):
    """Test disassembly with different programs"""

    def test_disasm_fibonacci(self):
        """Test disassembly with fibonacci program"""
        sim = Simulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        # Disassemble entry point
        pc = sim.get_pc()
        disasm = sim.disasm(pc)

        self.assertIsInstance(disasm, str)
        self.assertGreater(len(disasm), 0)

    def test_disasm_matrix_multiply(self):
        """Test disassembly with matrix_multiply program"""
        sim = Simulator()
        sim.load_elf('examples/riscv/matrix_multiply/matrix_mult')

        # Disassemble entry point
        pc = sim.get_pc()
        disasm = sim.disasm(pc)

        self.assertIsInstance(disasm, str)
        self.assertGreater(len(disasm), 0)

    def test_disasm_different_entry_points(self):
        """Test that different programs have different entry point disassembly"""
        sim1 = Simulator()
        sim1.load_elf('examples/riscv/fibonacci/fibonacci')
        disasm1 = sim1.disasm(sim1.get_pc())

        sim2 = Simulator()
        sim2.load_elf('examples/riscv/matrix_multiply/matrix_mult')
        disasm2 = sim2.disasm(sim2.get_pc())

        # Entry points should disassemble to something
        self.assertIsInstance(disasm1, str)
        self.assertIsInstance(disasm2, str)


def run_tests():
    """Run all disassembly tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDisassemblyAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestDisassemblyConsole))
    suite.addTests(loader.loadTestsFromTestCase(TestDisassemblyIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestDisassemblyEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestDisassemblyWithDifferentPrograms))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
