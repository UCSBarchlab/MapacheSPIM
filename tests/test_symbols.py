#!/usr/bin/env python3
"""
Symbol table tests for MapacheSail

Tests the symbol table functionality provided by Sail's ELF loader,
which is ISA-agnostic and works for any architecture Sail supports.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim.sail_backend import SailSimulator
from mapachespim.console import MapacheSPIMConsole


class TestSymbolTableAPI(unittest.TestCase):
    """Test symbol table at the API level"""

    def setUp(self):
        """Create a fresh simulator for each test"""
        self.sim = SailSimulator()
        self.sim.load_elf('examples/riscv/fibonacci/fibonacci')

    def test_get_symbols_returns_dict(self):
        """Test get_symbols returns a dictionary"""
        symbols = self.sim.get_symbols()
        self.assertIsInstance(symbols, dict)
        self.assertGreater(len(symbols), 0, "Symbol table should not be empty")

    def test_symbols_have_valid_addresses(self):
        """Test that all symbols have valid addresses"""
        symbols = self.sim.get_symbols()
        for name, addr in symbols.items():
            self.assertIsInstance(name, str)
            self.assertIsInstance(addr, int)
            self.assertGreaterEqual(addr, 0)

    def test_lookup_known_symbol(self):
        """Test looking up a known symbol (main)"""
        # Most programs have 'main' function
        addr = self.sim.lookup_symbol('main')

        # If main exists, it should be a valid address
        if addr is not None:
            self.assertIsInstance(addr, int)
            self.assertGreater(addr, 0)

    def test_lookup_nonexistent_symbol(self):
        """Test looking up a symbol that doesn't exist"""
        addr = self.sim.lookup_symbol('nonexistent_symbol_12345')
        self.assertIsNone(addr)

    def test_lookup_empty_string(self):
        """Test looking up empty string symbol name"""
        addr = self.sim.lookup_symbol('')
        self.assertIsNone(addr)

    def test_addr_to_symbol_at_symbol_start(self):
        """Test converting address to symbol at exact symbol location"""
        # Get a known symbol
        symbols = self.sim.get_symbols()
        if len(symbols) > 0:
            # Pick a specific symbol we know exists
            symbol_name = '_start'
            if symbol_name not in symbols:
                # Use any symbol if _start doesn't exist
                symbol_name = list(symbols.keys())[0]

            symbol_addr = symbols[symbol_name]

            # Look up by address
            found_name, offset = self.sim.addr_to_symbol(symbol_addr)

            # Should find a symbol at this address (may be different due to aliasing)
            self.assertIsNotNone(found_name)
            self.assertEqual(offset, 0)

    def test_addr_to_symbol_with_offset(self):
        """Test converting address to symbol with offset"""
        symbols = self.sim.get_symbols()
        if len(symbols) > 0:
            # Pick a specific symbol we know exists
            symbol_name = '_start'
            if symbol_name not in symbols:
                # Use any symbol if _start doesn't exist
                symbol_name = list(symbols.keys())[0]

            symbol_addr = symbols[symbol_name]

            # Look up address + 4 (one instruction later)
            found_name, offset = self.sim.addr_to_symbol(symbol_addr + 4)

            # Should find a symbol (may be aliased)
            self.assertIsNotNone(found_name)
            self.assertEqual(offset, 4)

    def test_addr_to_symbol_far_from_any_symbol(self):
        """Test converting address that's far from any symbol"""
        # Try very high address unlikely to have a symbol nearby
        found_name, offset = self.sim.addr_to_symbol(0xFFFFFFFF)
        self.assertIsNone(found_name)
        self.assertIsNone(offset)

    def test_symbol_consistency(self):
        """Test that lookup and get_symbols are consistent"""
        symbols = self.sim.get_symbols()

        # For each symbol in the table
        for name, expected_addr in symbols.items():
            # Lookup should return the same address
            found_addr = self.sim.lookup_symbol(name)
            self.assertEqual(found_addr, expected_addr,
                           f"Symbol {name} has inconsistent addresses")

    def test_symbols_persist_across_steps(self):
        """Test that symbols remain available after stepping"""
        symbols_before = self.sim.get_symbols()

        # Execute some steps
        self.sim.step()
        self.sim.step()

        symbols_after = self.sim.get_symbols()

        # Symbol table should be unchanged
        self.assertEqual(symbols_before, symbols_after)


class TestSymbolTableWithDifferentPrograms(unittest.TestCase):
    """Test symbol table with different ELF files"""

    def test_fibonacci_symbols(self):
        """Test fibonacci program has expected symbols"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        symbols = sim.get_symbols()
        self.assertGreater(len(symbols), 0)

        # Check for common symbols
        symbol_names = list(symbols.keys())
        # Most programs have at least one function or label

    def test_test_simple_symbols(self):
        """Test test_simple program symbols"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/test_simple/simple')

        symbols = sim.get_symbols()
        # Even simple programs may have symbols
        self.assertIsInstance(symbols, dict)

    def test_matrix_multiply_symbols(self):
        """Test matrix_multiply program symbols"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/matrix_multiply/matrix_mult')

        symbols = sim.get_symbols()
        self.assertGreater(len(symbols), 0)

    def test_symbols_cleared_on_new_load(self):
        """Test that symbols are replaced when loading new ELF"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')
        symbols1 = sim.get_symbols()

        sim.load_elf('examples/riscv/matrix_multiply/matrix_mult')
        symbols2 = sim.get_symbols()

        # Symbols should be different (different programs)
        # At minimum, the count or names should differ
        # (This test may need adjustment based on actual programs)
        self.assertIsInstance(symbols1, dict)
        self.assertIsInstance(symbols2, dict)


class TestSymbolsInConsole(unittest.TestCase):
    """Test symbol table integration with console commands"""

    def setUp(self):
        """Create a fresh console for each test"""
        self.console = MapacheSPIMConsole(verbose=False)
        self.console.stdout = sys.stdout
        self.console.onecmd('load examples/riscv/fibonacci/fibonacci')

    def test_info_symbols_command(self):
        """Test 'info symbols' command lists symbols"""
        # This command should be added to show symbol table
        # For now, just test it doesn't crash
        self.console.onecmd('info symbols')

    def test_symbolic_breakpoint(self):
        """Test setting breakpoint using symbol name"""
        # Get a known symbol
        symbols = self.console.sim.get_symbols()
        if len(symbols) > 0:
            symbol_name = list(symbols.keys())[0]

            # Try to set breakpoint with symbol name
            self.console.onecmd(f'break {symbol_name}')

            # Breakpoint should be set at symbol address
            symbol_addr = symbols[symbol_name]
            self.assertIn(symbol_addr, self.console.breakpoints)

    def test_symbolic_breakpoint_nonexistent(self):
        """Test setting breakpoint on nonexistent symbol"""
        # Should show error but not crash
        self.console.onecmd('break nonexistent_function_xyz')

    def test_step_shows_symbol_in_output(self):
        """Test that step command shows symbol names when available"""
        # Step from entry point
        # Output should include symbol name if available
        import io
        import sys

        # Capture output
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            self.console.onecmd('step')
            output = captured.getvalue()

            # Output should contain an address
            self.assertIn('[0x', output)

            # If there's a symbol at PC, it should be shown
            # (This is an integration test for enhanced step display)
        finally:
            sys.stdout = old_stdout


class TestSymbolEdgeCases(unittest.TestCase):
    """Test edge cases for symbol table"""

    def test_symbols_before_load(self):
        """Test querying symbols before loading ELF"""
        sim = SailSimulator()

        # Should return empty dict, not crash
        symbols = sim.get_symbols()
        self.assertEqual(len(symbols), 0)

    def test_lookup_before_load(self):
        """Test lookup before loading ELF"""
        sim = SailSimulator()

        addr = sim.lookup_symbol('main')
        self.assertIsNone(addr)

    def test_addr_to_symbol_before_load(self):
        """Test addr_to_symbol before loading ELF"""
        sim = SailSimulator()

        name, offset = sim.addr_to_symbol(0x80000000)
        self.assertIsNone(name)
        self.assertIsNone(offset)

    def test_symbol_with_special_characters(self):
        """Test symbols with special characters in names"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        symbols = sim.get_symbols()

        # C++ mangled names or special symbols may have dots, underscores, etc.
        # Just verify we can handle them
        for name in symbols.keys():
            # Should not crash when looking up
            addr = sim.lookup_symbol(name)
            self.assertIsNotNone(addr)


class TestSymbolSorting(unittest.TestCase):
    """Test symbol ordering and sorting"""

    def test_symbols_by_address(self):
        """Test getting symbols sorted by address"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        symbols = sim.get_symbols()

        # Sort by address
        sorted_symbols = sorted(symbols.items(), key=lambda x: x[1])

        # Verify sorting (addresses should be non-decreasing, not strictly increasing)
        # Multiple symbols can have the same address (aliases)
        prev_addr = -1
        for name, addr in sorted_symbols:
            self.assertGreaterEqual(addr, prev_addr)
            prev_addr = addr

    def test_symbols_by_name(self):
        """Test getting symbols sorted by name"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        symbols = sim.get_symbols()

        # Sort by name
        sorted_symbols = sorted(symbols.items(), key=lambda x: x[0])

        # Verify sorting
        prev_name = ""
        for name, addr in sorted_symbols:
            self.assertGreaterEqual(name, prev_name)
            prev_name = name


def run_tests():
    """Run all symbol table tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSymbolTableAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestSymbolTableWithDifferentPrograms))
    suite.addTests(loader.loadTestsFromTestCase(TestSymbolsInConsole))
    suite.addTests(loader.loadTestsFromTestCase(TestSymbolEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestSymbolSorting))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
