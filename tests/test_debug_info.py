#!/usr/bin/env python3
"""
Test suite for DWARF debug info and source listing functionality.

Tests that:
1. DWARF line info is correctly parsed
2. PC-to-source mapping works for all instructions (including expanded pseudo-ops)
3. The list command shows correct source lines
"""

import sys
import unittest
from pathlib import Path
from io import StringIO

sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim.console import MapacheSPIMConsole, _parse_dwarf_line_info, SourceInfo
from mapachespim import create_simulator


class TestDWARFParsing(unittest.TestCase):
    """Test DWARF debug info parsing"""

    def test_parse_riscv_debug_info(self):
        """Test parsing DWARF info from RISC-V ELF with debug symbols"""
        info = _parse_dwarf_line_info('examples/riscv/hello_asm/hello_asm')

        self.assertTrue(info.has_debug_info, "Should have debug info")
        self.assertGreater(len(info.addr_to_line), 0, "Should have address mappings")

        # Check that source file was found
        self.assertGreater(len(info.source_cache), 0, "Should have cached source")

    def test_address_mappings_exist(self):
        """Test that address mappings point to valid source lines"""
        info = _parse_dwarf_line_info('examples/riscv/hello_asm/hello_asm')

        for addr, (filename, line_num) in info.addr_to_line.items():
            self.assertIsInstance(addr, int)
            self.assertIsInstance(filename, str)
            self.assertIsInstance(line_num, int)
            self.assertGreater(line_num, 0, "Line numbers should be positive")


class TestSourceLocationMapping(unittest.TestCase):
    """Test PC-to-source location mapping, especially for expanded pseudo-ops"""

    def test_exact_address_lookup(self):
        """Test that exact address lookup works"""
        info = _parse_dwarf_line_info('examples/riscv/hello_asm/hello_asm')

        # Entry point should have a mapping
        location = info.get_location(0x80000000)
        self.assertIsNotNone(location, "Entry point should have mapping")
        self.assertEqual(location[1], 61, "Entry point should map to line 61 (la instruction)")

    def test_expanded_pseudo_op_mapping(self):
        """Test that addresses within expanded pseudo-ops map to correct source line

        The 'la' instruction expands to 'auipc + addi' (2 instructions, 8 bytes).
        Both 0x80000000 and 0x80000004 should map to line 61.
        """
        info = _parse_dwarf_line_info('examples/riscv/hello_asm/hello_asm')

        # The first 'la' at 0x80000000 expands to two instructions
        # Both addresses should map to the same source line
        loc1 = info.get_location(0x80000000)
        loc2 = info.get_location(0x80000004)  # Second instruction of expanded 'la'

        self.assertIsNotNone(loc1, "First instruction should have mapping")
        self.assertIsNotNone(loc2, "Second instruction of expanded pseudo-op should have mapping")

        # Both should map to the same source line
        self.assertEqual(loc1[1], loc2[1],
            "Both instructions of 'la' should map to same source line")

    def test_all_pcs_have_mapping(self):
        """Test that stepping through the program, every PC has a source mapping"""
        info = _parse_dwarf_line_info('examples/riscv/hello_asm/hello_asm')
        sim = create_simulator('examples/riscv/hello_asm/hello_asm')

        # Step through first 20 instructions
        unmapped_pcs = []
        for i in range(20):
            pc = sim.get_pc()
            location = info.get_location(pc)
            if location is None:
                unmapped_pcs.append(pc)

            result = sim.step()
            # Stop if we hit a syscall (ecall)
            if result.name == 'SYSCALL':
                break

        self.assertEqual(len(unmapped_pcs), 0,
            f"All PCs should have source mappings. Unmapped: {[hex(pc) for pc in unmapped_pcs]}")


class TestListCommand(unittest.TestCase):
    """Test the console 'list' command"""

    def setUp(self):
        """Create console for each test"""
        self.console = MapacheSPIMConsole(verbose=False)
        self.console.stdout = StringIO()

    def tearDown(self):
        """Clean up"""
        if hasattr(self.console, 'stdout'):
            self.console.stdout.close()

    def get_output(self):
        """Get captured output"""
        return self.console.stdout.getvalue()

    def clear_output(self):
        """Clear output buffer"""
        self.console.stdout = StringIO()

    def test_list_shows_pc_marker(self):
        """Test that list command marks the current PC line"""
        self.console.onecmd('load examples/riscv/hello_asm/hello_asm')
        self.clear_output()
        self.console.onecmd('list')
        output = self.get_output()

        self.assertIn('PC:', output, "Should show PC marker")
        self.assertIn('0x80000000', output.lower(), "Should show PC address")

    def test_list_after_step_shows_correct_line(self):
        """Test that list shows correct source after stepping"""
        self.console.onecmd('load examples/riscv/hello_asm/hello_asm')

        # Step once (still in first 'la' instruction)
        self.console.onecmd('step')
        self.clear_output()
        self.console.onecmd('list')
        output = self.get_output()

        # Should still show the 'la' line (line 61) even though PC is at second instruction
        self.assertIn('la', output.lower(), "Should show 'la' instruction line")
        self.assertIn('PC:', output, "Should show PC marker")

    def test_list_shows_source_not_no_mapping(self):
        """Test that list never shows 'No source location' for valid code"""
        self.console.onecmd('load examples/riscv/hello_asm/hello_asm')

        # Step through several instructions and verify list always works
        for i in range(10):
            self.clear_output()
            self.console.onecmd('list')
            output = self.get_output()

            # Should NOT show "No source location" error
            self.assertNotIn('No source location', output,
                f"Step {i}: list should show source, not 'No source location'")

            self.console.onecmd('step')


if __name__ == "__main__":
    unittest.main()
