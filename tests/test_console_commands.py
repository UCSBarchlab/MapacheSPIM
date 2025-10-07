#!/usr/bin/env python3
"""
Comprehensive test suite for MapacheSail console commands.

Tests all console commands using the test_simple program with known
cycle-by-cycle behavior documented in examples/test_simple/EXPECTED_BEHAVIOR.md
"""

import sys
import unittest
from pathlib import Path
from io import StringIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim.console import MapacheSPIMConsole
from mapachespim.sail_backend import StepResult


class TestConsoleCommands(unittest.TestCase):
    """Test suite for console commands using test_simple program"""

    SIMPLE_PATH = 'examples/test_simple/simple'

    # Expected register values from EXPECTED_BEHAVIOR.md
    EXPECTED_FINAL_REGS = {
        0: 0x00000000,  # zero
        1: 0x0000005d,  # ra = 93
        5: 0x0000000a,  # t0 = 10
        6: 0x00000014,  # t1 = 20
        7: 0x0000001e,  # t2 = 30
        8: 0x00000014,  # s0 = 20
        9: 0x00000028,  # s1 = 40
        10: 0x0000002a, # a0 = 42
    }

    def setUp(self):
        """Create a fresh console for each test"""
        # Suppress verbose output during tests
        self.console = MapacheSPIMConsole(verbose=False)
        self.console.stdout = StringIO()  # Capture output

    def tearDown(self):
        """Clean up after each test"""
        if hasattr(self.console, 'stdout'):
            self.console.stdout.close()

    def get_output(self):
        """Get captured console output"""
        return self.console.stdout.getvalue()

    def clear_output(self):
        """Clear captured output"""
        self.console.stdout = StringIO()

    # --- Test Load Command ---

    def test_load_valid_file(self):
        """Test loading a valid ELF file"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.assertEqual(self.console.loaded_file, self.SIMPLE_PATH)

        # Verify entry point is set correctly
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000000, "Entry point should be 0x80000000")

    def test_load_nonexistent_file(self):
        """Test loading a file that doesn't exist"""
        self.console.onecmd('load /nonexistent/file')
        self.assertIsNone(self.console.loaded_file)

    def test_load_clears_breakpoints(self):
        """Test that loading a new file clears breakpoints"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.assertEqual(len(self.console.breakpoints), 1)

        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.assertEqual(len(self.console.breakpoints), 0)

    # --- Test Step Command ---

    def test_step_single(self):
        """Test single step execution"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # Step 1: li t0, 10
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()

        self.assertEqual(pc, 0x80000004, "PC should advance to 0x80000004")
        self.assertEqual(regs[5], 10, "x5 (t0) should be 10")

    def test_step_multiple(self):
        """Test stepping multiple instructions"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # Step 3 times
        self.console.onecmd('step 3')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()

        self.assertEqual(pc, 0x8000000c, "PC should be at 0x8000000c")
        self.assertEqual(regs[5], 10, "x5 (t0) should be 10")
        self.assertEqual(regs[6], 20, "x6 (t1) should be 20")
        self.assertEqual(regs[7], 30, "x7 (t2) should be 30")

    def test_step_through_jump(self):
        """Test stepping through a jump instruction"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # Step to the jump instruction (step 7)
        self.console.onecmd('step 7')
        pc = self.console.sim.get_pc()

        # After jump, should be at done label (0x8000001c)
        self.assertEqual(pc, 0x8000001c, "PC should jump to 0x8000001c")

    def test_step_invalid_count(self):
        """Test step with invalid count"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # Try negative step
        output_before = self.get_output()
        self.console.onecmd('step -1')
        output = self.get_output()
        self.assertIn('Error', output, "Should show error for negative step")

    # --- Test Run Command ---

    def test_run_to_completion(self):
        """Test running program to completion"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('run')

        # Program should halt after 9 instructions
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()

        # Verify final register state matches expected
        self.assertEqual(regs[1], 93, "ra should be 93")
        self.assertEqual(regs[5], 10, "t0 should be 10")
        self.assertEqual(regs[6], 20, "t1 should be 20")
        self.assertEqual(regs[7], 30, "t2 should be 30")
        self.assertEqual(regs[8], 20, "s0 should be 20")
        self.assertEqual(regs[9], 40, "s1 should be 40")
        self.assertEqual(regs[10], 42, "a0 should be 42")

    def test_run_with_max_steps(self):
        """Test run with maximum step limit"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('run 5')

        # Should stop after 5 instructions
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000014, "Should stop at 0x80000014 after 5 steps")

    # --- Test Breakpoint Commands ---

    def test_break_set_and_hit(self):
        """Test setting and hitting a breakpoint"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')

        self.assertIn(0x80000010, self.console.breakpoints)

        # Run should stop at breakpoint
        self.console.onecmd('run')
        pc = self.console.sim.get_pc()

        self.assertEqual(pc, 0x80000010, "Should stop at breakpoint")

    def test_info_breakpoints(self):
        """Test listing breakpoints"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.console.onecmd('break 0x80000020')

        self.clear_output()
        self.console.onecmd('info breakpoints')
        output = self.get_output()

        self.assertIn('0x80000010', output)
        self.assertIn('0x80000020', output)

    def test_delete_breakpoint(self):
        """Test deleting a specific breakpoint"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.console.onecmd('break 0x80000020')

        self.assertEqual(len(self.console.breakpoints), 2)

        self.console.onecmd('delete 0x80000010')
        self.assertEqual(len(self.console.breakpoints), 1)
        self.assertNotIn(0x80000010, self.console.breakpoints)
        self.assertIn(0x80000020, self.console.breakpoints)

    def test_clear_all_breakpoints(self):
        """Test clearing all breakpoints"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.console.onecmd('break 0x80000020')
        self.console.onecmd('break 0x80000030')

        self.assertEqual(len(self.console.breakpoints), 3)

        self.console.onecmd('clear')
        self.assertEqual(len(self.console.breakpoints), 0)

    # --- Test Continue Command ---

    def test_continue_after_breakpoint(self):
        """Test continue command after hitting a breakpoint"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')

        # Run to first breakpoint
        self.console.onecmd('run')
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000010)

        # Continue should resume execution
        self.console.onecmd('continue')
        # Program should complete
        regs = self.console.sim.get_all_regs()
        self.assertEqual(regs[1], 93, "Should complete with ra=93")

    # --- Test Register Display ---

    def test_regs_display(self):
        """Test register display command"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('step 6')  # Execute first 6 instructions

        self.clear_output()
        self.console.onecmd('regs')
        output = self.get_output()

        # Check that register values are displayed
        self.assertIn('x5', output)
        self.assertIn('t0', output)
        self.assertIn('0x0000000a', output)  # t0 = 10

    def test_pc_display(self):
        """Test PC display command"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.clear_output()
        self.console.onecmd('pc')
        output = self.get_output()

        self.assertIn('0x80000000', output.lower())

    # --- Test Memory Display ---

    def test_mem_display(self):
        """Test memory display command"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.clear_output()
        self.console.onecmd('mem 0x80000000 32')
        output = self.get_output()

        # Should show memory contents at entry point
        self.assertIn('0x80000000', output.lower())

        # First instruction bytes (little-endian): 93 02 a0 00
        # This is the encoding of: addi x5, x0, 10
        self.assertIn('93', output)

    def test_mem_invalid_address(self):
        """Test memory display with invalid address"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.clear_output()
        self.console.onecmd('mem invalid_addr')
        output = self.get_output()

        self.assertIn('Error', output)

    # --- Test Reset Command ---

    def test_reset(self):
        """Test reset command"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('step 5')

        # Verify we've advanced
        pc_before = self.console.sim.get_pc()
        self.assertNotEqual(pc_before, 0x80000000)

        # Reset
        self.console.onecmd('reset')

        # Note: reset behavior may vary - the file is still loaded
        # but state is reset
        self.assertEqual(self.console.loaded_file, self.SIMPLE_PATH)

    # --- Test Status Command ---

    def test_status_no_file(self):
        """Test status with no file loaded"""
        self.clear_output()
        self.console.onecmd('status')
        output = self.get_output()

        self.assertIn('None', output)

    def test_status_with_file(self):
        """Test status with file loaded"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.clear_output()
        self.console.onecmd('status')
        output = self.get_output()

        self.assertIn(self.SIMPLE_PATH, output)
        self.assertIn('0x80000000', output.lower())

    def test_status_with_breakpoints(self):
        """Test status shows breakpoint count"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.console.onecmd('break 0x80000020')

        self.clear_output()
        self.console.onecmd('status')
        output = self.get_output()

        self.assertIn('2', output)

    # --- Test Aliases ---

    def test_step_alias(self):
        """Test 's' alias for step"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('s')

        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000004)

    def test_run_alias(self):
        """Test 'r' alias for run"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('r 5')

        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000014)

    def test_break_alias(self):
        """Test 'b' alias for break"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('b 0x80000010')

        self.assertIn(0x80000010, self.console.breakpoints)

    def test_continue_alias(self):
        """Test 'c' alias for continue"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('b 0x80000010')
        self.console.onecmd('r')

        pc_before = self.console.sim.get_pc()
        self.console.onecmd('c')

        # Should have continued past breakpoint
        regs = self.console.sim.get_all_regs()
        self.assertEqual(regs[1], 93)

    # --- Test Cycle-by-Cycle Behavior ---

    def test_step_by_step_execution(self):
        """Test complete step-by-step execution matches expected behavior"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # Step 1: addi x5, x0, 10
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()
        self.assertEqual(pc, 0x80000004, "Step 1: PC")
        self.assertEqual(regs[5], 10, "Step 1: x5 = 10")

        # Step 2: addi x6, x0, 20
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()
        self.assertEqual(pc, 0x80000008, "Step 2: PC")
        self.assertEqual(regs[6], 20, "Step 2: x6 = 20")

        # Step 3: add x7, x5, x6
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()
        self.assertEqual(pc, 0x8000000c, "Step 3: PC")
        self.assertEqual(regs[7], 30, "Step 3: x7 = 30")

        # Step 4: sub x8, x7, x5
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()
        self.assertEqual(pc, 0x80000010, "Step 4: PC")
        self.assertEqual(regs[8], 20, "Step 4: x8 = 20")

        # Step 5: slli x9, x5, 2
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()
        self.assertEqual(pc, 0x80000014, "Step 5: PC")
        self.assertEqual(regs[9], 40, "Step 5: x9 = 40")

        # Step 6: addi x10, x0, 42
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()
        self.assertEqual(pc, 0x80000018, "Step 6: PC")
        self.assertEqual(regs[10], 42, "Step 6: x10 = 42")

        # Step 7: j done
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x8000001c, "Step 7: PC after jump")

        # Step 8: addi x1, x0, 93
        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        regs = self.console.sim.get_all_regs()
        self.assertEqual(pc, 0x80000020, "Step 8: PC")
        self.assertEqual(regs[1], 93, "Step 8: x1 = 93")

    # --- Test Error Conditions ---

    def test_step_without_load(self):
        """Test stepping without loading a file"""
        self.clear_output()
        self.console.onecmd('step')
        output = self.get_output()

        self.assertIn('Error', output)
        self.assertIn('No program loaded', output)

    def test_run_without_load(self):
        """Test running without loading a file"""
        self.clear_output()
        self.console.onecmd('run')
        output = self.get_output()

        self.assertIn('Error', output)
        self.assertIn('No program loaded', output)

    def test_mem_without_args(self):
        """Test memory display without address"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.clear_output()
        self.console.onecmd('mem')
        output = self.get_output()

        self.assertIn('Error', output)

    def test_break_without_address(self):
        """Test break without address"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.clear_output()
        self.console.onecmd('break')
        output = self.get_output()

        self.assertIn('Error', output)

    def test_delete_without_address(self):
        """Test delete without address"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.clear_output()
        self.console.onecmd('delete')
        output = self.get_output()

        self.assertIn('Error', output)


class TestHelpExamples(unittest.TestCase):
    """Test that examples in help text actually work"""

    SIMPLE_PATH = 'examples/test_simple/simple'

    def setUp(self):
        """Create a fresh console for each test"""
        self.console = MapacheSPIMConsole(verbose=False)
        self.console.stdout = StringIO()

    def tearDown(self):
        """Clean up after each test"""
        if hasattr(self.console, 'stdout'):
            self.console.stdout.close()

    def test_load_example(self):
        """Verify load command example from help text"""
        # From help: load examples/test_simple/simple
        self.console.onecmd('load examples/test_simple/simple')
        self.assertEqual(self.console.loaded_file, 'examples/test_simple/simple')

    def test_step_example(self):
        """Verify step command examples from help text"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # From help: step 5
        self.console.onecmd('step 5')
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000014)

    def test_breakpoint_workflow(self):
        """Verify breakpoint workflow from help examples"""
        # From help: break 0x80000010, run, info breakpoints
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.console.onecmd('run')

        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000010)

    def test_mem_example(self):
        """Verify memory display examples from help text"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # From help: mem 0x80000000 64
        self.console.onecmd('mem 0x80000000 64')
        # Should not error
        output = self.console.stdout.getvalue()
        self.assertNotIn('Error', output)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestConsoleCommands))
    suite.addTests(loader.loadTestsFromTestCase(TestHelpExamples))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
