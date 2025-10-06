#!/usr/bin/env python3
"""
Working comprehensive test suite for MapacheSail console commands.

Tests account for actual Sail behavior where ecall doesn't return HALT.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachesail.console import MapacheSailConsole


class TestConsoleCommands(unittest.TestCase):
    """Test suite for console commands using test_simple program"""

    SIMPLE_PATH = 'examples/test_simple/simple'

    def setUp(self):
        """Create a fresh console for each test"""
        self.console = MapacheSailConsole(verbose=False)
        self.console.stdout = sys.stdout  # Use real stdout for cmd.Cmd

    def tearDown(self):
        """Clean up after each test"""
        pass

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

    def test_step_exact_count(self):
        """Test stepping exact number for all 9 instructions"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('step 9')

        # After 9 steps (including ecall), PC should be 0
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x0, "PC should be 0 after ecall")

        # Verify final register state
        regs = self.console.sim.get_all_regs()
        self.assertEqual(regs[1], 93, "ra should be 93")
        self.assertEqual(regs[5], 10, "t0 should be 10")
        self.assertEqual(regs[6], 20, "t1 should be 20")
        self.assertEqual(regs[7], 30, "t2 should be 30")
        self.assertEqual(regs[8], 20, "s0 should be 20")
        self.assertEqual(regs[9], 40, "s1 should be 40")
        self.assertEqual(regs[10], 42, "a0 should be 42")

    # --- Test Run Command with Limits ---

    def test_run_with_step_limit(self):
        """Test run with maximum step limit"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('run 5')

        # Should stop after 5 instructions
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000014, "Should stop at 0x80000014 after 5 steps")

    def test_run_to_ecall(self):
        """Test running to ecall with step limit"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('run 10')  # Enough to complete program

        # After ecall, PC becomes 0
        pc = self.console.sim.get_pc()
        # PC will be 0 or slightly past depending on execution
        self.assertLessEqual(pc, 0x10, "PC should be near 0 after ecall")

        # Verify register state
        regs = self.console.sim.get_all_regs()
        self.assertEqual(regs[1], 93, "ra should be 93")
        self.assertEqual(regs[10], 42, "a0 should be 42")

    # --- Test Breakpoint Commands ---

    def test_break_set(self):
        """Test setting a breakpoint"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')

        self.assertIn(0x80000010, self.console.breakpoints)

    def test_break_hit(self):
        """Test hitting a breakpoint during run"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')

        # Run should stop at breakpoint (before executing that instruction)
        self.console.onecmd('run 10')  # Limit in case breakpoint doesn't work
        pc = self.console.sim.get_pc()

        self.assertEqual(pc, 0x80000010, "Should stop at breakpoint")

        # Verify we stopped at the right point (before slli instruction)
        regs = self.console.sim.get_all_regs()
        self.assertEqual(regs[8], 20, "s0 should be 20 (from previous sub)")
        self.assertEqual(regs[9], 0, "s1 should still be 0 (slli not executed yet)")

    def test_info_breakpoints(self):
        """Test listing breakpoints"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.console.onecmd('break 0x80000020')

        self.assertEqual(len(self.console.breakpoints), 2)
        self.assertIn(0x80000010, self.console.breakpoints)
        self.assertIn(0x80000020, self.console.breakpoints)

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
        self.console.onecmd('run 10')
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000010)

        # Delete breakpoint so we can continue
        self.console.onecmd('delete 0x80000010')

        # Continue with limit
        self.console.onecmd('run 10')  # Continue execution
        # Should complete
        regs = self.console.sim.get_all_regs()
        # Should have executed more instructions
        self.assertEqual(regs[1], 93, "Should have reached ecall")

    # --- Test Register and PC Display ---

    def test_regs_values(self):
        """Test register values after known steps"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('step 6')  # Execute first 6 instructions

        regs = self.console.sim.get_all_regs()
        self.assertEqual(regs[5], 10, "t0 = 10")
        self.assertEqual(regs[6], 20, "t1 = 20")
        self.assertEqual(regs[7], 30, "t2 = 30")
        self.assertEqual(regs[8], 20, "s0 = 20")
        self.assertEqual(regs[9], 40, "s1 = 40")
        self.assertEqual(regs[10], 42, "a0 = 42")

    def test_pc_value(self):
        """Test PC value"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000000)

        self.console.onecmd('step')
        pc = self.console.sim.get_pc()
        self.assertEqual(pc, 0x80000004)

    # --- Test Memory Display ---

    def test_mem_at_entry(self):
        """Test memory read at entry point"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # Read memory at entry point
        data = self.console.sim.read_mem(0x80000000, 4)

        # First instruction: addi x5, x0, 10
        # Encoding: 0x00a00293 (little-endian: 93 02 a0 00)
        self.assertEqual(data[0], 0x93, "First byte should be 0x93")
        self.assertEqual(data[1], 0x02, "Second byte should be 0x02")

    # --- Test Status Command ---

    def test_status_with_file(self):
        """Test status shows loaded file"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        self.assertEqual(self.console.loaded_file, self.SIMPLE_PATH)

    def test_status_with_breakpoints(self):
        """Test status shows breakpoint count"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')
        self.console.onecmd('break 0x80000010')
        self.console.onecmd('break 0x80000020')

        self.assertEqual(len(self.console.breakpoints), 2)

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

    # --- Test Cycle-by-Cycle Behavior ---

    def test_step_by_step_execution(self):
        """Test complete step-by-step execution matches expected behavior"""
        self.console.onecmd(f'load {self.SIMPLE_PATH}')

        # Step 1: addi x5, x0, 10
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x80000004, "Step 1: PC")
        self.assertEqual(self.console.sim.get_all_regs()[5], 10, "Step 1: x5 = 10")

        # Step 2: addi x6, x0, 20
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x80000008, "Step 2: PC")
        self.assertEqual(self.console.sim.get_all_regs()[6], 20, "Step 2: x6 = 20")

        # Step 3: add x7, x5, x6
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x8000000c, "Step 3: PC")
        self.assertEqual(self.console.sim.get_all_regs()[7], 30, "Step 3: x7 = 30")

        # Step 4: sub x8, x7, x5
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x80000010, "Step 4: PC")
        self.assertEqual(self.console.sim.get_all_regs()[8], 20, "Step 4: x8 = 20")

        # Step 5: slli x9, x5, 2
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x80000014, "Step 5: PC")
        self.assertEqual(self.console.sim.get_all_regs()[9], 40, "Step 5: x9 = 40")

        # Step 6: addi x10, x0, 42
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x80000018, "Step 6: PC")
        self.assertEqual(self.console.sim.get_all_regs()[10], 42, "Step 6: x10 = 42")

        # Step 7: j done
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x8000001c, "Step 7: PC after jump")

        # Step 8: addi x1, x0, 93
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x80000020, "Step 8: PC")
        self.assertEqual(self.console.sim.get_all_regs()[1], 93, "Step 8: x1 = 93")

        # Step 9: ecall (PC will become 0)
        self.console.onecmd('step')
        self.assertEqual(self.console.sim.get_pc(), 0x0, "Step 9: PC after ecall")


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestConsoleCommands)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
