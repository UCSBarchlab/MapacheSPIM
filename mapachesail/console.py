#!/usr/bin/env python3
"""
MapacheSail Interactive Console

A SPIM-like interactive console for RISC-V programs using the Sail formal specification.
"""

import cmd
import signal
import sys
import math
from pathlib import Path

from .sail_backend import SailSimulator, StepResult


def _chunk_list(lst, n):
    """Chunk a list into sublists of length n."""
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


class MapacheSailConsole(cmd.Cmd):
    """
    Interactive console for stepping through RISC-V programs.

    Provides SPIM-like interface with commands for loading ELF files,
    stepping through execution, examining registers and memory.
    """

    intro = 'Welcome to MapacheSail. Type help or ? to list commands.\n'
    prompt = '(mapachesail) '

    # RISC-V ABI register names
    RISCV_ABI_NAMES = [
        'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
        's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
        'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
        's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'
    ]

    def __init__(self, verbose=True):
        super().__init__()
        self._verbose = verbose
        self.sim = None
        self.loaded_file = None
        self.breakpoints = set()
        self._interrupted = False
        self._running = False

        # Set up signal handler for Ctrl-C
        signal.signal(signal.SIGINT, self._handler_sigint)

        # Initialize simulator
        self._initialize_simulator()

    def _initialize_simulator(self):
        """Initialize or reset the simulator"""
        try:
            self.sim = SailSimulator()
            self.print_verbose('Sail RISC-V simulator initialized.')
        except Exception as e:
            print(f'Error initializing simulator: {e}')
            sys.exit(1)

    def _handler_sigint(self, signum, frame):
        """Handle Ctrl-C interrupts"""
        self._interrupted = True
        print()
        if not self._running:
            print('Use "quit" or "exit" to exit.')

    def print_verbose(self, *args, **kwargs):
        """Print only if verbose mode is enabled"""
        if self._verbose:
            print(*args, **kwargs)

    def print_error(self, msg):
        """Print an error message"""
        print(f'\n{msg}\n')

    # --- File Loading ---

    def do_load(self, arg):
        """Load a RISC-V ELF file

        Usage:
            load <filename>

        Loads a compiled RISC-V ELF executable into the simulator.
        The program counter is set to the entry point and all
        breakpoints are cleared.

        Examples:
            load examples/fibonacci/fibonacci
            load examples/test_simple/simple
            load /path/to/my_program

        After loading, use 'pc' to see the entry point address.
        """
        if not arg:
            self.print_error('Error: Please specify an ELF file to load.')
            return

        filepath = Path(arg)
        if not filepath.exists():
            self.print_error(f'Error: File "{arg}" not found.')
            return

        try:
            self.sim.load_elf(str(filepath))
            self.loaded_file = str(filepath)
            pc = self.sim.get_pc()
            print(f'✓ Loaded {filepath}')
            print(f'Entry point: {pc:#018x}')
            self.breakpoints.clear()
        except Exception as e:
            self.print_error(f'Error loading ELF file: {e}')

    # --- Execution Control ---

    def do_step(self, arg):
        """Execute one or more instructions

        Usage:
            step [n]

        Executes n instructions (default 1) and displays the program
        counter for each step. If a breakpoint is hit, execution stops.

        Arguments:
            n - Number of instructions to execute (optional, default=1)

        Aliases:
            s - Short alias for step

        Examples:
            step            # Execute 1 instruction
            step 5          # Execute 5 instructions
            s 10            # Execute 10 instructions (using alias)

        Tips:
            - Use 'step 1' to carefully trace through code
            - Use 'step 10' to quickly skip over known-good code
            - After stepping, use 'regs' to see register changes
            - Set breakpoints before stepping to stop at key locations
        """
        if not self.loaded_file:
            self.print_error('Error: No program loaded. Use "load <file>" first.')
            return

        n_steps = 1
        if arg:
            try:
                n_steps = int(arg)
                if n_steps <= 0:
                    self.print_error('Error: Number of steps must be positive.')
                    return
            except ValueError:
                self.print_error(f'Error: Invalid number "{arg}".')
                return

        # Execute instructions
        for i in range(n_steps):
            pc = self.sim.get_pc()

            # Check for breakpoint
            if pc in self.breakpoints:
                print(f'Breakpoint hit at {pc:#018x}')
                break

            result = self.sim.step()

            if result == StepResult.HALT:
                print(f'[{pc:#018x}] Program halted')
                break
            elif result == StepResult.ERROR:
                print(f'[{pc:#018x}] Execution error')
                break

            # For single step, show the PC that was executed
            if n_steps == 1:
                print(f'[{pc:#018x}] Executed 1 instruction')

        # For multiple steps, show range
        if n_steps > 1 and i > 0:
            print(f'Executed {i+1} instruction(s)')

    def do_run(self, arg):
        """Run program until halt or maximum instructions

        Usage:
            run [max]

        Executes instructions continuously until the program halts,
        a breakpoint is hit, or the maximum instruction count is reached.
        Press Ctrl-C to interrupt execution.

        Arguments:
            max - Maximum number of instructions (optional, default=unlimited)

        Aliases:
            r - Short alias for run

        Examples:
            run             # Run until program halts or breakpoint
            run 1000        # Run maximum 1000 instructions
            r 100           # Run max 100 instructions (using alias)

        Tips:
            - Set breakpoints before running to stop at specific addresses
            - Use 'run 1000' to limit execution if program might loop
            - Press Ctrl-C to interrupt a running program
            - After running, use 'pc' and 'regs' to inspect state
            - Use 'continue' to resume after hitting a breakpoint
        """
        if not self.loaded_file:
            self.print_error('Error: No program loaded. Use "load <file>" first.')
            return

        max_steps = 0  # 0 means unlimited
        if arg:
            try:
                max_steps = int(arg)
                if max_steps <= 0:
                    self.print_error('Error: Max steps must be positive.')
                    return
            except ValueError:
                self.print_error(f'Error: Invalid number "{arg}".')
                return

        # Run with breakpoint/interrupt checking
        self._running = True
        self._interrupted = False
        steps_executed = 0

        try:
            while max_steps == 0 or steps_executed < max_steps:
                # Check for interrupt
                if self._interrupted:
                    self._interrupted = False
                    print(f'Interrupted after {steps_executed} instructions')
                    break

                # Check for breakpoint
                pc = self.sim.get_pc()
                if pc in self.breakpoints:
                    print(f'Breakpoint hit at {pc:#018x} after {steps_executed} instructions')
                    break

                result = self.sim.step()
                steps_executed += 1

                if result == StepResult.HALT:
                    print(f'Program halted after {steps_executed} instructions')
                    break
                elif result == StepResult.ERROR:
                    print(f'Execution error at {pc:#018x} after {steps_executed} instructions')
                    break
        finally:
            self._running = False

        if not self._interrupted and steps_executed > 0:
            final_pc = self.sim.get_pc()
            if max_steps > 0 and steps_executed >= max_steps:
                print(f'Executed {steps_executed} instructions (max limit reached)')
            print(f'PC = {final_pc:#018x}')

    def do_continue(self, arg):
        """Continue execution after hitting a breakpoint

        Usage:
            continue

        Resumes execution from the current PC until the program halts,
        another breakpoint is hit, or you interrupt with Ctrl-C.
        Functionally equivalent to 'run' but semantically used to
        resume after stopping at a breakpoint.

        Aliases:
            c - Short alias for continue

        Examples:
            break 0x80000010        # Set a breakpoint
            run                     # Run until breakpoint
            regs                    # Inspect state
            continue                # Resume execution
            c                       # Using alias

        Tips:
            - Same as 'run' but clearer intent when resuming
            - Press Ctrl-C to interrupt execution
            - Use 'step' for finer control after breakpoint
        """
        self.do_run('')

    def do_reset(self, arg):
        """Reset the simulator to initial state

        Usage:
            reset

        Resets the simulator state, clearing all register values and
        resetting the program counter. The loaded program remains in
        memory but you may need to reload it to reset the entry point.

        Examples:
            load examples/test_simple/simple
            step 5                  # Execute some instructions
            reset                   # Reset simulator state
            load examples/test_simple/simple  # Reload to restore entry point

        Tips:
            - Breakpoints are preserved (use 'clear' to remove them)
            - Memory contents may be preserved (depends on Sail backend)
            - Usually better to reload the file for a clean state
            - Use to recover from error states
        """
        self.sim.reset()
        print('Simulator reset.')
        if self.loaded_file:
            print('Program still loaded. Use "load" to reload if needed.')

    # --- State Inspection ---

    def do_regs(self, arg):
        """Display all RISC-V registers

        Usage:
            regs

        Shows all 32 general-purpose registers (x0-x31) with both
        numeric names and ABI names, plus the program counter (PC).
        Values are displayed in hexadecimal.

        Register ABI Names:
            x0  = zero (hard-wired 0)    x16-17 = a6-a7 (args)
            x1  = ra (return addr)       x18-27 = s2-s11 (saved)
            x2  = sp (stack pointer)     x28-31 = t3-t6 (temps)
            x3  = gp (global pointer)
            x4  = tp (thread pointer)
            x5-7   = t0-t2 (temps)
            x8     = s0/fp (saved/frame)
            x9     = s1 (saved)
            x10-11 = a0-a1 (args/return)
            x12-15 = a2-a5 (args)

        Examples:
            regs                # Show all registers
            step                # Execute an instruction
            regs                # See what changed

        Tips:
            - Use after 'step' to see register changes
            - a0-a7 (x10-x17) hold function arguments/return values
            - sp (x2) is the stack pointer
            - ra (x1) holds the return address
            - x0 is always 0 (hard-wired)
        """
        print()
        regs = self.sim.get_all_regs()
        pc = self.sim.get_pc()

        # Format registers in 4 columns
        reg_lines = []
        for i in range(0, 32, 4):
            line_parts = []
            for j in range(4):
                if i + j < 32:
                    reg_num = i + j
                    abi_name = self.RISCV_ABI_NAMES[reg_num]
                    value = regs[reg_num]
                    line_parts.append(f'x{reg_num:<2} ({abi_name:>4}) = {value:#018x}')
            reg_lines.append('  '.join(line_parts))

        for line in reg_lines:
            print(line)

        print(f'\npc                 = {pc:#018x}')
        print()

    def do_pc(self, arg):
        """Display program counter

        Usage:
            pc

        Shows the current value of the program counter (PC), which
        points to the next instruction to be executed.

        Examples:
            pc              # Show current PC
            step            # Execute one instruction
            pc              # See new PC value

        Tips:
            - PC increments by 4 for each instruction (32-bit encoding)
            - Jump/branch instructions change PC non-sequentially
            - Use 'mem <pc_value>' to see instructions at PC
        """
        pc = self.sim.get_pc()
        print(f'pc = {pc:#018x}')

    def do_mem(self, arg):
        """Display memory contents in hex dump format

        Usage:
            mem <address> [length]

        Displays memory contents starting at the given address in
        hexadecimal format, grouped by 4-byte words. Default length
        is 256 bytes if not specified.

        Arguments:
            address - Memory address in hex (0x...) or decimal
            length  - Number of bytes to display (optional, default=256)

        Examples:
            mem 0x80000000          # Show 256 bytes from 0x80000000
            mem 0x80000000 64       # Show 64 bytes
            mem 0x80000000 16       # Show just 16 bytes (4 words)

        Common Addresses:
            0x80000000 - Typical code (.text) segment start
            0x83eff000 - Near stack area
            pc         - Use 'pc' command first to find current PC

        Tips:
            - Use to examine code bytes at PC
            - Check stack contents around SP
            - Verify data was written correctly
            - Each line shows 16 bytes (4 words of 4 bytes each)
        """
        if not arg:
            self.print_error('Error: Please specify an address (e.g., "mem 0x80000000").')
            return

        parts = arg.split()

        # Parse address
        try:
            addr = int(parts[0], 0)  # Auto-detect base (0x for hex, etc.)
        except ValueError:
            self.print_error(f'Error: Invalid address "{parts[0]}".')
            return

        # Parse length (default 256 bytes)
        length = 256
        if len(parts) > 1:
            try:
                length = int(parts[1], 0)
                if length <= 0:
                    self.print_error('Error: Length must be positive.')
                    return
            except ValueError:
                self.print_error(f'Error: Invalid length "{parts[1]}".')
                return

        # Read and display memory
        try:
            data = self.sim.read_mem(addr, length)
            self._print_memory(addr, data)
        except Exception as e:
            self.print_error(f'Error reading memory: {e}')

    def _print_memory(self, start_addr, data, width=16):
        """Pretty-print memory contents in hex dump format"""
        print()
        for offset in range(0, len(data), width):
            addr = start_addr + offset
            row = data[offset:offset+width]

            # Format bytes in groups of 4
            hex_bytes = [f'{b:02x}' for b in row]
            hex_groups = [' '.join(chunk) for chunk in _chunk_list(hex_bytes, 4)]
            hex_row = '  '.join(hex_groups)

            print(f'{addr:#010x}:  {hex_row}')
        print()

    def do_disasm(self, arg):
        """Disassemble instructions at address

        Usage:
            disasm <address> [count]

        Disassembles instructions starting at the given address.
        Default count is 10 instructions if not specified.

        Arguments:
            address - Memory address in hex (0x...) or decimal
            count   - Number of instructions to disassemble (optional, default=10)

        Aliases:
            d - Short alias for disasm

        Examples:
            disasm 0x80000000           # Disassemble 10 instructions
            disasm 0x80000000 5         # Disassemble 5 instructions
            d 0x80000000                # Using alias
            pc                          # Get current PC
            disasm 0x80000000 20        # Disassemble from entry

        Tips:
            - Use 'pc' to find current program counter
            - Each RISC-V instruction is 4 bytes (some compressed are 2)
            - Addresses should be 4-byte aligned
            - Use 'mem <addr>' to see raw instruction bytes
        """
        if not arg:
            self.print_error('Error: Please specify an address (e.g., "disasm 0x80000000").')
            return

        parts = arg.split()

        # Parse address
        try:
            addr = int(parts[0], 0)
        except ValueError:
            self.print_error(f'Error: Invalid address "{parts[0]}".')
            return

        # Parse count (default 10)
        count = 10
        if len(parts) > 1:
            try:
                count = int(parts[1], 0)
                if count <= 0:
                    self.print_error('Error: Count must be positive.')
                    return
            except ValueError:
                self.print_error(f'Error: Invalid count "{parts[1]}".')
                return

        # Disassemble instructions
        print()
        for i in range(count):
            try:
                instr_addr = addr + (i * 4)
                disasm = self.sim.disasm(instr_addr)
                print(f'[{instr_addr:#010x}]  {disasm}')
            except Exception as e:
                print(f'[{instr_addr:#010x}]  <error: {e}>')
                break
        print()

    # --- Breakpoints ---

    def do_break(self, arg):
        """Set a breakpoint at an address

        Usage:
            break <address>

        Sets a breakpoint at the specified address. When running or
        stepping, execution will stop if the PC reaches this address.

        Arguments:
            address - Memory address in hex (0x...) or decimal

        Aliases:
            b - Short alias for break

        Examples:
            break 0x80000010        # Set breakpoint at address
            b 0x8000001c            # Using alias
            run                     # Will stop at breakpoint
            info breakpoints        # List all breakpoints

        Tips:
            - Use 'info breakpoints' to see all set breakpoints
            - Use 'delete <address>' to remove a specific breakpoint
            - Use 'clear' to remove all breakpoints
            - Breakpoints stop execution before the instruction executes
            - Set breakpoints before running to stop at key locations
        """
        if not arg:
            self.print_error('Error: Please specify an address.')
            return

        try:
            addr = int(arg, 0)
            self.breakpoints.add(addr)
            print(f'Breakpoint set at {addr:#018x}')
        except ValueError:
            self.print_error(f'Error: Invalid address "{arg}".')

    def do_info(self, arg):
        """Show information about simulator state

        Usage:
            info breakpoints

        Displays information about the current simulator state.
        Currently supports viewing all set breakpoints.

        Arguments:
            breakpoints - List all set breakpoints (can abbreviate as 'break')

        Examples:
            info breakpoints        # List all breakpoints
            info break              # Same, abbreviated
            break 0x80000010        # Set a breakpoint
            info breakpoints        # See it in the list

        Tips:
            - Shows breakpoints sorted by address
            - Each breakpoint is numbered for reference
            - Use 'delete <address>' to remove specific breakpoints
        """
        if arg == 'breakpoints' or arg == 'break':
            if not self.breakpoints:
                print('No breakpoints set.')
            else:
                print('\nBreakpoints:')
                for i, addr in enumerate(sorted(self.breakpoints), 1):
                    print(f'  {i}. {addr:#018x}')
                print()
        else:
            self.print_error('Usage: info breakpoints')

    def do_delete(self, arg):
        """Delete a specific breakpoint

        Usage:
            delete <address>

        Removes the breakpoint at the specified address. If no
        breakpoint exists at that address, a message is displayed.

        Arguments:
            address - Memory address in hex (0x...) or decimal

        Examples:
            break 0x80000010        # Set a breakpoint
            info breakpoints        # Verify it's set
            delete 0x80000010       # Remove the breakpoint
            info breakpoints        # Confirm it's gone

        Tips:
            - Use 'info breakpoints' to see all addresses with breakpoints
            - Use 'clear' to remove all breakpoints at once
            - Address must match exactly (including 0x prefix if used)
        """
        if not arg:
            self.print_error('Error: Please specify an address.')
            return

        try:
            addr = int(arg, 0)
            if addr in self.breakpoints:
                self.breakpoints.remove(addr)
                print(f'Breakpoint removed at {addr:#018x}')
            else:
                print(f'No breakpoint at {addr:#018x}')
        except ValueError:
            self.print_error(f'Error: Invalid address "{arg}".')

    def do_clear(self, arg):
        """Clear all breakpoints

        Usage:
            clear

        Removes all breakpoints that have been set. Use this when you
        want to start fresh without any breakpoints.

        Examples:
            break 0x80000010        # Set breakpoint 1
            break 0x80000020        # Set breakpoint 2
            info breakpoints        # See both
            clear                   # Remove all
            info breakpoints        # None remain

        Tips:
            - Use 'delete <address>' to remove a specific breakpoint
            - Breakpoints are also cleared when loading a new file
            - No confirmation is required (immediate effect)
        """
        self.breakpoints.clear()
        print('All breakpoints cleared.')

    # --- Utility Commands ---

    def do_status(self, arg):
        """Show current simulator status

        Usage:
            status

        Displays an overview of the simulator's current state including
        the loaded file, program counter, and number of breakpoints.

        Examples:
            status                  # Show current status
            load examples/test_simple/simple
            status                  # See loaded file and PC
            break 0x80000010
            status                  # See breakpoint count

        Tips:
            - Quick way to see what's loaded and where you are
            - Shows PC only if a file is loaded
            - Use 'info breakpoints' for detailed breakpoint list
            - Use 'regs' for full register state
        """
        print(f'\nLoaded file: {self.loaded_file or "None"}')
        if self.loaded_file:
            pc = self.sim.get_pc()
            print(f'PC: {pc:#018x}')
        print(f'Breakpoints: {len(self.breakpoints)}')
        print()

    def do_quit(self, arg):
        """Exit the console

        Usage:
            quit

        Exits the MapacheSail console and returns to the shell.

        Aliases:
            exit - Same as quit
            q    - Short alias for quit
            Ctrl-D (EOF) - Also exits

        Examples:
            quit        # Exit the console
            exit        # Same
            q           # Using short alias

        Tips:
            - Press Ctrl-D for quick exit
            - Simulator state is not saved
            - No confirmation required
        """
        print('Goodbye!')
        return True

    def do_exit(self, arg):
        """Exit the console (same as quit)"""
        return self.do_quit(arg)

    def do_EOF(self, arg):
        """Exit on EOF (Ctrl-D)"""
        print()
        return self.do_quit(arg)

    # --- Aliases ---
    do_q = do_quit
    do_r = do_run
    do_s = do_step
    do_c = do_continue
    do_b = do_break
    do_d = do_disasm


def main():
    """Entry point for the console"""
    import argparse

    parser = argparse.ArgumentParser(
        description='MapacheSail - Interactive RISC-V Simulator using Sail'
    )
    parser.add_argument(
        'file',
        nargs='?',
        help='ELF file to load on startup'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (less verbose)'
    )

    args = parser.parse_args()

    # Create console
    console = MapacheSailConsole(verbose=not args.quiet)

    # Auto-load file if provided
    if args.file:
        console.onecmd(f'load {args.file}')

    # Start interactive loop
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print('\nGoodbye!')


if __name__ == '__main__':
    main()
