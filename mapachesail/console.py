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
        """Load a RISC-V ELF file: load <filename>

        Example:
            load examples/fibonacci/fibonacci
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
        """Execute N instructions (default 1): step [n]

        Examples:
            step       # Execute 1 instruction
            step 5     # Execute 5 instructions
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
        """Run until halt or max instructions: run [max]

        Examples:
            run        # Run until program halts
            run 1000   # Run max 1000 instructions
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
        """Continue execution until next breakpoint or halt

        Same as 'run' but typically used after hitting a breakpoint.
        """
        self.do_run('')

    def do_reset(self, arg):
        """Reset the simulator to initial state"""
        self.sim.reset()
        print('Simulator reset.')
        if self.loaded_file:
            print('Program still loaded. Use "load" to reload if needed.')

    # --- State Inspection ---

    def do_regs(self, arg):
        """Display all registers

        Shows all 32 RISC-V registers plus PC in a formatted display.
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
        """Display program counter"""
        pc = self.sim.get_pc()
        print(f'pc = {pc:#018x}')

    def do_mem(self, arg):
        """Display memory contents: mem <address> [length]

        Examples:
            mem 0x80000000         # Display 256 bytes from address
            mem 0x80000000 64      # Display 64 bytes from address
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

    # --- Breakpoints ---

    def do_break(self, arg):
        """Set a breakpoint at address: break <address>

        Example:
            break 0x80000010
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
        """Show information: info breakpoints

        Currently supports:
            info breakpoints - List all breakpoints
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
        """Delete breakpoint at address: delete <address>

        Example:
            delete 0x80000010
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
        """Clear all breakpoints"""
        self.breakpoints.clear()
        print('All breakpoints cleared.')

    # --- Utility Commands ---

    def do_status(self, arg):
        """Show simulator status"""
        print(f'\nLoaded file: {self.loaded_file or "None"}')
        if self.loaded_file:
            pc = self.sim.get_pc()
            print(f'PC: {pc:#018x}')
        print(f'Breakpoints: {len(self.breakpoints)}')
        print()

    def do_quit(self, arg):
        """Exit the console"""
        print('Goodbye!')
        return True

    def do_exit(self, arg):
        """Exit the console"""
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
