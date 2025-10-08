#!/usr/bin/env python3
"""
MapacheSPIM Interactive Console

A SPIM-like interactive console for RISC-V programs using the Sail formal specification.
"""

import cmd
import signal
import sys
import math
from pathlib import Path

from .sail_backend import SailSimulator, StepResult

try:
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.descriptions import describe_form_class
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False


class SourceInfo:
    """Cached source code information from DWARF debug info"""

    def __init__(self):
        self.addr_to_line = {}  # address -> (filename, line_number)
        self.source_cache = {}  # filename -> list of source lines
        self.has_debug_info = False

    def get_location(self, addr):
        """Get source location for an address. Returns (filename, line_num) or None"""
        return self.addr_to_line.get(addr)

    def get_source_lines(self, filename, start_line, count=10):
        """Get source lines from cached file. Returns list of (line_num, text)"""
        if filename not in self.source_cache:
            return None

        lines = self.source_cache[filename]
        result = []

        # Adjust to 0-indexed
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), start_idx + count)

        for i in range(start_idx, end_idx):
            result.append((i + 1, lines[i]))

        return result


def _parse_dwarf_line_info(elf_path):
    """Parse DWARF debug info and return SourceInfo object"""
    source_info = SourceInfo()

    if not ELFTOOLS_AVAILABLE:
        return source_info

    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)

            if not elf.has_dwarf_info():
                return source_info

            dwarf_info = elf.get_dwarf_info()
            source_info.has_debug_info = True

            # Parse line programs from all compilation units
            for CU in dwarf_info.iter_CUs():
                line_program = dwarf_info.line_program_for_CU(CU)
                if not line_program:
                    continue

                # Get file entry table
                file_entries = line_program['file_entry']

                # Version-specific delta for file indexing
                if line_program['version'] < 5:
                    delta = 1
                else:
                    delta = 0

                # Iterate through line program entries
                prev_state = None
                for entry in line_program.get_entries():
                    if entry.state is None:
                        continue

                    state = entry.state
                    if not state.end_sequence:
                        # Map this address to source location
                        if state.file > 0 and state.file <= len(file_entries) + delta:
                            file_entry = file_entries[state.file - delta]
                            filename = file_entry.name.decode('utf-8') if isinstance(file_entry.name, bytes) else file_entry.name

                            # Store mapping
                            source_info.addr_to_line[state.address] = (filename, state.line)

                            # Cache source file content if not already cached
                            if filename not in source_info.source_cache:
                                _load_source_file(source_info, filename, elf_path)

                    prev_state = state

            return source_info

    except Exception as e:
        # If DWARF parsing fails, just return empty source info
        return source_info


def _load_source_file(source_info, filename, elf_path):
    """Try to load source file contents into cache"""
    # Try to find source file relative to ELF location
    elf_dir = Path(elf_path).parent

    # Try multiple search paths
    search_paths = [
        Path(filename),  # Absolute or relative to CWD
        elf_dir / filename,  # Relative to ELF
        elf_dir / Path(filename).name,  # Just filename in ELF dir
    ]

    for path in search_paths:
        try:
            if path.exists() and path.is_file():
                with open(path, 'r') as f:
                    source_info.source_cache[filename] = f.read().splitlines()
                return
        except Exception:
            continue

    # If we couldn't find the file, store empty list
    source_info.source_cache[filename] = []


def _chunk_list(lst, n):
    """Chunk a list into sublists of length n."""
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


class MapacheSPIMConsole(cmd.Cmd):
    """
    Interactive console for stepping through RISC-V programs.

    Provides SPIM-like interface with commands for loading ELF files,
    stepping through execution, examining registers and memory.
    """

    intro = 'Welcome to MapacheSPIM. Type help or ? to list commands.\n'
    prompt = '(mapachespim) '

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

        # Register change tracking
        self.show_reg_changes = True
        self.prev_regs = None

        # Source code information (DWARF debug info)
        self.source_info = SourceInfo()

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

            # Parse DWARF debug information
            self.source_info = _parse_dwarf_line_info(str(filepath))
            if self.source_info.has_debug_info:
                num_files = len(self.source_info.source_cache)
                if num_files > 0:
                    file_list = ', '.join(self.source_info.source_cache.keys())
                    print(f'Source info: {file_list} ({len(self.source_info.addr_to_line)} address mappings)')
                else:
                    print('Debug info present but source files not found')
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

            # Get instruction before executing (for display)
            try:
                instr_disasm = self.sim.disasm(pc)
                instr_bytes = self.sim.read_mem(pc, 4)
                instr_hex = ''.join(f'{b:02x}' for b in instr_bytes)
            except Exception:
                instr_disasm = "<error>"
                instr_hex = "????????"

            # Snapshot registers before execution (only for single step with tracking enabled)
            prev_regs = None
            if self.show_reg_changes and n_steps == 1:
                prev_regs = self.sim.get_all_regs()

            result = self.sim.step()

            if result == StepResult.HALT:
                print(f'[{pc:#010x}]  0x{instr_hex}  {instr_disasm}')
                print(f'Program halted')
                break
            elif result == StepResult.ERROR:
                print(f'[{pc:#010x}]  0x{instr_hex}  {instr_disasm}')
                print(f'Execution error')
                break

            # Show the instruction that was executed
            # Try to show symbol name
            sym, offset = self.sim.addr_to_symbol(pc)
            if sym and offset == 0:
                print(f'[{pc:#010x}] 0x{instr_hex}  {instr_disasm}  <{sym}>')
            elif sym:
                print(f'[{pc:#010x}] 0x{instr_hex}  {instr_disasm}  <{sym}+{offset}>')
            else:
                print(f'[{pc:#010x}] 0x{instr_hex}  {instr_disasm}')

            # Show register changes (only for single step)
            if prev_regs is not None and n_steps == 1:
                curr_regs = self.sim.get_all_regs()
                changed = []
                for reg_num in range(32):
                    if prev_regs[reg_num] != curr_regs[reg_num]:
                        abi = self.RISCV_ABI_NAMES[reg_num]
                        changed.append((reg_num, abi, prev_regs[reg_num], curr_regs[reg_num]))

                if changed:
                    print('Register changes:')
                    for reg_num, abi, old_val, new_val in changed:
                        print(f'  x{reg_num:<2} ({abi:>4}) : {old_val:#018x} → {new_val:#018x}  ★')

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

                # Check for termination using centralized logic
                should_terminate, reason = self.sim.check_termination(result)
                if should_terminate:
                    # Print appropriate termination message
                    if reason == 'syscall_exit':
                        print(f'Program exited via syscall after {steps_executed} instructions')
                    elif reason == 'halt':
                        print(f'Program halted after {steps_executed} instructions')
                    elif reason == 'error':
                        print(f'Execution error at {pc:#018x} after {steps_executed} instructions')
                    elif reason == 'tohost':
                        print(f'Program completed (tohost) after {steps_executed} instructions')
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
            mem <address|section> [length]

        Displays memory contents starting at the given address or section
        in hexadecimal format with ASCII sidebar. Default length is 256
        bytes if not specified.

        Arguments:
            address - Memory address in hex (0x...) or decimal
            section - ELF section name (e.g., .text, .data, .rodata)
            length  - Number of bytes to display (optional, default=256)

        Examples:
            mem 0x80000000          # Show 256 bytes from address
            mem .data               # Show .data section
            mem .rodata             # Show read-only data section
            mem 0x80000000 64       # Show 64 bytes

        Common Sections:
            .text   - Executable code
            .data   - Initialized data
            .rodata - Read-only data (strings, constants)
            .bss    - Uninitialized data

        Tips:
            - Use 'info sections' to see all available sections
            - ASCII sidebar helps spot strings in data
            - Each line shows 16 bytes with hex and ASCII
            - Section names are shortcuts to their addresses
        """
        if not arg:
            self.print_error('Error: Please specify an address or section (e.g., "mem 0x80000000" or "mem .data").')
            return

        parts = arg.split()
        addr_or_section = parts[0]

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

        # Check if it's a section name (starts with .)
        if addr_or_section.startswith('.'):
            if not ELFTOOLS_AVAILABLE:
                self.print_error('Error: pyelftools not available. Install with: pip install pyelftools')
                return

            if not self.loaded_file:
                self.print_error('Error: No program loaded.')
                return

            # Look up section
            try:
                with open(self.loaded_file, 'rb') as f:
                    elf = ELFFile(f)
                    section = elf.get_section_by_name(addr_or_section)
                    if not section:
                        self.print_error(f'Error: Section "{addr_or_section}" not found. Use "info sections" to see available sections.')
                        return

                    addr = section['sh_addr']
                    section_size = section['sh_size']

                    if addr == 0:
                        self.print_error(f'Error: Section "{addr_or_section}" is not loaded in memory (address is 0).')
                        return

                    # Limit length to section size if not specified
                    if len(parts) == 1:  # No length given
                        length = min(length, section_size)

            except Exception as e:
                self.print_error(f'Error reading section: {e}')
                return
        else:
            # Parse as address
            try:
                addr = int(addr_or_section, 0)  # Auto-detect base (0x for hex, etc.)
            except ValueError:
                self.print_error(f'Error: Invalid address "{addr_or_section}".')
                return

        # Read and display memory
        try:
            data = self.sim.read_mem(addr, length)
            self._print_memory(addr, data)
        except Exception as e:
            self.print_error(f'Error reading memory: {e}')

    def _print_memory(self, start_addr, data, width=16):
        """Pretty-print memory contents in hex dump format with ASCII sidebar"""
        print()
        for offset in range(0, len(data), width):
            addr = start_addr + offset
            row = data[offset:offset+width]

            # Format bytes in groups of 4
            hex_bytes = [f'{b:02x}' for b in row]
            hex_groups = [' '.join(chunk) for chunk in _chunk_list(hex_bytes, 4)]
            hex_row = '  '.join(hex_groups)

            # ASCII sidebar - show printable chars, '.' for non-printable
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)

            # Pad hex if row is incomplete
            if len(row) < width:
                # Calculate padding needed
                missing_bytes = width - len(row)
                hex_row += '   ' * missing_bytes  # 3 chars per missing byte
                if missing_bytes >= 4:  # Account for group separator
                    hex_row += '  ' * (missing_bytes // 4)

            print(f'{addr:#010x}:  {hex_row}  |{ascii_str}|')
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

    def do_list(self, arg):
        """Display source code from assembly file

        Usage:
            list [location]

        Shows source code around the current PC or specified location.
        Requires the program to be compiled with debug symbols (-g flag).

        Arguments:
            location - Optional line number, function name, or blank for PC

        Aliases:
            l - Short alias for list

        Examples:
            list            # Show source around current PC
            list main       # Show source around 'main' function
            list 25         # Show source around line 25
            l               # Using alias

        Tips:
            - Compile with 'as -g' to include debug symbols
            - Source file must be in same directory as ELF file
            - Shows 10 lines by default
            - Current PC is marked with '# <-- PC: 0xXXXXXXXX'
        """
        if not self.loaded_file:
            self.print_error('Error: No program loaded. Use "load <file>" first.')
            return

        if not ELFTOOLS_AVAILABLE:
            self.print_error('Error: pyelftools not available.')
            return

        if not self.source_info.has_debug_info:
            print()
            print('No source information available.')
            print('Compile your program with debug symbols (use -g flag):')
            print('  as -g -o program.o program.s')
            print('  ld -o program program.o')
            print()
            return

        # Determine what to show
        pc = self.sim.get_pc()

        if arg:
            # User specified a location
            # Try to parse as line number first
            try:
                line_num = int(arg)
                # Find first file in cache
                if self.source_info.source_cache:
                    filename = list(self.source_info.source_cache.keys())[0]
                    self._show_source_lines(filename, line_num, pc, center=True)
                else:
                    print('No source files available.')
                return
            except ValueError:
                # Not a number, try as function name
                # Look up function in symbol table
                func_addr = self.sim.lookup_symbol(arg)
                if func_addr is not None:
                    location = self.source_info.get_location(func_addr)
                    if location:
                        filename, line_num = location
                        self._show_source_lines(filename, line_num, pc, center=True)
                    else:
                        print(f'No source location found for function "{arg}".')
                else:
                    print(f'Function "{arg}" not found.')
                return
        else:
            # Show around current PC
            location = self.source_info.get_location(pc)
            if location:
                filename, line_num = location
                self._show_source_lines(filename, line_num, pc, center=True)
            else:
                print(f'No source location for current PC ({pc:#010x}).')
                print('Try stepping to an instruction with debug info.')

    def _show_source_lines(self, filename, center_line, current_pc, center=True, count=10):
        """Helper to display source lines with PC marker"""
        if center:
            # Show lines centered around center_line
            start_line = max(1, center_line - count // 2)
        else:
            start_line = center_line

        lines = self.source_info.get_source_lines(filename, start_line, count)

        if not lines:
            print(f'Source file "{filename}" not available.')
            return

        print()
        print(f'{filename}:')

        # Find which line corresponds to current PC (if any)
        pc_line = None
        pc_location = self.source_info.get_location(current_pc)
        if pc_location and pc_location[0] == filename:
            pc_line = pc_location[1]

        for line_num, text in lines:
            # Mark current PC line
            if line_num == pc_line:
                print(f'{line_num:5d}: {text}  # <-- PC: {current_pc:#010x}')
            else:
                print(f'{line_num:5d}: {text}')

        print()

    do_l = do_list  # Alias

    # --- Breakpoints ---

    def do_break(self, arg):
        """Set a breakpoint at an address or symbol

        Usage:
            break <address|symbol>

        Sets a breakpoint at the specified address or symbol name.
        When running or stepping, execution will stop if the PC
        reaches this address.

        Arguments:
            address - Memory address in hex (0x...) or decimal
            symbol  - Function or label name from symbol table

        Aliases:
            b - Short alias for break

        Examples:
            break 0x80000010        # Set breakpoint at address
            break main              # Set breakpoint at 'main' function
            b fibonacci             # Using alias with symbol
            run                     # Will stop at breakpoint
            info breakpoints        # List all breakpoints

        Tips:
            - Use 'info symbols' to see available symbol names
            - Use 'info breakpoints' to see all set breakpoints
            - Use 'delete <address>' to remove a specific breakpoint
            - Use 'clear' to remove all breakpoints
            - Breakpoints stop execution before the instruction executes
            - Set breakpoints before running to stop at key locations
        """
        if not arg:
            self.print_error('Error: Please specify an address or symbol name.')
            return

        # First try to look up as symbol name
        if self.loaded_file:
            addr = self.sim.lookup_symbol(arg)
            if addr is not None:
                self.breakpoints.add(addr)
                print(f'Breakpoint set at {arg} ({addr:#010x})')
                return

        # If not a symbol, try to parse as address
        try:
            addr = int(arg, 0)
            self.breakpoints.add(addr)
            print(f'Breakpoint set at {addr:#010x}')
        except ValueError:
            self.print_error(f'Error: "{arg}" is not a valid address or known symbol.')

    def do_info(self, arg):
        """Show information about simulator state

        Usage:
            info breakpoints
            info symbols
            info sections

        Displays information about the current simulator state.
        Supports viewing breakpoints, symbol table, and ELF sections.

        Arguments:
            breakpoints - List all set breakpoints (can abbreviate as 'break')
            symbols     - List all symbols from symbol table (can abbreviate as 'sym')
            sections    - List all ELF sections (can abbreviate as 'sec')

        Examples:
            info breakpoints        # List all breakpoints
            info break              # Same, abbreviated
            info symbols            # List all symbols
            info sym                # Same, abbreviated
            info sections           # List all ELF sections
            info sec                # Same, abbreviated

        Tips:
            - Shows breakpoints sorted by address
            - Symbols are listed with their addresses
            - Sections show address, size, and type
            - Use section names with 'mem' (e.g., mem .data)
            - Each breakpoint is numbered for reference
        """
        if arg == 'breakpoints' or arg == 'break':
            if not self.breakpoints:
                print('No breakpoints set.')
            else:
                print('\nBreakpoints:')
                for i, addr in enumerate(sorted(self.breakpoints), 1):
                    # Try to show symbol name if available
                    sym, offset = self.sim.addr_to_symbol(addr)
                    if sym and offset == 0:
                        print(f'  {i}. {addr:#010x}  <{sym}>')
                    elif sym:
                        print(f'  {i}. {addr:#010x}  <{sym}+{offset}>')
                    else:
                        print(f'  {i}. {addr:#010x}')
                print()
        elif arg == 'symbols' or arg == 'sym':
            if not self.loaded_file:
                print('No program loaded.')
                return

            symbols = self.sim.get_symbols()
            if not symbols:
                print('No symbols available.')
                return

            print(f'\nSymbols ({len(symbols)} total):')

            # Sort by address
            sorted_symbols = sorted(symbols.items(), key=lambda x: x[1])

            for name, addr in sorted_symbols:
                print(f'  {addr:#010x}  {name}')
            print()
        elif arg == 'sections' or arg == 'sec':
            if not self.loaded_file:
                print('No program loaded.')
                return

            if not ELFTOOLS_AVAILABLE:
                self.print_error('Error: pyelftools not available. Install with: pip install pyelftools')
                return

            try:
                with open(self.loaded_file, 'rb') as f:
                    elf = ELFFile(f)

                    print()
                    print(f"ELF Sections:")
                    print(f"{'Name':<20} {'Address':>18} {'Size':>12}  {'Flags'}")
                    print("-" * 70)

                    for section in elf.iter_sections():
                        name = section.name
                        addr = section['sh_addr']
                        size = section['sh_size']
                        flags = section['sh_flags']

                        # Decode flags
                        flag_str = ""
                        if flags & 0x1:  # SHF_WRITE
                            flag_str += "W"
                        if flags & 0x2:  # SHF_ALLOC
                            flag_str += "A"
                        if flags & 0x4:  # SHF_EXECINSTR
                            flag_str += "X"

                        # Only show allocated sections (those loaded in memory)
                        if addr > 0:
                            print(f"{name:<20} {addr:#18x} {size:>12}  {flag_str}")

                    print()
                    print("Flags: W=Write, A=Alloc, X=Execute")
                    print("Use 'mem <section>' to view section contents (e.g., mem .data)")
                    print()

            except Exception as e:
                self.print_error(f'Error reading ELF sections: {e}')
        else:
            self.print_error('Usage: info [breakpoints|symbols|sections]')

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

    def do_set(self, arg):
        """Configure console options

        Usage:
            set <option> <value>
            set                    # Show all current settings

        Options:
            show-changes  [on|off]  - Show register changes after each step

        Examples:
            set                     # Show current settings
            set show-changes on     # Enable register change display
            set show-changes off    # Disable register change display

        Tips:
            - Register changes only shown for single steps
            - Use 'regs' command to manually check registers
        """
        if not arg:
            # Show all settings
            print()
            print('Current settings:')
            print(f'  show-changes : {"on" if self.show_reg_changes else "off"}')
            print()
            return

        parts = arg.split()
        if len(parts) != 2:
            self.print_error('Error: Usage: set <option> <value>')
            return

        option, value = parts[0].lower(), parts[1].lower()

        if option == 'show-changes':
            if value in ('on', 'true', '1', 'yes'):
                self.show_reg_changes = True
                print('Register change display enabled')
            elif value in ('off', 'false', '0', 'no'):
                self.show_reg_changes = False
                print('Register change display disabled')
            else:
                self.print_error('Error: Value must be on or off')
        else:
            self.print_error(f'Error: Unknown option "{option}"')

    def do_quit(self, arg):
        """Exit the console

        Usage:
            quit

        Exits the MapacheSPIM console and returns to the shell.

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
        description='MapacheSPIM - Interactive RISC-V Simulator using Sail'
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
    console = MapacheSPIMConsole(verbose=not args.quiet)

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
