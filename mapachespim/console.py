#!/usr/bin/env python3
"""
MapacheSPIM Interactive Console

A SPIM-like interactive console for assembly programs using the Unicorn Engine.
Supports RISC-V, ARM64, and x86-64 architectures.
"""

from __future__ import annotations

import cmd
import signal
import sys
from pathlib import Path
from types import FrameType
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

from . import Simulator, StepResult

try:
    from elftools.elf.elffile import ELFFile

    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False


class SourceInfo:
    """Cached source code information from DWARF debug info"""

    addr_to_line: Dict[int, Tuple[str, int]]
    source_cache: Dict[str, List[str]]
    has_debug_info: bool

    def __init__(self) -> None:
        self.addr_to_line = {}  # address -> (filename, line_number)
        self.source_cache = {}  # filename -> list of source lines
        self.has_debug_info = False

    def get_location(self, addr: int) -> Optional[Tuple[str, int]]:
        """Get source location for an address. Returns (filename, line_num) or None"""
        return self.addr_to_line.get(addr)

    def get_source_lines(
        self, filename: str, start_line: int, count: int = 10
    ) -> Optional[List[Tuple[int, str]]]:
        """Get source lines from cached file. Returns list of (line_num, text)"""
        if filename not in self.source_cache:
            return None

        lines = self.source_cache[filename]
        result: List[Tuple[int, str]] = []

        # Adjust to 0-indexed
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), start_idx + count)

        for i in range(start_idx, end_idx):
            result.append((i + 1, lines[i]))

        return result


def _parse_dwarf_line_info(elf_path: str) -> SourceInfo:
    """Parse DWARF debug info and return SourceInfo object"""
    source_info = SourceInfo()

    if not ELFTOOLS_AVAILABLE:
        return source_info

    try:
        with open(elf_path, "rb") as f:
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
                file_entries = line_program["file_entry"]

                # Version-specific delta for file indexing
                if line_program["version"] < 5:
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
                            filename = (
                                file_entry.name.decode("utf-8")
                                if isinstance(file_entry.name, bytes)
                                else file_entry.name
                            )

                            # Store mapping
                            source_info.addr_to_line[state.address] = (filename, state.line)

                            # Cache source file content if not already cached
                            if filename not in source_info.source_cache:
                                _load_source_file(source_info, filename, elf_path)

                    prev_state = state

            return source_info

    except Exception:
        # If DWARF parsing fails, just return empty source info
        return source_info


def _load_source_file(source_info: SourceInfo, filename: str, elf_path: str) -> None:
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
                with open(path) as f:
                    source_info.source_cache[filename] = f.read().splitlines()
                return
        except Exception:
            continue

    # If we couldn't find the file, store empty list
    source_info.source_cache[filename] = []


def _chunk_list(lst: List[Any], n: int) -> Generator[List[Any], None, None]:
    """Chunk a list into sublists of length n."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


class MapacheSPIMConsole(cmd.Cmd):
    """
    Interactive console for stepping through assembly programs.

    Provides SPIM-like interface with commands for loading ELF files,
    stepping through execution, examining registers and memory.
    Supports multiple ISAs: RISC-V, ARM64, and x86-64.
    """

    intro: str = "Welcome to MapacheSPIM. Type help or ? to list commands.\n"
    prompt: str = "(mapachespim) "

    _verbose: bool
    sim: Optional[Simulator]
    loaded_file: Optional[str]
    breakpoints: Set[int]
    _interrupted: bool
    _running: bool
    show_reg_changes: bool
    prev_regs: Optional[List[int]]
    regs_base: str
    regs_leading_zeros: str
    source_info: SourceInfo

    _ALIASES: Dict[str, str]

    def __init__(self, verbose: bool = False) -> None:
        super().__init__()
        self._verbose = verbose

        # Configure readline to not treat / as a word delimiter
        # This allows tab completion to work properly with file paths
        try:
            import readline

            # Remove / from delimiters so paths complete correctly
            delims = readline.get_completer_delims()
            readline.set_completer_delims(delims.replace("/", ""))
        except ImportError:
            pass  # readline not available on all platforms

        self.sim = None
        self.loaded_file = None
        self.breakpoints = set()
        self._interrupted = False
        self._running = False

        # Register change tracking
        self.show_reg_changes = True
        self.prev_regs = None

        # Register display options
        self.regs_base = "hex"  # hex, decimal, or binary
        self.regs_leading_zeros = "default"  # default, show, cut, or dot

        # Source code information (DWARF debug info)
        self.source_info = SourceInfo()

        # Set up signal handler for Ctrl-C
        signal.signal(signal.SIGINT, self._handler_sigint)

        # Initialize simulator
        self._initialize_simulator()

    def _initialize_simulator(self) -> None:
        """Initialize or reset the simulator"""
        try:
            self.sim = Simulator()
            self.print_verbose("Unicorn Engine simulator initialized.")
        except Exception as e:
            print(f"Error initializing simulator: {e}", file=self.stdout)
            sys.exit(1)

    def _handler_sigint(self, signum: int, frame: Optional[FrameType]) -> None:
        """Handle Ctrl-C interrupts"""
        self._interrupted = True
        print(file=self.stdout)
        if not self._running:
            print('Use "quit" or "exit" to exit.', file=self.stdout)

    def print_verbose(self, *args: Any, **kwargs: Any) -> None:
        """Print only if verbose mode is enabled"""
        if self._verbose:
            print(*args, **kwargs, file=self.stdout)

    def print_error(self, msg: str) -> None:
        """Print an error message"""
        print(f"\n{msg}\n", file=self.stdout)

    # --- File Loading ---

    def do_load(self, arg: str) -> None:
        """Load an ELF file

        Usage:
            load <filename>

        Loads a compiled ELF executable into the simulator. The ISA is
        auto-detected from the ELF file (RISC-V, ARM64, or x86-64).
        The program counter is set to the entry point and all
        breakpoints are cleared.

        Examples:
            load examples/riscv/fibonacci/fibonacci
            load examples/arm/test_simple/simple
            load examples/x86_64/test_simple/simple

        After loading, use 'status' to see the ISA and entry point.
        """
        if not arg:
            self.print_error("Error: Please specify an ELF file to load.")
            return

        filepath = Path(arg)
        if not filepath.exists():
            self.print_error(f'Error: File "{arg}" not found.')
            return

        try:
            self.sim.load_elf(str(filepath))
            self.loaded_file = str(filepath)
            pc = self.sim.get_pc()
            isa_name = self.sim.get_isa_name()
            print(f"Loaded {filepath} ({isa_name})", file=self.stdout)
            print(f"Entry point: {pc:#018x}", file=self.stdout)
            self.breakpoints.clear()

            # Parse DWARF debug information
            self.source_info = _parse_dwarf_line_info(str(filepath))
            if self.source_info.has_debug_info:
                num_files = len(self.source_info.source_cache)
                if num_files > 0:
                    file_list = ", ".join(self.source_info.source_cache.keys())
                    print(
                        f"Source info: {file_list} ({len(self.source_info.addr_to_line)} address mappings)",
                        file=self.stdout,
                    )
                else:
                    print("Debug info present but source files not found", file=self.stdout)
        except Exception as e:
            self.print_error(f"Error loading ELF file: {e}")

    # --- Execution Control ---

    def do_step(self, arg: str) -> None:
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
                    self.print_error("Error: Number of steps must be positive.")
                    return
            except ValueError:
                self.print_error(f'Error: Invalid number "{arg}".')
                return

        # Execute instructions
        for i in range(n_steps):
            pc = self.sim.get_pc()

            # Check for breakpoint (but skip if this is the first step and we're already at a breakpoint)
            if i > 0 and pc in self.breakpoints:
                print(f"Breakpoint hit at {pc:#018x}", file=self.stdout)
                break

            # Get instruction before executing (for display)
            try:
                instr_disasm = self.sim.disasm(pc)
                instr_bytes = self.sim.read_mem(pc, 4)
                instr_hex = "".join(f"{b:02x}" for b in instr_bytes)
            except Exception:
                instr_disasm = "<error>"
                instr_hex = "????????"

            # Snapshot registers before execution (for tracking changes)
            prev_regs = self.sim.get_all_regs()

            result = self.sim.step()

            if result == StepResult.HALT:
                print(f"[{pc:#010x}]  0x{instr_hex}  {instr_disasm}", file=self.stdout)
                print("Program halted", file=self.stdout)
                # Update prev_regs even on halt
                self.prev_regs = prev_regs
                break
            elif result == StepResult.ERROR:
                print(f"[{pc:#010x}]  0x{instr_hex}  {instr_disasm}", file=self.stdout)
                print("Execution error", file=self.stdout)
                # Update prev_regs even on error
                self.prev_regs = prev_regs
                break

            # Show the instruction that was executed
            # Try to show symbol name
            sym, offset = self.sim.addr_to_symbol(pc)
            if sym and offset == 0:
                print(f"[{pc:#010x}] 0x{instr_hex}  {instr_disasm}  <{sym}>", file=self.stdout)
            elif sym:
                print(
                    f"[{pc:#010x}] 0x{instr_hex}  {instr_disasm}  <{sym}+{offset}>",
                    file=self.stdout,
                )
            else:
                print(f"[{pc:#010x}] 0x{instr_hex}  {instr_disasm}", file=self.stdout)

            # Store prev_regs for the regs command to show changes
            self.prev_regs = prev_regs

    def do_stepreg(self, arg: str) -> None:
        """Execute instructions and show registers

        Usage:
            stepreg [n]

        Executes n instructions (default 1) and then displays all registers.
        This is a convenience command equivalent to running 'step' followed
        by 'regs'. Useful for stepping through code while tracking register
        changes.

        Arguments:
            n - Number of instructions to execute (optional, default=1)

        Aliases:
            sr - Short alias for stepreg

        Examples:
            stepreg         # Execute 1 instruction and show registers
            stepreg 5       # Execute 5 instructions and show registers
            sr              # Using alias

        Tips:
            - Stars (★) mark registers that changed with the last instruction
            - Use 'step' alone if you don't need to see registers each time
            - Combine with breakpoints for efficient debugging workflow
        """
        self.do_step(arg)
        self.do_regs("")

    def do_run(self, arg: str) -> None:
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
                    self.print_error("Error: Max steps must be positive.")
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
                    print(f"Interrupted after {steps_executed} instructions", file=self.stdout)
                    break

                # Check for breakpoint (but skip on first iteration to allow continuing from a breakpoint)
                pc = self.sim.get_pc()
                if steps_executed > 0 and pc in self.breakpoints:
                    print(
                        f"Breakpoint hit at {pc:#018x} after {steps_executed} instructions",
                        file=self.stdout,
                    )
                    break

                result = self.sim.step()
                steps_executed += 1

                # Check for termination using centralized logic
                should_terminate, reason = self.sim.check_termination(result)
                if should_terminate:
                    # Print appropriate termination message
                    if reason == "syscall_exit":
                        print(
                            f"Program exited via syscall after {steps_executed} instructions",
                            file=self.stdout,
                        )
                    elif reason == "halt":
                        print(
                            f"Program halted after {steps_executed} instructions", file=self.stdout
                        )
                    elif reason == "error":
                        print(
                            f"Execution error at {pc:#018x} after {steps_executed} instructions",
                            file=self.stdout,
                        )
                    elif reason == "tohost":
                        print(
                            f"Program completed (tohost) after {steps_executed} instructions",
                            file=self.stdout,
                        )
                    break
        finally:
            self._running = False

        if not self._interrupted and steps_executed > 0:
            final_pc = self.sim.get_pc()
            if max_steps > 0 and steps_executed >= max_steps:
                print(
                    f"Executed {steps_executed} instructions (max limit reached)", file=self.stdout
                )
            print(f"PC = {final_pc:#018x}", file=self.stdout)

    def do_continue(self, arg: str) -> None:
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
        self.do_run("")

    def do_reset(self, arg: str) -> None:
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
            - Memory contents may be preserved (depends on simulator state)
            - Usually better to reload the file for a clean state
            - Use to recover from error states
        """
        self.sim.reset()
        print("Simulator reset.", file=self.stdout)
        if self.loaded_file:
            print('Program still loaded. Use "load" to reload if needed.', file=self.stdout)

    # --- State Inspection ---

    def _format_reg_value(self, value: int, show_mode: str, leading_zeros_mode: str) -> str:
        """Format a register value according to display settings"""
        if show_mode == "hex":
            # Format as hex with 0x prefix
            formatted = f"{value:016x}"
            prefix = "0x"
        elif show_mode == "decimal":
            # Format as decimal (max 20 digits for 64-bit)
            formatted = f"{value:020d}"
            prefix = ""
        elif show_mode == "binary":
            # Format as binary with 0b prefix
            formatted = f"{value:064b}"
            prefix = "0b"
        else:
            formatted = f"{value:016x}"
            prefix = "0x"

        # Handle 'default' mode: show for hex/binary, dot for decimal
        resolved_mode = leading_zeros_mode
        if leading_zeros_mode == "default":
            if show_mode == "decimal":
                resolved_mode = "dot"
            else:
                resolved_mode = "show"

        # Apply leading zeros mode
        if resolved_mode == "cut":
            # Strip leading zeros but keep at least one digit
            formatted = formatted.lstrip("0") or "0"
        elif resolved_mode == "dot":
            # Replace leading zeros with dots
            stripped = formatted.lstrip("0") or "0"
            num_leading = len(formatted) - len(stripped)
            formatted = "." * num_leading + stripped

        return prefix + formatted

    def do_regs(self, arg: str) -> None:
        """Display all registers

        Usage:
            regs [options]

        Shows all general-purpose registers with their ABI names plus the
        program counter (PC). Register count and names vary by ISA:
          - RISC-V: 32 registers (x0-x31)
          - ARM64:  32 registers (x0-x30, sp)
          - x86-64: 16 registers (rax, rcx, rdx, etc.)

        Display format can be controlled with arguments or 'set' command.

        Options (override current settings for this call only):
            hex      - Show values in hexadecimal
            decimal  - Show values in decimal
            binary   - Show values in binary
            default  - Use default leading zeros (show for hex/binary, dot for decimal)
            show     - Show all leading zeros
            cut      - Remove leading zeros
            dot      - Replace leading zeros with dots

        Examples:
            regs                # Show all registers (default format)
            regs decimal        # Show in decimal (temporary)
            regs binary cut     # Show in binary without leading zeros
            regs dot            # Use dots for leading zeros
            step                # Execute an instruction
            regs                # See what changed (★ marks changes)

        Tips:
            - Use 'set regs-base' to change default format globally
            - Use 'set regs-leading-zeros' to change leading zero display
            - Stars (★) mark registers that changed with last instruction
            - Use 'status' to see current ISA
        """
        # Parse arguments for temporary overrides
        show_mode = self.regs_base
        leading_zeros_mode = self.regs_leading_zeros

        if arg:
            parts = arg.split()
            for part in parts:
                part_lower = part.lower()
                if part_lower in ("hex", "decimal", "binary"):
                    show_mode = part_lower
                elif part_lower in ("default", "show", "cut", "dot"):
                    leading_zeros_mode = part_lower
                else:
                    self.print_error(
                        f'Error: Unknown option "{part}". Use: hex, decimal, binary, default, show, cut, or dot'
                    )
                    return

        print(file=self.stdout)
        regs = self.sim.get_all_regs()
        pc = self.sim.get_pc()

        # Determine the width needed for values based on format
        if show_mode == "hex":
            value_width = 18  # 0x + 16 hex digits
        elif show_mode == "decimal":
            value_width = 20  # max 20 decimal digits for 64-bit
        elif show_mode == "binary":
            value_width = 66  # 0b + 64 binary digits
        else:
            value_width = 18

        # Format registers in 2 columns (or 1 if binary is too wide)
        cols = 1 if show_mode == "binary" else 2
        num_regs = self.sim.get_register_count()
        isa = self.sim.get_isa()

        # Determine register display format based on ISA
        from . import ISA

        use_x_prefix = isa in (ISA.RISCV, ISA.ARM)

        reg_lines = []
        for i in range(0, num_regs, cols):
            line_parts = []
            for j in range(cols):
                if i + j < num_regs:
                    reg_num = i + j
                    abi_name = self.sim.get_reg_name(reg_num)
                    value = regs[reg_num]

                    # Format the value
                    formatted_value = self._format_reg_value(value, show_mode, leading_zeros_mode)

                    # Check if this register changed with the last instruction
                    star = (
                        " ★ "
                        if (
                            self.prev_regs is not None
                            and reg_num < len(self.prev_regs)
                            and self.prev_regs[reg_num] != value
                        )
                        else "   "
                    )

                    # Format register name based on ISA
                    if use_x_prefix:
                        line_parts.append(
                            f"x{reg_num:<2} ({abi_name:>4}) = {formatted_value:<{value_width}}{star}"
                        )
                    else:
                        # x86-64: just show the register name (no x prefix)
                        line_parts.append(f"{abi_name:>3} = {formatted_value:<{value_width}}{star}")
            reg_lines.append(" ".join(line_parts))

        for line in reg_lines:
            print(line, file=self.stdout)

        # Format PC
        formatted_pc = self._format_reg_value(pc, show_mode, leading_zeros_mode)
        print(f"\npc = {formatted_pc}", file=self.stdout)
        print(file=self.stdout)

    def do_pc(self, arg: str) -> None:
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
        print(f"pc = {pc:#018x}", file=self.stdout)

    def do_mem(self, arg: str) -> None:
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
            self.print_error(
                'Error: Please specify an address or section (e.g., "mem 0x80000000" or "mem .data").'
            )
            return

        parts = arg.split()
        addr_or_section = parts[0]

        # Parse length (default 256 bytes)
        length = 256
        if len(parts) > 1:
            try:
                length = int(parts[1], 0)
                if length <= 0:
                    self.print_error("Error: Length must be positive.")
                    return
            except ValueError:
                self.print_error(f'Error: Invalid length "{parts[1]}".')
                return

        # Check if it's a section name (starts with .)
        if addr_or_section.startswith("."):
            if not ELFTOOLS_AVAILABLE:
                self.print_error(
                    "Error: pyelftools not available. Install with: pip install pyelftools"
                )
                return

            if not self.loaded_file:
                self.print_error("Error: No program loaded.")
                return

            # Look up section
            try:
                with open(self.loaded_file, "rb") as f:
                    elf = ELFFile(f)
                    section = elf.get_section_by_name(addr_or_section)
                    if not section:
                        self.print_error(
                            f'Error: Section "{addr_or_section}" not found. Use "info sections" to see available sections.'
                        )
                        return

                    addr = section["sh_addr"]
                    section_size = section["sh_size"]

                    if addr == 0:
                        self.print_error(
                            f'Error: Section "{addr_or_section}" is not loaded in memory (address is 0).'
                        )
                        return

                    # Limit length to section size if not specified
                    if len(parts) == 1:  # No length given
                        length = min(length, section_size)

            except Exception as e:
                self.print_error(f"Error reading section: {e}")
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
            self.print_error(f"Error reading memory: {e}")

    def _print_memory(self, start_addr: int, data: bytes, width: int = 16) -> None:
        """Pretty-print memory contents in hex dump format with ASCII sidebar"""
        print(file=self.stdout)
        for offset in range(0, len(data), width):
            addr = start_addr + offset
            row = data[offset : offset + width]

            # Format bytes in groups of 4
            hex_bytes = [f"{b:02x}" for b in row]
            hex_groups = [" ".join(chunk) for chunk in _chunk_list(hex_bytes, 4)]
            hex_row = "  ".join(hex_groups)

            # ASCII sidebar - show printable chars, '.' for non-printable
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in row)

            # Pad hex if row is incomplete
            if len(row) < width:
                # Calculate padding needed
                missing_bytes = width - len(row)
                hex_row += "   " * missing_bytes  # 3 chars per missing byte
                if missing_bytes >= 4:  # Account for group separator
                    hex_row += "  " * (missing_bytes // 4)

            print(f"{addr:#010x}:  {hex_row}  |{ascii_str}|", file=self.stdout)
        print(file=self.stdout)

    def do_disasm(self, arg: str) -> None:
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
            - Instruction sizes: RISC-V/ARM64 = 4 bytes, x86-64 = variable
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
                    self.print_error("Error: Count must be positive.")
                    return
            except ValueError:
                self.print_error(f'Error: Invalid count "{parts[1]}".')
                return

        # Disassemble instructions
        print(file=self.stdout)
        for i in range(count):
            try:
                instr_addr = addr + (i * 4)
                disasm = self.sim.disasm(instr_addr)
                print(f"[{instr_addr:#010x}]  {disasm}", file=self.stdout)
            except Exception as e:
                print(f"[{instr_addr:#010x}]  <error: {e}>", file=self.stdout)
                break
        print(file=self.stdout)

    def do_list(self, arg: str) -> None:
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
            self.print_error("Error: pyelftools not available.")
            return

        if not self.source_info.has_debug_info:
            print(file=self.stdout)
            print("No source information available.", file=self.stdout)
            print("Compile your program with debug symbols (use -g flag):", file=self.stdout)
            print("  as -g -o program.o program.s", file=self.stdout)
            print("  ld -o program program.o", file=self.stdout)
            print(file=self.stdout)
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
                    print("No source files available.", file=self.stdout)
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
                        print(f'No source location found for function "{arg}".', file=self.stdout)
                else:
                    print(f'Function "{arg}" not found.', file=self.stdout)
                return
        else:
            # Show around current PC
            location = self.source_info.get_location(pc)
            if location:
                filename, line_num = location
                self._show_source_lines(filename, line_num, pc, center=True)
            else:
                print(f"No source location for current PC ({pc:#010x}).", file=self.stdout)
                print("Try stepping to an instruction with debug info.", file=self.stdout)

    def _show_source_lines(
        self, filename: str, center_line: int, current_pc: int, center: bool = True, count: int = 10
    ) -> None:
        """Helper to display source lines with PC marker"""
        if center:
            # Show lines centered around center_line
            start_line = max(1, center_line - count // 2)
        else:
            start_line = center_line

        lines = self.source_info.get_source_lines(filename, start_line, count)

        if not lines:
            print(f'Source file "{filename}" not available.', file=self.stdout)
            return

        print(file=self.stdout)
        print(f"{filename}:", file=self.stdout)

        # Find which line corresponds to current PC (if any)
        pc_line = None
        pc_location = self.source_info.get_location(current_pc)
        if pc_location and pc_location[0] == filename:
            pc_line = pc_location[1]

        for line_num, text in lines:
            # Mark current PC line
            if line_num == pc_line:
                print(f"{line_num:5d}: {text}  # <-- PC: {current_pc:#010x}", file=self.stdout)
            else:
                print(f"{line_num:5d}: {text}", file=self.stdout)

        print(file=self.stdout)

    # --- Breakpoints ---

    def do_break(self, arg: str) -> None:
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
            self.print_error("Error: Please specify an address or symbol name.")
            return

        # First try to look up as symbol name
        if self.loaded_file:
            addr = self.sim.lookup_symbol(arg)
            if addr is not None:
                self.breakpoints.add(addr)
                print(f"Breakpoint set at {arg} ({addr:#010x})", file=self.stdout)
                return

        # If not a symbol, try to parse as address
        try:
            addr = int(arg, 0)
            self.breakpoints.add(addr)
            print(f"Breakpoint set at {addr:#010x}", file=self.stdout)
        except ValueError:
            self.print_error(f'Error: "{arg}" is not a valid address or known symbol.')

    def do_info(self, arg: str) -> None:
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
        if arg == "breakpoints" or arg == "break":
            if not self.breakpoints:
                print("No breakpoints set.", file=self.stdout)
            else:
                print("\nBreakpoints:", file=self.stdout)
                for i, addr in enumerate(sorted(self.breakpoints), 1):
                    # Try to show symbol name if available
                    sym, offset = self.sim.addr_to_symbol(addr)
                    if sym and offset == 0:
                        print(f"  {i}. {addr:#010x}  <{sym}>", file=self.stdout)
                    elif sym:
                        print(f"  {i}. {addr:#010x}  <{sym}+{offset}>", file=self.stdout)
                    else:
                        print(f"  {i}. {addr:#010x}", file=self.stdout)
                print(file=self.stdout)
        elif arg == "symbols" or arg == "sym":
            if not self.loaded_file:
                print("No program loaded.", file=self.stdout)
                return

            symbols = self.sim.get_symbols()
            if not symbols:
                print("No symbols available.", file=self.stdout)
                return

            print(f"\nSymbols ({len(symbols)} total):", file=self.stdout)

            # Sort by address
            sorted_symbols = sorted(symbols.items(), key=lambda x: x[1])

            for name, addr in sorted_symbols:
                print(f"  {addr:#010x}  {name}", file=self.stdout)
            print(file=self.stdout)
        elif arg == "sections" or arg == "sec":
            if not self.loaded_file:
                print("No program loaded.", file=self.stdout)
                return

            if not ELFTOOLS_AVAILABLE:
                self.print_error(
                    "Error: pyelftools not available. Install with: pip install pyelftools"
                )
                return

            try:
                with open(self.loaded_file, "rb") as f:
                    elf = ELFFile(f)

                    print(file=self.stdout)
                    print("ELF Sections:", file=self.stdout)
                    print(f"{'Name':<20} {'Address':>18} {'Size':>12}  {'Flags'}", file=self.stdout)
                    print("-" * 70, file=self.stdout)

                    for section in elf.iter_sections():
                        name = section.name
                        addr = section["sh_addr"]
                        size = section["sh_size"]
                        flags = section["sh_flags"]

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
                            print(
                                f"{name:<20} {addr:#18x} {size:>12}  {flag_str}", file=self.stdout
                            )

                    print(file=self.stdout)
                    print("Flags: W=Write, A=Alloc, X=Execute", file=self.stdout)
                    print(
                        "Use 'mem <section>' to view section contents (e.g., mem .data)",
                        file=self.stdout,
                    )
                    print(file=self.stdout)

            except Exception as e:
                self.print_error(f"Error reading ELF sections: {e}")
        else:
            self.print_error("Usage: info [breakpoints|symbols|sections]")

    def do_delete(self, arg: str) -> None:
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
            self.print_error("Error: Please specify an address.")
            return

        try:
            addr = int(arg, 0)
            if addr in self.breakpoints:
                self.breakpoints.remove(addr)
                print(f"Breakpoint removed at {addr:#018x}", file=self.stdout)
            else:
                print(f"No breakpoint at {addr:#018x}", file=self.stdout)
        except ValueError:
            self.print_error(f'Error: Invalid address "{arg}".')

    def do_clear(self, arg: str) -> None:
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
        print("All breakpoints cleared.", file=self.stdout)

    # --- Utility Commands ---

    def do_status(self, arg: str) -> None:
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
        print(f"\nLoaded file: {self.loaded_file or 'None'}", file=self.stdout)
        if self.loaded_file:
            isa_name = self.sim.get_isa_name()
            pc = self.sim.get_pc()
            print(f"ISA: {isa_name}", file=self.stdout)
            print(f"PC: {pc:#018x}", file=self.stdout)
        print(f"Breakpoints: {len(self.breakpoints)}", file=self.stdout)
        print(file=self.stdout)

    def do_set(self, arg: str) -> None:
        """Configure console options

        Usage:
            set <option> <value>
            set                    # Show all current settings

        Options:
            show-changes         [on|off]                     - Show register changes after each step
            regs-base            [hex|decimal|binary]         - Default format for register values
            regs-leading-zeros   [default|show|cut|dot]       - How to display leading zeros

        Examples:
            set                          # Show current settings
            set show-changes on          # Enable register change display
            set regs-base decimal        # Show registers in decimal by default
            set regs-leading-zeros dot   # Use dots for leading zeros
            set regs-leading-zeros cut   # Remove leading zeros

        Tips:
            - Use 'regs <option>' to temporarily override format for one call
            - Binary format uses single column due to width
        """
        if not arg:
            # Show all settings
            print(file=self.stdout)
            print("Current settings:", file=self.stdout)
            print(
                f"  show-changes       : {'on' if self.show_reg_changes else 'off'}",
                file=self.stdout,
            )
            print(f"  regs-base          : {self.regs_base}", file=self.stdout)
            print(f"  regs-leading-zeros : {self.regs_leading_zeros}", file=self.stdout)
            print(file=self.stdout)
            return

        parts = arg.split()
        if len(parts) != 2:
            self.print_error("Error: Usage: set <option> <value>")
            return

        option, value = parts[0].lower(), parts[1].lower()

        if option == "show-changes":
            if value in ("on", "true", "1", "yes"):
                self.show_reg_changes = True
                print("Register change display enabled", file=self.stdout)
            elif value in ("off", "false", "0", "no"):
                self.show_reg_changes = False
                print("Register change display disabled", file=self.stdout)
            else:
                self.print_error("Error: Value must be on or off")
        elif option == "regs-base":
            if value in ("hex", "decimal", "binary"):
                self.regs_base = value
                print(f"Register display format set to {value}", file=self.stdout)
            else:
                self.print_error("Error: Value must be hex, decimal, or binary")
        elif option == "regs-leading-zeros":
            if value in ("default", "show", "cut", "dot"):
                self.regs_leading_zeros = value
                print(f"Register leading zeros display set to {value}", file=self.stdout)
            else:
                self.print_error("Error: Value must be default, show, cut, or dot")
        else:
            self.print_error(f'Error: Unknown option "{option}"')

    def do_quit(self, arg: str) -> bool:
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
        print("Goodbye!", file=self.stdout)
        return True

    def do_exit(self, arg: str) -> bool:
        """Exit the console (same as quit)"""
        return self.do_quit(arg)

    def do_EOF(self, arg: str) -> bool:
        """Exit on EOF (Ctrl-D)"""
        print(file=self.stdout)
        return self.do_quit(arg)

    # --- Aliases (hidden from help) ---
    # These are implemented via _ALIASES dict and do_help override
    _ALIASES = {
        "q": "quit",
        "r": "run",
        "s": "step",
        "sr": "stepreg",
        "c": "continue",
        "b": "break",
        "d": "disasm",
        "l": "list",
    }

    def default(self, line: str) -> Optional[bool]:
        """Handle aliases and unknown commands"""
        cmd = line.split()[0] if line.split() else ""
        if cmd in self._ALIASES:
            # Replace alias with full command and re-execute
            full_cmd = self._ALIASES[cmd]
            rest = line[len(cmd) :].strip()
            return self.onecmd(f"{full_cmd} {rest}".strip())
        return super().default(line)

    def do_help(self, arg: str) -> None:
        """Show help for commands

        Usage:
            help [command]

        Shows a list of available commands, or detailed help for a
        specific command if provided.

        Examples:
            help            # List all commands
            help step       # Detailed help for step command
            help load       # Detailed help for load command
        """
        if arg:
            # Check if asking about an alias
            if arg in self._ALIASES:
                arg = self._ALIASES[arg]
            # Use default help for specific command
            super().do_help(arg)
        else:
            # Custom help listing that groups aliases
            print(file=self.stdout)
            print("MapacheSPIM Commands:", file=self.stdout)
            print("=" * 60, file=self.stdout)
            print(file=self.stdout)

            # Group commands by category
            categories = {
                "Loading & Running": [
                    ("load", "Load an ELF file"),
                    ("run (r)", "Run program until halt or breakpoint"),
                    ("step (s)", "Execute one or more instructions"),
                    ("stepreg (sr)", "Step and show registers"),
                    ("continue (c)", "Continue after breakpoint"),
                    ("reset", "Reset simulator state"),
                ],
                "Inspection": [
                    ("regs", "Display all registers"),
                    ("pc", "Display program counter"),
                    ("mem", "Display memory contents"),
                    ("disasm (d)", "Disassemble instructions"),
                    ("list (l)", "Show source code (if debug info)"),
                    ("status", "Show simulator status"),
                    ("info", "Show breakpoints/symbols/sections"),
                ],
                "Breakpoints": [
                    ("break (b)", "Set a breakpoint"),
                    ("delete", "Delete a breakpoint"),
                    ("clear", "Clear all breakpoints"),
                ],
                "Configuration": [
                    ("set", "Configure display options"),
                ],
                "Other": [
                    ("help", "Show this help"),
                    ("quickstart", "Tutorial for new users"),
                    ("quit (q)", "Exit the console"),
                ],
            }

            for category, commands in categories.items():
                print(f"{category}:", file=self.stdout)
                for cmd, desc in commands:
                    print(f"  {cmd:<16} {desc}", file=self.stdout)
                print(file=self.stdout)

            print('Type "help <command>" for detailed help on any command.', file=self.stdout)
            print('Shortcuts shown in parentheses (e.g., "s" for "step").', file=self.stdout)
            print(file=self.stdout)

    # --- Tab Completion ---

    def complete_load(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for load command - completes file paths"""
        import glob

        # Handle ~ expansion
        if text.startswith("~"):
            expanded = str(Path(text).expanduser())
            # Keep track that we need to show ~ in results
            home_prefix = str(Path.home())
            use_tilde = True
        else:
            expanded = text
            use_tilde = False

        # Build glob pattern
        if expanded.endswith("/"):
            # User typed a directory path ending in /, list its contents
            pattern = expanded + "*"
        elif expanded:
            # User typed partial path, complete it
            pattern = expanded + "*"
        else:
            # No text yet, list current directory
            pattern = "*"

        # Get matching paths
        matches = glob.glob(pattern)

        # Format completions - return full paths that replace `text`
        completions = []
        for match in matches:
            path = Path(match)
            if path.is_dir():
                # Add trailing slash for directories
                result = match + "/"
            else:
                result = match

            # Convert back to ~ notation if user started with ~
            if use_tilde and result.startswith(home_prefix):
                result = "~" + result[len(home_prefix) :]

            completions.append(result)

        return completions

    def complete_break(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for break command - completes symbol names"""
        if not self.loaded_file:
            return []

        symbols = self.sim.get_symbols()
        if text:
            return [s for s in symbols.keys() if s.startswith(text)]
        return list(symbols.keys())

    def complete_info(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for info command"""
        options = ["breakpoints", "break", "symbols", "sym", "sections", "sec"]
        if text:
            return [o for o in options if o.startswith(text)]
        return options

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for set command"""
        parts = line.split()
        if len(parts) <= 2:
            # Completing option name
            options = ["show-changes", "regs-base", "regs-leading-zeros"]
            if text:
                return [o for o in options if o.startswith(text)]
            return options
        elif len(parts) == 3 or (len(parts) == 2 and text):
            # Completing value for option
            option = parts[1] if len(parts) >= 2 else ""
            if option == "show-changes":
                values = ["on", "off"]
            elif option == "regs-base":
                values = ["hex", "decimal", "binary"]
            elif option == "regs-leading-zeros":
                values = ["default", "show", "cut", "dot"]
            else:
                return []
            if text:
                return [v for v in values if v.startswith(text)]
            return values
        return []

    def complete_mem(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for mem command - completes section names"""
        sections = [".text", ".data", ".rodata", ".bss"]
        if text:
            return [s for s in sections if s.startswith(text)]
        return sections

    # --- Quick Start Guide ---

    def do_quickstart(self, arg: str) -> None:
        """Show a quick start tutorial for new users

        Usage:
            quickstart

        Displays a step-by-step guide for common operations,
        perfect for students learning assembly for the first time.
        """
        print(file=self.stdout)
        print("=" * 60, file=self.stdout)
        print("MapacheSPIM Quick Start Guide", file=self.stdout)
        print("=" * 60, file=self.stdout)
        print(file=self.stdout)
        print("1. LOAD A PROGRAM (ISA is auto-detected)", file=self.stdout)
        print("   load examples/riscv/fibonacci/fibonacci  # RISC-V", file=self.stdout)
        print("   load examples/arm/fibonacci/fibonacci    # ARM64", file=self.stdout)
        print("   load examples/x86_64/test_simple/simple  # x86-64", file=self.stdout)
        print("   (Use Tab to autocomplete file paths!)", file=self.stdout)
        print(file=self.stdout)
        print("2. SEE WHERE YOU ARE", file=self.stdout)
        print("   pc              - Show program counter", file=self.stdout)
        print("   disasm <addr>   - Disassemble instructions", file=self.stdout)
        print("   regs            - Show all registers", file=self.stdout)
        print(file=self.stdout)
        print("3. EXECUTE CODE", file=self.stdout)
        print("   step (s)        - Execute one instruction", file=self.stdout)
        print("   step 5          - Execute 5 instructions", file=self.stdout)
        print("   run             - Run until program ends", file=self.stdout)
        print("   run 100         - Run at most 100 instructions", file=self.stdout)
        print(file=self.stdout)
        print("4. SET BREAKPOINTS", file=self.stdout)
        print("   break <addr>    - Set breakpoint at address", file=self.stdout)
        print("   break main      - Set breakpoint at symbol", file=self.stdout)
        print("   info break      - List all breakpoints", file=self.stdout)
        print("   continue (c)    - Resume after breakpoint", file=self.stdout)
        print(file=self.stdout)
        print("5. EXAMINE MEMORY", file=self.stdout)
        print("   mem 0x80000000  - Show memory at address", file=self.stdout)
        print("   mem .data       - Show data section", file=self.stdout)
        print(file=self.stdout)
        print("6. TIPS FOR DEBUGGING", file=self.stdout)
        print("   - Stars (★) in regs show changed registers", file=self.stdout)
        print("   - Use stepreg (sr) to step and see registers", file=self.stdout)
        print("   - Use Ctrl-C to interrupt a running program", file=self.stdout)
        print("   - Most commands have short aliases (s, r, c, b)", file=self.stdout)
        print(file=self.stdout)
        print('Type "help <command>" for detailed help.', file=self.stdout)
        print("=" * 60, file=self.stdout)
        print(file=self.stdout)


def main() -> None:
    """Entry point for the console"""
    import argparse

    parser = argparse.ArgumentParser(
        description="MapacheSPIM - Interactive Multi-ISA Simulator (RISC-V, ARM64, x86-64)"
    )
    parser.add_argument("file", nargs="?", help="ELF file to load on startup")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose mode (show extra messages)"
    )

    args = parser.parse_args()

    # Create console
    console = MapacheSPIMConsole(verbose=args.verbose)

    # Auto-load file if provided
    if args.file:
        console.onecmd(f"load {args.file}")

    # Start interactive loop
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\nGoodbye!")


if __name__ == "__main__":
    main()
