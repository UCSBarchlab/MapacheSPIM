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
import tempfile
from pathlib import Path
from types import FrameType
from typing import Any, Dict, Generator, List, Optional, Set

from . import Simulator, StopReason
from .debug_info import SourceInfo, parse_line_info
from .isa import find_spec, isa_names


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

    intro: str = (
        "Welcome to MapacheSPIM. Type help or ? to list commands, or quickstart for a tutorial.\n"
    )
    prompt: str = "(mapachespim) "

    _verbose: bool
    sim: Optional[Simulator]
    loaded_file: Optional[str]
    loaded_source: Optional[Path]
    _elf_path: Optional[str]
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
        self.loaded_file = None  # what the user loaded (ELF or source file)
        self.loaded_source = None  # assembly source, when loaded from .s
        self._elf_path = None  # ELF actually loaded into the simulator
        self._isa_override: Optional[str] = None
        self._tempdir: Optional[tempfile.TemporaryDirectory] = None
        self.breakpoints = set()
        self._interrupted = False
        self._running = False

        # Register change tracking
        self.show_reg_changes = True
        self.prev_regs = None

        # Register display options
        self.regs_base = "hex"  # hex, decimal, or binary
        self.regs_leading_zeros = "default"  # default, show, cut, or dot

        # Output formatting
        self.output_spacing = "normal"  # normal or compact

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

    def _print_block_start(self) -> None:
        """Print leading blank line for block output (respects spacing setting)."""
        if self.output_spacing == "normal":
            print(file=self.stdout)

    def _print_block_end(self) -> None:
        """Print trailing blank line for block output (respects spacing setting)."""
        if self.output_spacing == "normal":
            print(file=self.stdout)

    # --- File Loading ---

    def do_load(self, arg: str) -> None:
        """Load a program (an ELF executable, an assembly file, or an example)

        Usage:
            load <file> [isa]

        Loads a program into the simulator. The program counter is set to
        the entry point and all breakpoints are cleared.

          - ELF executables are loaded directly; the ISA is auto-detected.
          - Assembly source files (.s, .S, .asm) are assembled first, with
            debug info so 'list' can show your source. The ISA comes from a
            '.isa' directive in the file, or from the optional isa argument
            (riscv64, mips32, arm64, x86_64).
          - Bundled examples can be loaded by name; see 'examples'.

        Examples:
            load riscv/hello_asm                    # A bundled example
            load examples/riscv/fibonacci/fibonacci # Same, by path
            load myprog.s                           # Assemble and load
            load myprog.s riscv64                   # ...choosing the ISA
            load myprog                             # An ELF you built

        Tips:
            - After editing a .s file, use 'reload' to re-assemble it
            - Use 'examples' to list the bundled example programs
            - Use Tab to complete file paths and example names
        """
        parts = arg.split()
        if not parts:
            self.print_error("Error: Please specify a file to load (or see 'examples').")
            return
        if len(parts) > 2:
            self.print_error("Error: Usage: load <file> [isa]")
            return

        name = parts[0]
        isa = parts[1] if len(parts) > 1 else None
        filepath = Path(name).expanduser()
        if not filepath.exists():
            from .examples import find_example

            example = find_example(name)
            if example is None:
                self.print_error(
                    f'Error: File "{name}" not found. Type "examples" to see the bundled examples.'
                )
                return
            filepath = example

        if filepath.is_dir():
            self.print_error(f'Error: "{name}" is a directory.')
            return

        if filepath.suffix in (".s", ".S", ".asm"):
            self._assemble_and_load(filepath, isa, display_name=name)
        else:
            if isa is not None:
                self.print_error(
                    "Error: The ISA argument only applies to assembly files; "
                    "an ELF file's ISA is detected automatically."
                )
                return
            self._load_elf_file(str(filepath), display_name=name)

    def _load_elf_file(
        self,
        elf_path: str,
        display_name: str,
        source: Optional[Path] = None,
        keep_breakpoints: bool = False,
    ) -> bool:
        """Load an ELF into the simulator and read its debug info"""
        try:
            self.sim.load_elf(elf_path)
        except Exception as e:
            self.print_error(f"Error loading ELF file: {e}")
            return False

        self.loaded_file = display_name
        self.loaded_source = source
        self._elf_path = elf_path
        # Registers at the entry point are the baseline for ★ change markers
        self.prev_regs = self.sim.get_all_regs()
        pc = self.sim.get_pc()
        isa_name = self.sim.get_isa_name()
        print(f"Loaded {display_name} ({isa_name})", file=self.stdout)
        print(f"Entry point: {pc:#018x}", file=self.stdout)
        if not keep_breakpoints:
            self.breakpoints.clear()

        # Parse DWARF debug information
        source_dirs = [source.parent] if source is not None else None
        self.source_info = parse_line_info(elf_path, source_dirs)
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
        return True

    def _assemble_and_load(
        self,
        source: Path,
        isa: Optional[str],
        display_name: str,
        keep_breakpoints: bool = False,
    ) -> bool:
        """Assemble a source file (with debug info) and load the result"""
        from .toolchain import assemble_file

        valid_isas = isa_names()
        if isa is not None and find_spec(isa) is None:
            self.print_error(f'Error: Unknown ISA "{isa}". Use one of: {", ".join(valid_isas)}')
            return False

        if self._tempdir is None:
            self._tempdir = tempfile.TemporaryDirectory(prefix="mapachespim-")
        elf_path = Path(self._tempdir.name) / (source.stem or "program")

        result = assemble_file(source, output_path=elf_path, isa=isa, debug=True)
        for warning in result.warnings:
            print(f"{source.name}: warning: {warning}", file=self.stdout)
        if not result.success:
            self._print_block_start()
            if any(e.startswith("ISA not specified") for e in result.errors):
                print(f"Error: {source.name} does not say which ISA it is for.", file=self.stdout)
                print("Add a line like this at the top of the file:", file=self.stdout)
                print("    .isa riscv64", file=self.stdout)
                print(
                    f"or give the ISA when loading:  load {display_name} riscv64", file=self.stdout
                )
                print(f"(ISAs: {', '.join(valid_isas)})", file=self.stdout)
            else:
                print(f"Error: could not assemble {source.name}:", file=self.stdout)
                for error in result.errors:
                    first, *rest = error.splitlines()
                    print(f"  {source.name}: {first}", file=self.stdout)
                    for line in rest:
                        print(f"    {line}" if line.strip() else "", file=self.stdout)
            self._print_block_end()
            return False

        self._isa_override = isa
        print(f"Assembled {source.name} ({len(result.elf_bytes)} bytes)", file=self.stdout)
        return self._load_elf_file(
            str(elf_path), display_name, source=source, keep_breakpoints=keep_breakpoints
        )

    def do_reload(self, arg: str) -> None:
        """Reload the current program from disk

        Usage:
            reload

        For an assembly file, re-assembles it and loads the result, so you
        can edit your .s file and try the new version without retyping the
        'load' command. For an ELF file, reloads it (for example after you
        rebuilt it with mapachespim-as).

        Breakpoints set on labels move with their label; breakpoints on
        addresses that are no longer labelled are kept as they are.

        Examples:
            load myprog.s
            run                     # Find a bug, edit myprog.s...
            reload                  # Re-assemble and load the fixed version
        """
        if not self.loaded_file:
            self.print_error('Error: No program loaded. Use "load <file>" first.')
            return

        # Remember which label each breakpoint was on so it can follow the label
        old_symbols = {addr: name for name, addr in self.sim.get_symbols().items()}
        by_label = {addr: old_symbols[addr] for addr in self.breakpoints if addr in old_symbols}

        if self.loaded_source is not None:
            ok = self._assemble_and_load(
                self.loaded_source,
                self._isa_override,
                self.loaded_file,
                keep_breakpoints=True,
            )
        else:
            ok = self._load_elf_file(
                self._elf_path or self.loaded_file, self.loaded_file, keep_breakpoints=True
            )
        if not ok:
            return

        moved = set()
        for addr in list(self.breakpoints):
            if addr in by_label:
                new_addr = self.sim.lookup_symbol(by_label[addr])
                self.breakpoints.discard(addr)
                if new_addr is not None:
                    moved.add(new_addr)
            else:
                moved.add(addr)
        self.breakpoints = moved
        if self.breakpoints:
            print(f"Kept {len(self.breakpoints)} breakpoint(s)", file=self.stdout)

    def do_examples(self, arg: str) -> None:
        """List the bundled example programs

        Usage:
            examples [isa]

        Lists the example programs that come with MapacheSPIM, optionally
        only those for one ISA (riscv, mips, arm, x86_64). Load one by name.

        Examples:
            examples                # List everything
            examples riscv          # Only RISC-V examples
            load riscv/hello_asm    # Load one

        Tips:
            - To edit the examples, copy them to your own directory with:
                mapachespim --copy-examples my-examples
        """
        from .examples import ISA_DIRS, list_examples

        wanted = arg.strip().lower() or None
        if wanted is not None and wanted not in ISA_DIRS:
            spec = find_spec(wanted)
            if spec is None:
                self.print_error(
                    f'Error: Unknown ISA "{arg.strip()}". Use one of: {", ".join(ISA_DIRS)}'
                )
                return
            wanted = spec.examples_dir

        examples = [e for e in list_examples() if wanted is None or e.isa == wanted]
        if not examples:
            self.print_error("No bundled examples found in this installation.")
            return

        self._print_block_start()
        current = None
        for example in examples:
            if example.isa != current:
                if current is not None:
                    print(file=self.stdout)
                current = example.isa
                print(f"{ISA_DIRS[example.isa]}:", file=self.stdout)
            print(f"  {example.short_name:<24} {example.description}", file=self.stdout)
        print(file=self.stdout)
        print(f"Load one with, e.g.:  load {examples[0].short_name}", file=self.stdout)
        self._print_block_end()

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

        if self._report_if_exited():
            return

        # Execute instructions
        for i in range(n_steps):
            pc = self.sim.get_pc()

            # Check for breakpoint (but skip if this is the first step and we're already at a breakpoint)
            if i > 0 and pc in self.breakpoints:
                print(f"Breakpoint hit at {pc:#018x}", file=self.stdout)
                break

            # Show the instruction before executing it, so any output it
            # produces (e.g. a print syscall) appears after it
            self._end_program_output()
            print(self._format_instruction(pc), file=self.stdout)
            self.stdout.flush()

            result = self.sim.step()
            should_terminate, reason = self.sim.check_termination(result)
            if should_terminate and reason is not None:
                self._report_stop(reason, pc)
                break

        # Keep the next prompt off the line of any program output
        self._end_program_output()

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
            - Stars (★) mark registers that changed since the last register display
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

        if self._report_if_exited():
            return

        # Run with breakpoint/interrupt checking
        self._running = True
        self._interrupted = False
        try:
            result = self.sim.run_until(max_steps or None, stop_before=self._stop_before)
        finally:
            self._running = False

        self._end_program_output()
        if result.reason == StopReason.INTERRUPTED:
            self._interrupted = False
            print(f"Interrupted after {result.steps} instructions", file=self.stdout)
        elif result.reason == StopReason.BREAKPOINT:
            print(
                f"Breakpoint hit at {result.pc:#018x} after {result.steps} instructions",
                file=self.stdout,
            )
        elif result.reason is not None:
            self._report_stop(result.reason, result.pc, result.steps)
        else:
            print(f"Executed {result.steps} instructions (max limit reached)", file=self.stdout)
        self._end_program_output()
        if result.steps > 0 and not self.sim.exited:
            print(f"PC = {self.sim.get_pc():#018x}", file=self.stdout)

    def _stop_before(self, pc: int) -> Optional[StopReason]:
        """Stop a run at a breakpoint or when the user pressed Ctrl-C"""
        if self._interrupted:
            return StopReason.INTERRUPTED
        if pc in self.breakpoints:
            return StopReason.BREAKPOINT
        return None

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
        """Reset the program to its initial state

        Usage:
            reset

        Reloads the current program from disk: memory, registers, and the
        program counter go back to how they were right after 'load', so
        you can run the program again from the start. Breakpoints are kept.

        Examples:
            load examples/riscv/fibonacci/fibonacci
            run                     # Run to completion
            reset                   # Start over
            step                    # Step from the entry point again

        Tips:
            - Use 'clear' to remove breakpoints
            - 'reset' restarts the version that was loaded; after editing
              a .s file, use 'reload' to re-assemble it
        """
        if not self.loaded_file:
            self.print_error('Error: No program loaded. Use "load <file>" first.')
            return
        try:
            self.sim.reset()
        except Exception as e:
            self.print_error(f"Error reloading {self.loaded_file}: {e}")
            return
        self.prev_regs = self.sim.get_all_regs()
        print(
            f"Reset {self.loaded_file}. PC = {self.sim.get_pc():#018x}",
            file=self.stdout,
        )

    # --- Execution helpers ---

    def _format_instruction(self, pc: int) -> str:
        """Format one instruction as '[addr] 0xbytes  disasm  <symbol+off>'"""
        try:
            text, size = self.sim.disasm_with_size(pc)
            raw = self.sim.read_mem(pc, size)
            instr_hex = "".join(f"{b:02x}" for b in raw)
        except Exception:
            text, instr_hex = "<invalid address>", "????????"

        symbol = self.sim.symbols.describe(pc)
        suffix = f"  {symbol}" if symbol else ""
        return f"[{pc:#010x}] 0x{instr_hex}  {text}{suffix}"

    def _end_program_output(self) -> None:
        """Start a new line if the program's output left the cursor mid-line"""
        if self.sim is not None and self.sim.output_needs_newline:
            print(file=self.stdout)
            self.sim.output_needs_newline = False

    def _report_if_exited(self) -> bool:
        """If the program already exited, say so and return True"""
        if self.sim.exited:
            self.print_error(
                f'The program has exited (code {self.sim.exit_code}). Use "reset" to run it again.'
            )
            return True
        return False

    def _report_stop(self, reason: StopReason, pc: int, steps: Optional[int] = None) -> None:
        """Print why execution stopped (exit, error, ...)"""
        self._end_program_output()
        after = f" after {steps} instructions" if steps is not None else ""
        if reason == StopReason.EXIT:
            print(f"Program exited with code {self.sim.exit_code}{after}", file=self.stdout)
        elif reason == StopReason.HALT:
            print(f"Program halted{after}", file=self.stdout)
        elif reason == StopReason.TOHOST:
            print(f"Program completed (tohost){after}", file=self.stdout)
        elif reason == StopReason.ERROR:
            detail = self.sim.last_error or "Execution error"
            print(f"Error: {detail}", file=self.stdout)
            print(f"  {self._format_instruction(pc)}", file=self.stdout)
            location = self.source_info.get_location(pc)
            if location:
                filename, line_num = location
                lines = self.source_info.get_source_lines(filename, line_num, 1)
                if lines:
                    print(f"  {filename}:{line_num}: {lines[0][1].strip()}", file=self.stdout)

    # --- State Inspection ---

    def _format_reg_value(self, value: int, show_mode: str, leading_zeros_mode: str) -> str:
        """Format a register value according to display settings"""
        sign = ""  # only used by signed decimal
        if show_mode == "hex":
            # Format as hex with 0x prefix
            formatted = f"{value:016x}"
            prefix = "0x"
        elif show_mode == "decimal":
            # Signed decimal, since that is how students think of values
            # like -1 (max 20 digits for 64-bit)
            bits = self.sim.spec.word_bits if self.sim.get_isa() is not None else 64
            if value & (1 << (bits - 1)):
                value -= 1 << bits
            sign = "-" if value < 0 else ""
            formatted = f"{abs(value):0{20 - len(sign)}d}"
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
            formatted = "." * num_leading + sign + stripped
            sign = ""

        return sign + prefix + formatted

    def _change_marker(self) -> str:
        """Marker for changed registers; '*' where the terminal can't show ★"""
        encoding = getattr(self.stdout, "encoding", None) or "utf-8"
        try:
            "★".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            return "*"
        return "★"

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
            decimal  - Show values in signed decimal
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
            regs peek           # View registers without resetting the change baseline

        Tips:
            - Use 'set regs-base' to change default format globally
            - Use 'set regs-leading-zeros' to change leading zero display
            - Stars (★) mark registers that changed since you last viewed them
            - Use 'regs peek' to view without resetting the change baseline
            - Use 'status' to see current ISA
        """
        # Parse arguments for temporary overrides and peek mode
        show_mode = self.regs_base
        leading_zeros_mode = self.regs_leading_zeros
        peek_mode = False

        if arg:
            parts = arg.split()
            for part in parts:
                part_lower = part.lower()
                if part_lower in ("hex", "decimal", "binary"):
                    show_mode = part_lower
                elif part_lower in ("default", "show", "cut", "dot"):
                    leading_zeros_mode = part_lower
                elif part_lower in ("peek", "-n", "--no-reset"):
                    peek_mode = True
                else:
                    self.print_error(
                        f'Error: Unknown option "{part}". Use: hex, decimal, binary, default, show, cut, dot, or peek'
                    )
                    return

        self._print_block_start()
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
        prefix = self.sim.spec.registers.number_prefix if self.sim.get_isa() is not None else None

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
                        f" {self._change_marker()} "
                        if (
                            self.show_reg_changes
                            and self.prev_regs is not None
                            and reg_num < len(self.prev_regs)
                            and self.prev_regs[reg_num] != value
                        )
                        else "   "
                    )

                    # Format register name based on ISA
                    if prefix:  # e.g. "x5 (t0)"
                        label = f"{prefix}{reg_num:<2} ({abi_name:>4})"
                    else:  # just the name, e.g. "rax"
                        label = f"{abi_name:>3}"
                    line_parts.append(f"{label} = {formatted_value:<{value_width}}{star}")
            reg_lines.append(" ".join(line_parts))

        for line in reg_lines:
            print(line, file=self.stdout)

        # Format PC
        formatted_pc = self._format_reg_value(pc, show_mode, leading_zeros_mode)
        print(f"\npc = {formatted_pc}", file=self.stdout)
        self._print_block_end()

        # Update the snapshot for change tracking (unless peek mode)
        if not peek_mode:
            self.prev_regs = regs

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
            mem <address|symbol|section> [length]

        Displays memory contents starting at the given address or section
        in hexadecimal format with ASCII sidebar. Default length is 256
        bytes if not specified.

        Arguments:
            address - Memory address in hex (0x...) or decimal
            symbol  - Label name from the symbol table (e.g., my_array)
            section - ELF section name (e.g., .text, .data, .rodata)
            length  - Number of bytes to display (optional, default=256)

        Examples:
            mem 0x80000000          # Show 256 bytes from address
            mem .data               # Show .data section
            mem .rodata             # Show read-only data section
            mem 0x80000000 64       # Show 64 bytes
            mem my_array 32         # Show 32 bytes at label my_array

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
            if not self.loaded_file:
                self.print_error("Error: No program loaded.")
                return

            section = self.sim.find_section(addr_or_section)
            if section is None:
                self.print_error(
                    f'Error: Section "{addr_or_section}" not found. Use "info sections" to see available sections.'
                )
                return
            if section.address == 0:
                self.print_error(
                    f'Error: Section "{addr_or_section}" is not loaded in memory (address is 0).'
                )
                return
            addr = section.address
            if len(parts) == 1:  # No length given: at most the whole section
                length = min(length, section.size)
        else:
            # Parse as address or symbol name
            parsed = self._parse_address(addr_or_section)
            if parsed is None:
                self.print_error(
                    f'Error: "{addr_or_section}" is not a valid address or known symbol.'
                )
                return
            addr = parsed

        # Read and display memory
        try:
            data = self.sim.read_mem(addr, length)
            self._print_memory(addr, data)
        except Exception as e:
            self.print_error(f"Error reading memory: {e}")

    def _print_memory(self, start_addr: int, data: bytes, width: int = 16) -> None:
        """Pretty-print memory contents in hex dump format with ASCII sidebar"""
        self._print_block_start()
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
        self._print_block_end()

    def do_disasm(self, arg: str) -> None:
        """Disassemble instructions at address

        Usage:
            disasm [address|symbol|pc] [count]

        Disassembles instructions starting at the given address.
        If no address is specified, defaults to the current PC.
        Default count is 10 instructions if not specified.

        Arguments:
            address - Memory address in hex (0x...), a symbol name, or 'pc'
            count   - Number of instructions to disassemble (optional, default=10)

        Aliases:
            d - Short alias for disasm

        Examples:
            disasm                      # Disassemble 10 from current PC
            disasm pc                   # Same as above
            disasm pc 5                 # Disassemble 5 from PC
            disasm 0x80000000           # Disassemble 10 instructions
            disasm 0x80000000 5         # Disassemble 5 instructions
            d 0x80000000                # Using alias
            disasm fibonacci            # Disassemble a function by name

        Tips:
            - '>' marks the instruction at the current PC
            - Instruction sizes: RISC-V/ARM64/MIPS = 4 bytes, x86-64 = variable
            - Use 'mem <addr>' to see raw instruction bytes
        """
        parts = arg.split() if arg else []

        # Default to current PC if no args
        if not parts:
            addr = self.sim.get_pc()
            count = 10
        elif parts[0].lower() in ("pc", "$"):
            # "pc" or "$" means current PC
            addr = self.sim.get_pc()
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
        else:
            # Parse address or symbol name
            parsed = self._parse_address(parts[0])
            if parsed is None:
                self.print_error(f'Error: "{parts[0]}" is not a valid address or known symbol.')
                return
            addr = parsed

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

        # Disassemble instructions (x86-64 instructions vary in length, so
        # advance by each instruction's actual size)
        self._print_block_start()
        instr_addr = addr
        for _ in range(count):
            try:
                disasm, size = self.sim.disasm_with_size(instr_addr)
            except Exception as e:
                print(f"[{instr_addr:#010x}]  <error: {e}>", file=self.stdout)
                break
            marker = ">" if instr_addr == self.sim.get_pc() else " "
            print(f"[{instr_addr:#010x}]{marker} {disasm}", file=self.stdout)
            if disasm == "<invalid address>":
                break
            instr_addr += size
        self._print_block_end()

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
            - Assemble with 'mapachespim-as -g' to include debug info
            - Source file must be in same directory as ELF file
            - Shows 10 lines by default
            - Current PC is marked with '# <-- PC: 0xXXXXXXXX'
        """
        if not self.loaded_file:
            self.print_error('Error: No program loaded. Use "load <file>" first.')
            return

        if not self.source_info.has_debug_info:
            self._print_block_start()
            print("No source information available.", file=self.stdout)
            print("Assemble your program with debug info (use the -g flag):", file=self.stdout)
            print("  mapachespim-as -g program.s -o program", file=self.stdout)
            self._print_block_end()
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

        self._print_block_start()
        print(f"{filename}:", file=self.stdout)

        # Find which line corresponds to current PC (if any)
        pc_line = None
        pc_location = self.source_info.get_location(current_pc)
        if pc_location and pc_location[0] == filename:
            pc_line = pc_location[1]

        for line_num, text in lines:
            # Mark current PC line with ">" instead of ":" for visibility
            if line_num == pc_line:
                print(f"{line_num:5d}> {text}  # <-- PC: {current_pc:#010x}", file=self.stdout)
            else:
                print(f"{line_num:5d}: {text}", file=self.stdout)

        self._print_block_end()

    # --- Breakpoints ---

    def _parse_address(self, text: str) -> Optional[int]:
        """Parse a symbol name or a numeric address (hex or decimal)"""
        if self.loaded_file:
            addr = self.sim.lookup_symbol(text)
            if addr is not None:
                return addr
        try:
            return int(text, 0)
        except ValueError:
            return None

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

        addr = self._parse_address(arg)
        if addr is None:
            self.print_error(f'Error: "{arg}" is not a valid address or known symbol.')
            return
        self.breakpoints.add(addr)
        if self.loaded_file and self.sim.lookup_symbol(arg) is not None:
            print(f"Breakpoint set at {arg} ({addr:#010x})", file=self.stdout)
        else:
            print(f"Breakpoint set at {addr:#010x}", file=self.stdout)

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
                self._print_block_start()
                print("Breakpoints:", file=self.stdout)
                for i, addr in enumerate(sorted(self.breakpoints), 1):
                    symbol = self.sim.symbols.describe(addr)
                    print(f"  {i}. {addr:#010x}  {symbol}".rstrip(), file=self.stdout)
                self._print_block_end()
        elif arg == "symbols" or arg == "sym":
            if not self.loaded_file:
                print("No program loaded.", file=self.stdout)
                return

            symbols = self.sim.get_symbols()
            if not symbols:
                print("No symbols available.", file=self.stdout)
                return

            self._print_block_start()
            print(f"Symbols ({len(symbols)} total):", file=self.stdout)

            # Sort by address
            sorted_symbols = sorted(symbols.items(), key=lambda x: x[1])

            for name, addr in sorted_symbols:
                print(f"  {addr:#010x}  {name}", file=self.stdout)
            self._print_block_end()
        elif arg == "sections" or arg == "sec":
            if not self.loaded_file:
                print("No program loaded.", file=self.stdout)
                return

            self._print_block_start()
            print("ELF Sections:", file=self.stdout)
            print(f"{'Name':<20} {'Address':>18} {'Size':>12}  {'Flags'}", file=self.stdout)
            print("-" * 70, file=self.stdout)
            # Only sections loaded in memory are of interest
            for section in self.sim.get_sections():
                if section.address > 0:
                    print(
                        f"{section.name:<20} {section.address:#18x} {section.size:>12}  "
                        f"{section.flag_letters}",
                        file=self.stdout,
                    )
            print(file=self.stdout)
            print("Flags: W=Write, A=Alloc, X=Execute", file=self.stdout)
            print(
                "Use 'mem <section>' to view section contents (e.g., mem .data)",
                file=self.stdout,
            )
            self._print_block_end()
        else:
            self.print_error("Usage: info [breakpoints|symbols|sections]")

    def do_delete(self, arg: str) -> None:
        """Delete a specific breakpoint

        Usage:
            delete <address|symbol>

        Removes the breakpoint at the specified address. If no
        breakpoint exists at that address, a message is displayed.

        Arguments:
            address - Memory address in hex (0x...) or decimal
            symbol  - Function or label name used with 'break'

        Examples:
            break 0x80000010        # Set a breakpoint
            info breakpoints        # Verify it's set
            delete 0x80000010       # Remove the breakpoint
            info breakpoints        # Confirm it's gone

        Tips:
            - Use 'info breakpoints' to see all addresses with breakpoints
            - Use 'clear' to remove all breakpoints at once
        """
        if not arg:
            self.print_error("Error: Please specify an address.")
            return

        addr = self._parse_address(arg)
        if addr is None:
            self.print_error(f'Error: "{arg}" is not a valid address or known symbol.')
            return
        if addr in self.breakpoints:
            self.breakpoints.remove(addr)
            print(f"Breakpoint removed at {addr:#018x}", file=self.stdout)
        else:
            print(f"No breakpoint at {addr:#018x}", file=self.stdout)

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
        self._print_block_start()
        print(f"Loaded file: {self.loaded_file or 'None'}", file=self.stdout)
        if self.loaded_source is not None:
            print(f"Source: {self.loaded_source}", file=self.stdout)
        if self.loaded_file:
            isa_name = self.sim.get_isa_name()
            pc = self.sim.get_pc()
            print(f"ISA: {isa_name}", file=self.stdout)
            print(f"PC: {pc:#018x}", file=self.stdout)
        print(f"Breakpoints: {len(self.breakpoints)}", file=self.stdout)
        self._print_block_end()

    def do_set(self, arg: str) -> None:
        """Configure console options

        Usage:
            set <option> <value>
            set                    # Show all current settings

        Options:
            show-changes         [on|off]                     - Mark changed registers with ★ in regs
            regs-base            [hex|decimal|binary]         - Default format for register values
            regs-leading-zeros   [default|show|cut|dot]       - How to display leading zeros
            output-spacing       [normal|compact]             - Spacing around multi-line output

        Examples:
            set                          # Show current settings
            set show-changes on          # Enable register change display
            set regs-base decimal        # Show registers in decimal by default
            set regs-leading-zeros dot   # Use dots for leading zeros
            set regs-leading-zeros cut   # Remove leading zeros
            set output-spacing compact   # Remove blank lines around output blocks

        Tips:
            - Use 'regs <option>' to temporarily override format for one call
            - Binary format uses single column due to width
            - Compact spacing is useful for smaller terminals
        """
        if not arg:
            # Show all settings
            self._print_block_start()
            print("Current settings:", file=self.stdout)
            print(
                f"  show-changes       : {'on' if self.show_reg_changes else 'off'}",
                file=self.stdout,
            )
            print(f"  regs-base          : {self.regs_base}", file=self.stdout)
            print(f"  regs-leading-zeros : {self.regs_leading_zeros}", file=self.stdout)
            print(f"  output-spacing     : {self.output_spacing}", file=self.stdout)
            self._print_block_end()
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
        elif option == "output-spacing":
            if value in ("normal", "compact"):
                self.output_spacing = value
                print(f"Output spacing set to {value}", file=self.stdout)
            else:
                self.print_error("Error: Value must be normal or compact")
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
            self._print_block_start()
            print("MapacheSPIM Commands:", file=self.stdout)
            print("=" * 60, file=self.stdout)
            print(file=self.stdout)

            # Group commands by category
            categories = {
                "Loading & Running": [
                    ("load", "Load a program (.s file, ELF, or example)"),
                    ("reload", "Re-assemble/reload the current program"),
                    ("examples", "List the bundled example programs"),
                    ("run (r)", "Run program until halt or breakpoint"),
                    ("step (s)", "Execute one or more instructions"),
                    ("stepreg (sr)", "Step and show registers"),
                    ("continue (c)", "Continue after breakpoint"),
                    ("reset", "Restart the program from the beginning"),
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
            self._print_block_end()

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

        # Also offer bundled example names like "riscv/fibonacci"
        if not use_tilde and text.count("/") <= 1:
            from .examples import list_examples

            for example in list_examples():
                if example.short_name.startswith(text) and not Path(example.short_name).exists():
                    matches.append(example.short_name)

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
            options = ["show-changes", "regs-base", "regs-leading-zeros", "output-spacing"]
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
            elif option == "output-spacing":
                values = ["normal", "compact"]
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
        self._print_block_start()
        print("=" * 60, file=self.stdout)
        print("MapacheSPIM Quick Start Guide", file=self.stdout)
        print("=" * 60, file=self.stdout)
        print(file=self.stdout)
        print("1. LOAD A PROGRAM", file=self.stdout)
        print("   examples                 - List the bundled examples", file=self.stdout)
        print("   load riscv/hello_asm     - Load an example by name", file=self.stdout)
        print("   load myprog.s            - Assemble and load your own program", file=self.stdout)
        print("   reload                   - Re-assemble after editing", file=self.stdout)
        print("   (Use Tab to autocomplete file paths and example names!)", file=self.stdout)
        print(file=self.stdout)
        print("2. SEE WHERE YOU ARE", file=self.stdout)
        print("   pc              - Show program counter", file=self.stdout)
        print("   list            - Show your source code around the PC", file=self.stdout)
        print("   disasm          - Disassemble instructions at the PC", file=self.stdout)
        print("   regs            - Show all registers", file=self.stdout)
        print(file=self.stdout)
        print("3. EXECUTE CODE", file=self.stdout)
        print("   step (s)        - Execute one instruction", file=self.stdout)
        print("   step 5          - Execute 5 instructions", file=self.stdout)
        print("   run             - Run until program ends", file=self.stdout)
        print("   run 100         - Run at most 100 instructions", file=self.stdout)
        print("   reset           - Start over from the beginning", file=self.stdout)
        print(file=self.stdout)
        print("4. SET BREAKPOINTS", file=self.stdout)
        print("   break <addr>    - Set breakpoint at address", file=self.stdout)
        print("   break main      - Set breakpoint at symbol", file=self.stdout)
        print("   info break      - List all breakpoints", file=self.stdout)
        print("   continue (c)    - Resume after breakpoint", file=self.stdout)
        print(file=self.stdout)
        print("5. EXAMINE MEMORY", file=self.stdout)
        print("   mem 0x80000000  - Show memory at address", file=self.stdout)
        print("   mem my_label    - Show memory at a label", file=self.stdout)
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
        self._print_block_end()


DEFAULT_MAX_STEPS = 10_000_000


def _execute(
    console: MapacheSPIMConsole,
    path: str,
    max_steps: int,
    verbose: bool,
    isa: Optional[str] = None,
) -> int:
    """Run a program non-interactively and return the process exit status.

    The status is the program's exit code if it exits normally, 1 if the file
    cannot be loaded or execution fails, and 124 (like ``timeout``) if the
    instruction limit is reached.
    """
    import io

    from .examples import find_example

    if not Path(path).exists() and find_example(path) is None:
        print(f"Error: File '{path}' not found", file=sys.stderr)
        return 1

    # Suppress console output during load (unless verbose)
    captured_output = io.StringIO()
    original_stdout = console.stdout
    if not verbose:
        console.stdout = captured_output
    console.onecmd(f"load {path} {isa}" if isa else f"load {path}")
    console.stdout = original_stdout

    if not console.loaded_file:
        captured = captured_output.getvalue().strip()
        print(captured or f"Error: Failed to load '{path}'", file=sys.stderr)
        return 1

    sim = console.sim
    result = sim.run_until(max_steps)
    reason = result.reason

    # Diagnostics go to stderr so stdout contains only the program's output
    if sim.output_needs_newline:
        sys.stdout.flush()
        print(file=sys.stderr)
    if verbose:
        print(f"Program completed in {result.steps} steps", file=sys.stderr)

    if reason == StopReason.EXIT:
        return sim.exit_code or 0
    if reason in (StopReason.HALT, StopReason.TOHOST):
        return 0
    if reason == StopReason.ERROR:
        print(f"Error: {sim.last_error or 'execution error'}", file=sys.stderr)
        print(f"  {console._format_instruction(result.pc)}", file=sys.stderr)
        return 1
    print(
        f"Error: program did not exit within {max_steps} instructions "
        "(infinite loop? use --max-steps to raise the limit)",
        file=sys.stderr,
    )
    return 124


def main() -> None:
    """Entry point for the console"""
    import argparse

    from . import __version__

    parser = argparse.ArgumentParser(
        prog="mapachespim",
        description="MapacheSPIM - Interactive Multi-ISA Simulator (RISC-V, ARM64, x86-64, MIPS32)",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Program to load: an ELF file, an assembly file (.s), or an example name",
    )
    parser.add_argument(
        "--isa",
        choices=isa_names(),
        help="ISA of an assembly file without an .isa directive",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose mode (show extra messages)"
    )
    parser.add_argument(
        "-e",
        "--execute",
        action="store_true",
        help="Run the program and exit with its exit code (no interactive console)",
    )
    parser.add_argument(
        "--copy-examples",
        metavar="DIR",
        nargs="?",
        const="mapachespim-examples",
        help="Copy the bundled example programs to DIR (default: ./mapachespim-examples) and exit",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=DEFAULT_MAX_STEPS,
        metavar="N",
        help=f"With -e, stop after N instructions (default {DEFAULT_MAX_STEPS:,})",
    )

    # Some terminals (e.g. legacy Windows code pages) can't show every
    # character we print; substitute rather than crash
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")

    args = parser.parse_args()
    if args.max_steps < 1:
        parser.error("--max-steps must be at least 1")

    if args.copy_examples is not None:
        from .examples import copy_examples

        try:
            dest = copy_examples(Path(args.copy_examples))
        except (FileNotFoundError, FileExistsError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Copied examples to {dest}/")
        print(f"Try:  mapachespim {dest}/riscv/hello_asm/hello_asm.s")
        sys.exit(0)

    # Create console
    console = MapacheSPIMConsole(verbose=args.verbose)

    # Execute mode: run program and exit
    if args.execute:
        if not args.file:
            print("Error: -e/--execute requires a file argument", file=sys.stderr)
            sys.exit(1)
        try:
            status = _execute(console, args.file, args.max_steps, args.verbose, args.isa)
        except BrokenPipeError:
            # Output was piped into something like `head` that exited early
            import os

            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            status = 1
        sys.exit(status)

    # Interactive mode: start REPL
    if args.file:
        console.onecmd(f"load {args.file} {args.isa}" if args.isa else f"load {args.file}")

    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\nGoodbye!")


if __name__ == "__main__":
    main()
