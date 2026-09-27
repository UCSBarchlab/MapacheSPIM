"""
The simulator: runs programs for any registered ISA on the Unicorn Engine.

ISA-specific facts come from :mod:`mapachespim.isa` (registers, syscall ABI,
memory layout, ...) and :mod:`mapachespim.engines` (Unicorn and Capstone
constants), so nothing here branches on the ISA. Syscalls are performed by
:mod:`mapachespim.syscalls`.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Callable, Dict, List, Optional, TextIO, Tuple, Union

try:
    from unicorn import (
        UC_HOOK_MEM_UNMAPPED,
        UC_MEM_FETCH_UNMAPPED,
        UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_UNMAPPED,
        UC_PROT_ALL,
        Uc,
        UcError,
    )
except ImportError as e:
    raise ImportError(
        f"Unicorn Engine not installed. Install with: pip install unicorn\nOriginal error: {e}"
    )

from .disassembler import Disassembler
from .elf_loader import ELFSection, ELFSegment, load_elf_file
from .engines import EngineBinding, engine_for
from .isa import ISA, ISASpec, get_spec
from .memory_map import MemoryLayout
from .symbols import SymbolTable
from .syscalls import ProgramIO, SyscallHandler

__all__ = [
    "ISA",
    "RunResult",
    "StepResult",
    "StopReason",
    "UnicornSimulator",
    "create_simulator",
    "detect_elf_isa",
]


class StepResult(IntEnum):
    """Result codes from step()"""

    OK = 0
    HALT = 1
    WAITING = 2
    SYSCALL = 3
    ERROR = -1


class StopReason(str, Enum):
    """Why execution stopped. Compares equal to its string value (e.g. "halt")."""

    EXIT = "syscall_exit"
    """The program made an exit syscall (see ``exit_code``)."""

    HALT = "halt"
    """The program had already exited."""

    ERROR = "error"
    """An instruction or syscall failed (see ``last_error``)."""

    TOHOST = "tohost"
    """The program wrote to the RISC-V HTIF ``tohost`` symbol."""

    BREAKPOINT = "breakpoint"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class RunResult:
    """Outcome of :meth:`UnicornSimulator.run_until`."""

    steps: int
    """Instructions executed."""

    reason: Optional[StopReason]
    """Why execution stopped, or None if the step limit was reached."""

    pc: int
    """Address of the last instruction executed (or attempted)."""


PAGE_SIZE = 0x1000

# Size of the region mapped at the start of each ISA's text/data areas so that
# small hand-written programs work without an ELF file.
DEFAULT_REGION_SIZE = 0x400000

_UNMAPPED_ACCESS_KINDS = {
    UC_MEM_READ_UNMAPPED: "Read from",
    UC_MEM_WRITE_UNMAPPED: "Write to",
    UC_MEM_FETCH_UNMAPPED: "Instruction fetch from",
}


def _describe_uc_error(e: UcError) -> str:
    """Turn a Unicorn error into a message a student can act on"""
    text = str(e)
    if "INSN_INVALID" in text:
        return "Invalid instruction"
    if "FETCH_PROT" in text or "FETCH_UNALIGNED" in text:
        return "Cannot execute code at this address"
    if "UNALIGNED" in text:
        return "Unaligned memory access"
    if "EXCEPTION" in text:
        return "CPU exception (unhandled trap)"
    return text


class UnicornSimulator:
    """
    Unicorn Engine-based CPU emulator for every ISA in :mod:`mapachespim.isa`

    Provides step-by-step execution, register/memory access, and state inspection.

    Program I/O from syscalls goes to ``stdout`` and comes from ``stdin``. Both
    default to the process streams (looked up at call time, so pytest's capsys
    and similar redirection work) and can be replaced, e.g. for autograding.
    """

    _spec: Optional[ISASpec]
    _engine: Optional[EngineBinding]
    _uc: Optional[Uc]
    _disasm: Optional[Disassembler]
    _symbols: SymbolTable
    _sections: List[ELFSection]
    _entry_point: Optional[int]
    _last_error: Optional[str]
    _elf_path: Optional[str]
    _explicit_isa: bool
    _mem_buffers: List[ctypes.Array]
    _exit_code: Optional[int]
    _tohost_addr: Optional[int]

    def __init__(self, isa: Optional[ISA] = None, config_file: Optional[str] = None) -> None:
        """
        Initialize the simulator

        Args:
            isa (ISA, optional): ISA to use (e.g. ISA.RISCV). If None, it is
                detected from each ELF file passed to load_elf().
            config_file (str, optional): Not used (kept for compatibility)
        """
        self._explicit_isa = isa is not None
        self._spec = None
        self._engine = None
        self._uc = None
        self._disasm = None
        self._symbols = SymbolTable()
        self._sections = []
        self._entry_point = None
        self._last_error = None
        self._elf_path = None
        self._mem_buffers = []
        self._exit_code = None
        self._tohost_addr = None
        self._io = ProgramIO()
        self._syscalls = SyscallHandler(self._io)

        if isa is not None:
            self._init_machine(get_spec(isa))

    # --- Machine setup ---

    def _init_machine(self, spec: ISASpec) -> None:
        """Create a fresh machine for ``spec`` with the default memory map"""
        engine = engine_for(spec)
        try:
            uc = Uc(engine.uc_arch, engine.uc_mode)
        except UcError as e:
            raise RuntimeError(f"Failed to initialize Unicorn: {e}")
        self._spec, self._engine, self._uc = spec, engine, uc
        self._disasm = Disassembler(spec)
        self._mem_buffers = []
        self._exit_code = None
        self._last_error = None
        self._symbols = SymbolTable()
        self._sections = []
        self._tohost_addr = None
        self._io.clear_input()

        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped_access)
        self._map_default_memory()

    def _on_unmapped_access(
        self, uc: Uc, access: int, address: int, size: int, value: int, user_data: object
    ) -> bool:
        kind = _UNMAPPED_ACCESS_KINDS.get(access, "access")
        self._last_error = f"{kind} unmapped address 0x{address:x}"
        return False  # Don't handle it, let it error

    def _map_new(self, addr: int, size: int) -> None:
        """Map a fresh, page-aligned region that does not overlap existing maps.

        On RV64, ``lui`` sign-extends, so an address like 0x80100000 built with
        lui+addi becomes 0xFFFFFFFF80100000. Real hardware with a 32-bit
        physical address space treats these as the same location, so for such
        ISAs any region in [0x80000000, 0x100000000) is also mapped at its
        sign-extended alias, backed by the same host memory.
        """
        mirror = self.spec.sign_extends_32bit_addresses
        if mirror and addr >= 0x80000000 and addr + size <= 0x100000000:
            buf = ctypes.create_string_buffer(size)
            self._mem_buffers.append(buf)  # keep host memory alive
            ptr = ctypes.addressof(buf)
            self._uc.mem_map_ptr(addr, size, UC_PROT_ALL, ptr)
            self._uc.mem_map_ptr(addr | 0xFFFFFFFF00000000, size, UC_PROT_ALL, ptr)
        else:
            self._uc.mem_map(addr, size, UC_PROT_ALL)

    def _ensure_mapped(self, addr: int, size: int) -> None:
        """Map every page in [addr, addr+size) that is not already mapped."""
        start = addr & ~(PAGE_SIZE - 1)
        end = (addr + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        if end <= start:
            return

        cur = start
        # mem_regions() yields (begin, end_inclusive, perms)
        for begin, last, _perms in sorted(self._uc.mem_regions()):
            region_end = last + 1
            if region_end <= cur or begin >= end:
                continue
            if begin > cur:
                self._map_new(cur, begin - cur)
            cur = max(cur, region_end)
            if cur >= end:
                return
        if cur < end:
            self._map_new(cur, end - cur)

    def _map_default_memory(self) -> None:
        """Map the ISA's text/data area and stack so programs can run without an ELF.

        Address 0 is deliberately left unmapped on every ISA so that null
        pointer dereferences fault instead of silently succeeding.
        """
        layout = self.layout
        self._ensure_mapped(layout.text_base, DEFAULT_REGION_SIZE)
        if not layout.text_base <= layout.data_base < layout.text_base + DEFAULT_REGION_SIZE:
            self._ensure_mapped(layout.data_base, DEFAULT_REGION_SIZE)
        self._setup_stack()
        # Start at the conventional code address rather than 0
        self.set_pc(layout.text_base)

    def _load_segments(self, segments: List[ELFSegment]) -> None:
        """Map memory for ELF segments and copy in their contents"""
        for segment in segments:
            if segment.memsz == 0:
                continue
            self._ensure_mapped(segment.vaddr, segment.memsz)
            if segment.data:
                self._uc.mem_write(segment.vaddr, segment.data)
            # Zero-fill BSS (if memsz > filesz)
            if segment.memsz > segment.filesz:
                bss_size = segment.memsz - segment.filesz
                self._uc.mem_write(segment.vaddr + segment.filesz, b"\x00" * bss_size)

    def _setup_stack(self) -> None:
        """Map stack memory and point the stack pointer at its top"""
        layout = self.layout
        self._ensure_mapped(layout.stack_top - layout.stack_size, layout.stack_size)
        self._uc.reg_write(self._engine.sp_reg, layout.stack_top - 8)

    def load_elf(self, elf_path: str) -> bool:
        """
        Load an ELF file into simulator memory

        Args:
            elf_path (str): Path to an ELF executable for any supported ISA

        Returns:
            bool: True if successful
        """
        elf_info = load_elf_file(elf_path)

        # A simulator created for a specific ISA only accepts that ISA; one
        # created without an ISA adopts whatever each loaded ELF uses.
        if self._explicit_isa and self._spec is not elf_info.spec:
            raise RuntimeError(
                f"ELF ISA ({elf_info.spec.isa.name}) doesn't match simulator ISA "
                f"({self.get_isa_name()})"
            )
        # Start from a fresh machine so nothing from a previous program
        # (memory, registers, exit state) leaks into this one.
        self._init_machine(elf_info.spec)
        self._elf_path = elf_path
        self._load_segments(elf_info.segments)
        self._setup_stack()
        self._entry_point = elf_info.entry
        self.set_pc(elf_info.entry)
        self._symbols = SymbolTable(elf_info.symbols)
        self._sections = elf_info.sections
        self._tohost_addr = self._symbols.lookup("tohost")
        return True

    # --- Execution ---

    def _read_word(self, addr: int, size: int) -> Optional[int]:
        """The ``size`` bytes at ``addr`` as an integer in the ISA's byte order"""
        try:
            return int.from_bytes(self._uc.mem_read(addr, size), self.spec.byteorder)
        except UcError:
            return None

    def _is_syscall(self, pc: int) -> bool:
        pattern = self.spec.syscall_instruction
        word = self._read_word(pc, pattern.size)
        return word is not None and pattern.matches(word)

    def step(self) -> StepResult:
        """
        Execute one instruction

        A syscall instruction is not executed by the CPU: step() moves the PC
        past it and returns SYSCALL, and check_termination() performs it.

        Returns:
            StepResult: Result code (OK, HALT, SYSCALL, or ERROR)
        """
        if self._uc is None:
            return StepResult.ERROR

        # Once the program has exited there is nothing left to execute
        if self.exited:
            return StepResult.HALT

        self._last_error = None
        pc = self.get_pc()

        if self._is_syscall(pc):
            self.set_pc(pc + self.spec.syscall_instruction.size)
            return StepResult.SYSCALL

        try:
            # count=1 executes one instruction. The end address must be past
            # it (MIPS does not advance with pc+4, so use a larger offset).
            self._uc.emu_start(pc, pc + 0x10000, count=1)
        except UcError as e:
            # Prefer the specific description recorded by the unmapped-memory
            # hook (it includes the faulting address) over Unicorn's message.
            detail = self._last_error or self._describe_trap(pc) or _describe_uc_error(e)
            self._last_error = f"{detail} (at PC=0x{pc:x})"
            # Unicorn may leave PC anywhere after a fault; keep it on the
            # faulting instruction so the user can inspect it.
            self.set_pc(pc)
            return StepResult.ERROR

        return StepResult.OK

    def _describe_trap(self, pc: int) -> Optional[str]:
        """Explain a trap raised by a breakpoint-style instruction at ``pc``, if any."""
        word = self._read_word(pc, self.spec.min_instruction_size)
        return None if word is None else self.spec.describe_trap(word)

    def check_termination(self, step_result: StepResult) -> Tuple[bool, Optional[StopReason]]:
        """
        Check if program should terminate based on step result

        Performs the syscall if ``step_result`` is SYSCALL.

        Returns:
            tuple: (should_terminate, reason) where reason is a StopReason
            (EXIT, HALT, ERROR, or TOHOST) or None
        """
        if step_result == StepResult.SYSCALL:
            outcome = self._syscalls.handle(self)
            if outcome.error is not None:
                self._last_error = outcome.error
                return (True, StopReason.ERROR)
            if outcome.exit_code is not None:
                self._exit_code = outcome.exit_code
                return (True, StopReason.EXIT)

        if step_result == StepResult.HALT:
            return (True, StopReason.HALT)

        if step_result == StepResult.ERROR:
            return (True, StopReason.ERROR)

        # Check for tohost write (HTIF mechanism)
        if self._tohost_addr is not None and self._read_word(self._tohost_addr, 8):
            return (True, StopReason.TOHOST)

        return (False, None)

    def run_until(
        self,
        max_steps: Optional[int] = None,
        stop_before: Optional[Callable[[int], Optional[StopReason]]] = None,
    ) -> RunResult:
        """
        Run until the program stops, ``stop_before`` says to stop, or the step limit.

        Args:
            max_steps: Maximum number of instructions to execute (None for no limit)
            stop_before: Called with the PC before each instruction except the
                first (so a run can resume from a breakpoint); returning a
                StopReason (e.g. BREAKPOINT) stops the run there.
        """
        steps = 0
        pc = self.get_pc()
        while max_steps is None or steps < max_steps:
            pc = self.get_pc()
            if steps > 0 and stop_before is not None:
                reason = stop_before(pc)
                if reason is not None:
                    return RunResult(steps, reason, pc)
            result = self.step()
            steps += 1
            done, reason = self.check_termination(result)
            if done:
                return RunResult(steps, reason, pc)
        return RunResult(steps, None, pc)

    def run(self, max_steps: Optional[int] = None) -> int:
        """
        Run until halt, syscall exit, or max_steps reached

        Returns:
            int: Number of instructions executed
        """
        return self.run_until(max_steps).steps

    def reset(self) -> None:
        """Reset the simulator to its initial state

        If an ELF file was loaded it is reloaded from disk, restoring memory,
        registers, and the entry point, so the program can be run again.
        """
        if self._elf_path is not None:
            self.load_elf(self._elf_path)
        elif self._spec is not None:
            self._init_machine(self._spec)

    # --- ISA ---

    @property
    def spec(self) -> ISASpec:
        """Specification of the current ISA"""
        if self._spec is None:
            raise RuntimeError("Simulator ISA not set")
        return self._spec

    @property
    def layout(self) -> MemoryLayout:
        """Memory layout for the current ISA"""
        return self.spec.layout

    def get_isa(self) -> Optional[ISA]:
        """The current ISA, or None if not set yet"""
        return self._spec.isa if self._spec is not None else None

    def get_isa_name(self) -> str:
        """Name of the current ISA's enum member (e.g. "RISCV"), or "Unknown" """
        return self._spec.isa.name if self._spec is not None else "Unknown"

    # --- Registers ---

    def get_pc(self) -> int:
        """Get the program counter"""
        if self._uc is None:
            return 0
        return self._uc.reg_read(self._engine.pc_reg)

    def set_pc(self, pc: int) -> None:
        """Set the program counter"""
        if self._uc is not None:
            self._uc.reg_write(self._engine.pc_reg, pc)

    def get_register_count(self) -> int:
        """Number of general-purpose registers for the current ISA"""
        return self._spec.registers.count if self._spec is not None else 32

    def get_reg_name(self, n: int) -> str:
        """The ABI/conventional name for register n (e.g. "ra", "sp", "rax")"""
        if self._spec is None:
            return f"r{n}"
        names = self._spec.registers.names
        return names[n] if 0 <= n < len(names) else f"?{n}"

    def _check_reg(self, reg_num: int) -> int:
        count = self.spec.registers.count
        if not 0 <= reg_num < count:
            raise ValueError(f"Register number must be 0-{count - 1}, got {reg_num}")
        return self._engine.gpr_regs[reg_num]

    def get_reg(self, reg_num: int) -> int:
        """Get a general-purpose register's value"""
        if self._uc is None:
            return 0
        return self._uc.reg_read(self._check_reg(reg_num))

    def set_reg(self, reg_num: int, value: int) -> None:
        """
        Set a general-purpose register (value is truncated to 64 bits)

        Raises:
            ValueError: For an invalid register number or the hardwired zero register
        """
        if self._uc is None:
            return
        reg = self._check_reg(reg_num)
        if reg_num == self.spec.registers.zero_register:
            raise ValueError(
                f"Register {reg_num} ({self.get_reg_name(reg_num)}) is always zero "
                "and cannot be written"
            )
        self._uc.reg_write(reg, value & 0xFFFFFFFFFFFFFFFF)

    def get_all_regs(self) -> List[int]:
        """All general-purpose register values, by register number"""
        return [self.get_reg(i) for i in range(self.get_register_count())]

    def get_special_regs(self) -> List[int]:
        """Values of the ISA's other registers (e.g. MIPS hi and lo), in the
        order of ``spec.registers.special``"""
        if self._uc is None:
            return []
        return [self._uc.reg_read(reg) for reg in self._engine.special_regs]

    def get_flags(self) -> Optional[int]:
        """The condition-code register (e.g. x86 rflags, ARM64 nzcv), or None if
        the ISA has none; ``spec.registers.flags`` says which bits are which"""
        if self._uc is None or self._engine.flags_reg is None:
            return None
        return self._uc.reg_read(self._engine.flags_reg)

    # --- Memory ---

    def read_mem(self, addr: int, length: int) -> bytes:
        """Read memory (raises RuntimeError for unmapped addresses)"""
        if self._uc is None:
            raise RuntimeError("Simulator not initialized")
        try:
            return bytes(self._uc.mem_read(addr, length))
        except UcError as e:
            raise RuntimeError(f"Failed to read memory at 0x{addr:x}: {e}")

    def write_mem(self, addr: int, data: Union[bytes, str]) -> bool:
        """Write memory (a str is written as UTF-8); raises RuntimeError on failure"""
        if self._uc is None:
            raise RuntimeError("Simulator not initialized")
        if isinstance(data, str):
            data = data.encode("utf-8")
        try:
            self._uc.mem_write(addr, bytes(data))
            return True
        except UcError as e:
            raise RuntimeError(f"Failed to write memory at 0x{addr:x}: {e}")

    # --- Disassembly ---

    def disasm_with_size(self, addr: int, att: bool = False) -> Tuple[str, int]:
        """
        Disassemble the instruction at ``addr`` and return its size in bytes

        Callers that walk a range of instructions must advance by the size,
        since x86-64 instructions vary in length. On x86-64, ``att`` selects
        AT&T syntax instead of Intel syntax.
        """
        if self._disasm is None:
            raise RuntimeError("Simulator not initialized")
        # Near the end of a mapped region fewer bytes may be readable
        size = self._disasm.max_size
        while size > 0:
            try:
                return self._disasm.disassemble(self.read_mem(addr, size), addr, att)
            except RuntimeError:
                size -= 1
        return self._disasm.disassemble(b"", addr, att)

    def disasm(self, addr: int, att: bool = False) -> str:
        """Disassemble the instruction at ``addr`` (in AT&T syntax on x86-64 if ``att``)"""
        return self.disasm_with_size(addr, att)[0]

    # --- Symbols and sections ---

    @property
    def symbols(self) -> SymbolTable:
        """The loaded program's symbol table"""
        return self._symbols

    def get_symbols(self) -> Dict[str, int]:
        """All symbols as a dictionary mapping names to addresses"""
        return self._symbols.as_dict()

    def lookup_symbol(self, name: str) -> Optional[int]:
        """Address of a symbol, or None if not found"""
        return self._symbols.lookup(name)

    def addr_to_symbol(self, addr: int) -> Tuple[Optional[str], Optional[int]]:
        """(symbol_name, offset) for the nearest symbol at or before addr, or (None, None)"""
        return self._symbols.nearest(addr)

    def get_sections(self) -> List[ELFSection]:
        """Sections of the loaded ELF file"""
        return list(self._sections)

    def find_section(self, name: str) -> Optional[ELFSection]:
        """The loaded ELF file's section with this name, or None"""
        return next((s for s in self._sections if s.name == name), None)

    # --- Program state and I/O ---

    @property
    def last_error(self) -> Optional[str]:
        """Description of the most recent execution error, if any"""
        return self._last_error

    @property
    def exited(self) -> bool:
        """True once the program has exited via an exit syscall"""
        return self._exit_code is not None

    @property
    def exit_code(self) -> Optional[int]:
        """Exit code passed to the exit syscall (None if not exited)"""
        return self._exit_code

    @property
    def stdout(self) -> Optional[TextIO]:
        """Where program output goes (None for the process's stdout)"""
        return self._io.stdout

    @stdout.setter
    def stdout(self, stream: Optional[TextIO]) -> None:
        self._io.stdout = stream

    @property
    def stdin(self) -> Optional[TextIO]:
        """Where program input comes from (None for the process's stdin)"""
        return self._io.stdin

    @stdin.setter
    def stdin(self, stream: Optional[TextIO]) -> None:
        self._io.stdin = stream

    @property
    def output_needs_newline(self) -> bool:
        """True if program output so far did not end with a newline

        Consoles use this to avoid printing their own messages on the same
        line as program output.
        """
        return self._io.output_needs_newline

    @output_needs_newline.setter
    def output_needs_newline(self, value: bool) -> None:
        self._io.output_needs_newline = value

    def __enter__(self) -> UnicornSimulator:
        """Context manager support"""
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> None:
        """Context manager cleanup (Unicorn handles its own cleanup)"""


def detect_elf_isa(elf_path: str) -> ISA:
    """The ISA of an ELF file (ISA.UNKNOWN if it cannot be read or is unsupported)"""
    try:
        return load_elf_file(elf_path).isa
    except Exception:
        return ISA.UNKNOWN


def create_simulator(
    elf_path: Optional[str] = None, config_file: Optional[str] = None
) -> UnicornSimulator:
    """
    Create a simulator, loading ``elf_path`` (whose ISA it adopts) if given

    Without an ELF file the simulator is for RISC-V.
    """
    if not elf_path:
        return UnicornSimulator(isa=ISA.RISCV, config_file=config_file)
    isa = detect_elf_isa(elf_path)
    if isa == ISA.UNKNOWN:
        raise RuntimeError(f"Could not detect ISA from ELF file: {elf_path}")
    sim = UnicornSimulator(isa=isa, config_file=config_file)
    sim.load_elf(elf_path)
    return sim
