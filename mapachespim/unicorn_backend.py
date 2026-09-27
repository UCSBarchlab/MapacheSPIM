"""
Python bindings for Unicorn Engine-based simulator

Provides a Pythonic interface to the Unicorn CPU emulator for RISC-V, ARM64,
x86-64, and MIPS32.
"""

from __future__ import annotations

import ctypes
import struct
import sys
from enum import IntEnum
from typing import TYPE_CHECKING, Dict, List, Optional, TextIO, Tuple, Union

if TYPE_CHECKING:
    from unicorn import Uc

try:
    from unicorn import (
        UC_ARCH_ARM64,
        UC_ARCH_MIPS,
        UC_ARCH_RISCV,
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_UNMAPPED,
        UC_MEM_FETCH_UNMAPPED,
        UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_UNMAPPED,
        UC_MODE_64,
        UC_MODE_ARM,
        UC_MODE_BIG_ENDIAN,
        UC_MODE_MIPS32,
        UC_MODE_RISCV64,
        UC_PROT_ALL,
        Uc,
        UcError,
    )
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0
    from unicorn.mips_const import UC_MIPS_REG_0, UC_MIPS_REG_PC, UC_MIPS_REG_SP
    from unicorn.riscv_const import UC_RISCV_REG_PC, UC_RISCV_REG_SP, UC_RISCV_REG_X0
    from unicorn.x86_const import (
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
        UC_X86_REG_RAX,
        UC_X86_REG_RBP,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDI,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSI,
        UC_X86_REG_RSP,
    )
except ImportError as e:
    raise ImportError(
        f"Unicorn Engine not installed. Install with: pip install unicorn\nOriginal error: {e}"
    )

try:
    from capstone import (
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_RISCV,
        CS_ARCH_X86,
        CS_MODE_ARM,
        CS_MODE_BIG_ENDIAN,
        CS_MODE_MIPS32,
        CS_MODE_RISCV64,
        Cs,
    )
    from capstone import CS_MODE_64 as CS_MODE_X86_64
except ImportError as e:
    raise ImportError(
        f"Capstone not installed. Install with: pip install capstone\nOriginal error: {e}"
    )

from .elf_loader import ISA as ELF_ISA
from .elf_loader import ELFSegment, load_elf_file
from .memory_map import MemoryLayout, get_layout


class ISA(IntEnum):
    """ISA types supported by the simulator"""

    RISCV = 0
    ARM = 1
    X86_64 = 2
    MIPS = 3
    UNKNOWN = -1


class StepResult(IntEnum):
    """Result codes from step()"""

    OK = 0
    HALT = 1
    WAITING = 2
    SYSCALL = 3
    ERROR = -1


# RISC-V memory layout constants (kept for backward compatibility; see memory_map)
STACK_TOP = 0x83F00000
STACK_SIZE = 0x100000  # 1MB stack
STACK_ADDR = STACK_TOP - STACK_SIZE  # Bottom of stack

PAGE_SIZE = 0x1000

_UNMAPPED_ACCESS_KINDS = {
    UC_MEM_READ_UNMAPPED: "Read from",
    UC_MEM_WRITE_UNMAPPED: "Write to",
    UC_MEM_FETCH_UNMAPPED: "Instruction fetch from",
}

# Size of the region mapped at the start of each ISA's text/data areas so that
# small hand-written programs work without an ELF file.
DEFAULT_REGION_SIZE = 0x400000

_ISA_LAYOUT_NAMES = {
    0: "riscv64",  # ISA.RISCV
    1: "arm64",  # ISA.ARM
    2: "x86_64",  # ISA.X86_64
    3: "mips32",  # ISA.MIPS
}

# SPIM-compatible syscall numbers
SYSCALL_PRINT_INT = 1
SYSCALL_PRINT_STRING = 4
SYSCALL_READ_INT = 5
SYSCALL_EXIT = 10
SYSCALL_PRINT_CHAR = 11
SYSCALL_READ_CHAR = 12
SYSCALL_EXIT2 = 17
SYSCALL_EXIT_CODE = 93

SUPPORTED_SYSCALLS = (
    SYSCALL_PRINT_INT,
    SYSCALL_PRINT_STRING,
    SYSCALL_READ_INT,
    SYSCALL_EXIT,
    SYSCALL_PRINT_CHAR,
    SYSCALL_READ_CHAR,
    SYSCALL_EXIT2,
    SYSCALL_EXIT_CODE,
)


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


class ISAConfig:
    """Base class for ISA-specific configuration"""

    arch: int
    mode: int

    def __init__(self, arch: int, mode: int) -> None:
        self.arch = arch
        self.mode = mode

    def get_pc_reg(self) -> int:
        """Get the program counter register constant"""
        raise NotImplementedError

    def get_sp_reg(self) -> int:
        """Get the stack pointer register constant"""
        raise NotImplementedError

    def get_gpr_reg(self, n: int) -> int:
        """Get general purpose register constant for register n (0-31)"""
        raise NotImplementedError

    def get_reg_name(self, n: int) -> str:
        """Get register name for register n"""
        raise NotImplementedError

    def detect_syscall(self, uc: Uc, pc: int) -> bool:
        """Detect if instruction at PC is a syscall"""
        raise NotImplementedError


class RISCVConfig(ISAConfig):
    """RISC-V 64-bit configuration"""

    def __init__(self) -> None:
        super().__init__(UC_ARCH_RISCV, UC_MODE_RISCV64)

    def get_pc_reg(self) -> int:
        return UC_RISCV_REG_PC

    def get_sp_reg(self) -> int:
        return UC_RISCV_REG_SP

    def get_gpr_reg(self, n: int) -> int:
        """Get RISC-V register constant for x0-x31"""
        if not 0 <= n <= 31:
            raise ValueError(f"Register number must be 0-31, got {n}")
        return UC_RISCV_REG_X0 + n

    def get_reg_name(self, n: int) -> str:
        """Get RISC-V register ABI name"""
        abi_names = [
            "zero",
            "ra",
            "sp",
            "gp",
            "tp",
            "t0",
            "t1",
            "t2",
            "s0",
            "s1",
            "a0",
            "a1",
            "a2",
            "a3",
            "a4",
            "a5",
            "a6",
            "a7",
            "s2",
            "s3",
            "s4",
            "s5",
            "s6",
            "s7",
            "s8",
            "s9",
            "s10",
            "s11",
            "t3",
            "t4",
            "t5",
            "t6",
        ]
        return abi_names[n] if 0 <= n <= 31 else f"x{n}"

    def detect_syscall(self, uc: Uc, pc: int) -> bool:
        """Check if instruction at PC is 'ecall' (0x00000073)"""
        try:
            instr_bytes = uc.mem_read(pc, 4)
            instr = struct.unpack("<I", instr_bytes)[0]
            return instr == 0x00000073  # ecall instruction
        except Exception:
            return False


class ARM64Config(ISAConfig):
    """ARM64 (AArch64) configuration"""

    def __init__(self) -> None:
        super().__init__(UC_ARCH_ARM64, UC_MODE_ARM)

    def get_pc_reg(self) -> int:
        return UC_ARM64_REG_PC

    def get_sp_reg(self) -> int:
        return UC_ARM64_REG_SP

    def get_gpr_reg(self, n: int) -> int:
        """Get ARM64 register constant for x0-x30, sp"""
        if not 0 <= n <= 31:
            raise ValueError(f"Register number must be 0-31, got {n}")
        if n == 31:
            return UC_ARM64_REG_SP
        return UC_ARM64_REG_X0 + n

    def get_reg_name(self, n: int) -> str:
        """Get ARM64 register name"""
        if n == 31:
            return "sp"
        return f"x{n}" if 0 <= n <= 30 else f"?{n}"

    def detect_syscall(self, uc: Uc, pc: int) -> bool:
        """Check if instruction at PC is 'svc #0' or similar"""
        try:
            instr_bytes = uc.mem_read(pc, 4)
            instr = struct.unpack("<I", instr_bytes)[0]
            # SVC instruction: 1101 0100 000x xxxx xxxx xxxx xxx0 0001
            return (instr & 0xFFE0001F) == 0xD4000001
        except Exception:
            return False


class X86_64Config(ISAConfig):
    """x86-64 configuration"""

    # x86-64 register constants ordered for our API
    _GPR_REGS: List[int] = [
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RBX,
        UC_X86_REG_RSP,
        UC_X86_REG_RBP,
        UC_X86_REG_RSI,
        UC_X86_REG_RDI,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
    ]

    _GPR_NAMES: List[str] = [
        "rax",
        "rcx",
        "rdx",
        "rbx",
        "rsp",
        "rbp",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]

    def __init__(self) -> None:
        super().__init__(UC_ARCH_X86, UC_MODE_64)

    def get_pc_reg(self) -> int:
        return UC_X86_REG_RIP

    def get_sp_reg(self) -> int:
        return UC_X86_REG_RSP

    def get_gpr_reg(self, n: int) -> int:
        """Get x86-64 register constant for register n (0-15)"""
        if not 0 <= n <= 15:
            raise ValueError(f"Register number must be 0-15 for x86-64, got {n}")
        return self._GPR_REGS[n]

    def get_reg_name(self, n: int) -> str:
        """Get x86-64 register name"""
        if 0 <= n <= 15:
            return self._GPR_NAMES[n]
        return f"?{n}"

    def detect_syscall(self, uc: Uc, pc: int) -> bool:
        """Check if instruction at PC is 'syscall' (0x0F 0x05)"""
        try:
            instr_bytes = uc.mem_read(pc, 2)
            return instr_bytes[0] == 0x0F and instr_bytes[1] == 0x05
        except Exception:
            return False


class MIPSConfig(ISAConfig):
    """MIPS32 configuration"""

    # MIPS register names in standard order ($0-$31)
    _GPR_NAMES: List[str] = [
        "zero",
        "at",
        "v0",
        "v1",  # $0-$3
        "a0",
        "a1",
        "a2",
        "a3",  # $4-$7
        "t0",
        "t1",
        "t2",
        "t3",  # $8-$11
        "t4",
        "t5",
        "t6",
        "t7",  # $12-$15
        "s0",
        "s1",
        "s2",
        "s3",  # $16-$19
        "s4",
        "s5",
        "s6",
        "s7",  # $20-$23
        "t8",
        "t9",  # $24-$25
        "k0",
        "k1",  # $26-$27
        "gp",
        "sp",
        "fp",
        "ra",  # $28-$31
    ]

    def __init__(self) -> None:
        # MIPS32 big-endian mode
        super().__init__(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)

    def get_pc_reg(self) -> int:
        return UC_MIPS_REG_PC

    def get_sp_reg(self) -> int:
        return UC_MIPS_REG_SP

    def get_gpr_reg(self, n: int) -> int:
        """Get MIPS register constant for $0-$31"""
        if not 0 <= n <= 31:
            raise ValueError(f"Register number must be 0-31, got {n}")
        return UC_MIPS_REG_0 + n

    def get_reg_name(self, n: int) -> str:
        """Get MIPS register name"""
        if 0 <= n <= 31:
            return self._GPR_NAMES[n]
        return f"?{n}"

    def detect_syscall(self, uc: Uc, pc: int) -> bool:
        """Check if instruction at PC is 'syscall' (0x0000000C)"""
        try:
            instr_bytes = uc.mem_read(pc, 4)
            # MIPS is big-endian in our configuration
            instr = struct.unpack(">I", instr_bytes)[0]
            return instr == 0x0000000C  # syscall instruction
        except Exception:
            return False


class Disassembler:
    """Capstone-based disassembler for RISC-V, ARM64, x86-64, and MIPS"""

    _cs: Cs
    _isa: ISA

    def __init__(self, isa: ISA) -> None:
        if isa == ISA.RISCV:
            self._cs = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        elif isa == ISA.ARM:
            self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif isa == ISA.X86_64:
            self._cs = Cs(CS_ARCH_X86, CS_MODE_X86_64)
        elif isa == ISA.MIPS:
            self._cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
        else:
            raise ValueError(f"Unsupported ISA for disassembly: {isa}")
        self._isa = isa

        self._cs.detail = False  # We don't need detailed instruction info

    def disassemble_one(self, simulator: UnicornSimulator, addr: int) -> str:
        """
        Disassemble single instruction at address

        Args:
            simulator: UnicornSimulator instance (to read memory)
            addr: Address of instruction

        Returns:
            str: Disassembled instruction string
        """
        try:
            # Read bytes - x86 instructions can be up to 15 bytes, RISC-V/ARM are 4
            read_size = 15 if self._isa == ISA.X86_64 else 4
            code = simulator.read_mem(addr, read_size)
        except Exception:
            return "<invalid address>"

        # Try to disassemble
        for instr in self._cs.disasm(code, addr, count=1):
            return f"{instr.mnemonic} {instr.op_str}".strip()

        # If disassembly failed, show raw bytes
        word = int.from_bytes(code[:4], byteorder="big" if self._isa == ISA.MIPS else "little")
        return f".word 0x{word:08x}"

    def disassemble_with_size(self, simulator: UnicornSimulator, addr: int) -> Tuple[str, int]:
        """
        Disassemble one instruction and report its length in bytes.

        x86-64 instructions are variable length, so callers that walk a range
        of instructions must use the returned size to find the next one.

        Returns:
            (text, size) - size is 4 for undecodable fixed-width instructions
            and 1 for undecodable x86 bytes.
        """
        read_size = 15 if self._isa == ISA.X86_64 else 4
        code = b""
        # Near the end of a mapped region fewer than 15 bytes may be readable
        while read_size > 0:
            try:
                code = simulator.read_mem(addr, read_size)
                break
            except Exception:
                read_size -= 1
        if not code:
            return ("<invalid address>", 4)

        for instr in self._cs.disasm(code, addr, count=1):
            return (f"{instr.mnemonic} {instr.op_str}".strip(), instr.size)

        if self._isa == ISA.X86_64:
            return (f".byte 0x{code[0]:02x}", 1)
        word = int.from_bytes(code[:4], byteorder="big" if self._isa == ISA.MIPS else "little")
        return (f".word 0x{word:08x}", 4)


class UnicornSimulator:
    """
    Unicorn Engine-based CPU emulator for RISC-V, ARM64, x86-64, and MIPS32

    Provides step-by-step execution, register/memory access, and state inspection.

    Program I/O from syscalls goes to ``stdout`` and comes from ``stdin``. Both
    default to the process streams (looked up at call time, so pytest's capsys
    and similar redirection work) and can be replaced, e.g. for autograding.
    """

    stdout: Optional[TextIO]
    stdin: Optional[TextIO]

    _isa: Optional[ISA]
    _config: Optional[ISAConfig]
    _uc: Optional[Uc]
    _symbols: Dict[str, int]
    _addr_to_symbol: Dict[int, Tuple[str, int]]
    _disasm: Optional[Disassembler]
    _entry_point: Optional[int]
    _pending_syscall: bool
    _last_error: Optional[str]
    _elf_path: Optional[str]
    _explicit_isa: bool
    _mem_buffers: List[ctypes.Array]
    _exited: bool
    _exit_code: Optional[int]
    _output_needs_newline: bool
    _input_buffer: str
    _tohost_addr: Optional[int]

    def __init__(self, isa: Optional[ISA] = None, config_file: Optional[str] = None) -> None:
        """
        Initialize the simulator

        Args:
            isa (ISA, optional): ISA to use (ISA.RISCV, ISA.ARM, ISA.X86_64, ISA.MIPS).
                                If None, will be auto-detected from ELF file during load_elf()
            config_file (str, optional): Not used by Unicorn backend (for compatibility)
        """
        self._isa = isa
        self._explicit_isa = isa is not None
        self._config = None
        self._uc = None
        self._symbols = {}
        self._addr_to_symbol = {}
        self._disasm = None
        self._entry_point = None
        self._pending_syscall = False
        self._last_error = None
        self._elf_path = None
        self._mem_buffers = []
        self._exited = False
        self._exit_code = None
        self._output_needs_newline = False
        self._input_buffer = ""
        self._tohost_addr = None
        self.stdout = None
        self.stdin = None

        # If ISA is specified, initialize Unicorn now
        if isa is not None:
            self._init_unicorn(isa)

    def _init_unicorn(self, isa: ISA) -> None:
        """Initialize Unicorn engine with ISA-specific configuration"""
        if isa == ISA.RISCV:
            self._config = RISCVConfig()
        elif isa == ISA.ARM:
            self._config = ARM64Config()
        elif isa == ISA.X86_64:
            self._config = X86_64Config()
        elif isa == ISA.MIPS:
            self._config = MIPSConfig()
        else:
            raise ValueError(f"Unsupported ISA: {isa}")

        # Create Unicorn instance
        try:
            self._uc = Uc(self._config.arch, self._config.mode)
        except UcError as e:
            raise RuntimeError(f"Failed to initialize Unicorn: {e}")
        self._isa = isa
        self._mem_buffers = []
        self._exited = False
        self._exit_code = None
        self._last_error = None
        self._input_buffer = ""
        self._pending_syscall = False
        self._symbols = {}
        self._addr_to_symbol = {}
        self._tohost_addr = None

        # Create disassembler
        self._disasm = Disassembler(isa)

        # Map a default memory region for tests that don't load ELF files
        # This ensures basic operations like write_mem work even without load_elf
        self._map_default_memory()

        # Install syscall detection hook
        self._install_syscall_hook()

        # Install unmapped memory handler
        self._install_unmapped_handler()

    def _install_syscall_hook(self) -> None:
        """Install code hook to detect syscalls"""

        def syscall_hook(uc: Uc, address: int, size: int, user_data: Optional[object]) -> None:
            # Check if this is a syscall instruction
            if self._config.detect_syscall(uc, address):
                self._pending_syscall = True
                uc.emu_stop()

        self._uc.hook_add(UC_HOOK_CODE, syscall_hook)

    def _install_unmapped_handler(self) -> None:
        """Install hook to handle unmapped memory accesses"""

        def unmapped_handler(
            uc: Uc, access: int, address: int, size: int, value: int, user_data: Optional[object]
        ) -> bool:
            kind = _UNMAPPED_ACCESS_KINDS.get(access, "access")
            self._last_error = f"{kind} unmapped address 0x{address:x}"
            return False  # Don't handle it, let it error

        self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_handler)

    @property
    def layout(self) -> MemoryLayout:
        """Memory layout for the current ISA"""
        if self._isa is None:
            raise RuntimeError("Simulator ISA not set")
        return get_layout(_ISA_LAYOUT_NAMES[int(self._isa)])

    def _map_new(self, addr: int, size: int) -> None:
        """Map a fresh, page-aligned region that does not overlap existing maps.

        On RV64, ``lui`` sign-extends, so an address like 0x80100000 built with
        lui+addi becomes 0xFFFFFFFF80100000. Real hardware with a 32-bit
        physical address space treats these as the same location, so any
        region in [0x80000000, 0x100000000) is also mapped at its sign-extended
        alias, backed by the same host memory.
        """
        if self._isa == ISA.RISCV and addr >= 0x80000000 and addr + size <= 0x100000000:
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
        stack_bottom = layout.stack_top - layout.stack_size
        stack_span = layout.stack_size
        if self._isa == ISA.RISCV:
            # RISC-V has historically mapped one page above stack_top too
            stack_span += PAGE_SIZE
        self._ensure_mapped(stack_bottom, stack_span)
        # Start at the conventional code address rather than 0
        self.set_pc(layout.text_base)

    def _map_memory_for_segments(self, segments: List[ELFSegment]) -> None:
        """Map memory regions for ELF segments and copy in their contents"""
        for segment in segments:
            if segment.memsz == 0:
                continue
            self._ensure_mapped(segment.vaddr, segment.memsz)

            if segment.data:
                self._uc.mem_write(segment.vaddr, segment.data)

            # Zero-fill BSS (if memsz > filesz)
            if segment.memsz > segment.filesz:
                bss_size = segment.memsz - segment.filesz
                bss_addr = segment.vaddr + segment.filesz
                self._uc.mem_write(bss_addr, b"\x00" * bss_size)

    def _setup_stack(self) -> None:
        """Map stack memory and point the stack pointer at its top"""
        layout = self.layout
        self._ensure_mapped(layout.stack_top - layout.stack_size, layout.stack_size)
        self._uc.reg_write(self._config.get_sp_reg(), layout.stack_top - 8)

    def load_elf(self, elf_path: str) -> bool:
        """
        Load an ELF file into simulator memory

        Args:
            elf_path (str): Path to RISC-V or ARM ELF executable

        Returns:
            bool: True if successful
        """
        # Parse ELF file
        elf_info = load_elf_file(elf_path)

        # Convert ELF ISA enum to our ISA enum
        if elf_info.isa == ELF_ISA.RISCV:
            detected_isa = ISA.RISCV
        elif elf_info.isa == ELF_ISA.ARM:
            detected_isa = ISA.ARM
        elif elf_info.isa == ELF_ISA.X86_64:
            detected_isa = ISA.X86_64
        elif elf_info.isa == ELF_ISA.MIPS:
            detected_isa = ISA.MIPS
        else:
            raise RuntimeError(f"Unknown ISA in ELF file: {elf_path}")

        # A simulator created for a specific ISA only accepts that ISA; one
        # created without an ISA adopts whatever each loaded ELF uses.
        if self._explicit_isa and self._isa != detected_isa:
            raise RuntimeError(
                f"ELF ISA ({detected_isa.name}) doesn't match simulator ISA ({self._isa.name})"
            )
        # Start from a fresh machine so nothing from a previous program
        # (memory, registers, exit state) leaks into this one.
        self._init_unicorn(detected_isa)
        self._elf_path = elf_path

        # Map memory for ELF segments
        self._map_memory_for_segments(elf_info.segments)

        # Setup stack
        self._setup_stack()

        # Set program counter to entry point
        self._entry_point = elf_info.entry
        self.set_pc(elf_info.entry)

        # Store symbol table
        self._symbols = elf_info.symbols

        # Build reverse mapping (addr -> symbol)
        self._addr_to_symbol = {addr: name for name, addr in self._symbols.items()}
        self._tohost_addr = self._symbols.get("tohost")

        return True

    def step(self) -> StepResult:
        """
        Execute one instruction

        Returns:
            StepResult: Result code (OK, HALT, WAITING, SYSCALL, or ERROR)
        """
        if self._uc is None:
            return StepResult.ERROR

        # Once the program has exited there is nothing left to execute
        if self._exited:
            return StepResult.HALT

        self._pending_syscall = False
        self._last_error = None
        pc = self.get_pc()

        try:
            # Execute one instruction
            # Use a large end address - the count=1 ensures we stop after one instruction.
            # Note: MIPS has a Unicorn quirk where pc+4 as end address doesn't advance PC.
            # Using a larger offset (0x10000) works for all ISAs.
            end_addr = pc + 0x10000
            # The hook will stop execution if a syscall is detected
            self._uc.emu_start(pc, end_addr, count=1)
        except UcError as e:
            # Prefer the specific description recorded by the unmapped-memory
            # hook (it includes the faulting address) over Unicorn's message.
            detail = self._last_error or self._describe_trap(pc) or _describe_uc_error(e)
            self._last_error = f"{detail} (at PC=0x{pc:x})"
            # Unicorn may leave PC anywhere after a fault; keep it on the
            # faulting instruction so the user can inspect it.
            self.set_pc(pc)
            return StepResult.ERROR

        # Check if we hit a syscall
        if self._pending_syscall:
            # Advance PC past the syscall instruction
            # x86-64 syscall is 2 bytes, RISC-V ecall/ARM svc are 4 bytes
            syscall_size = 2 if self._isa == ISA.X86_64 else 4
            self.set_pc(pc + syscall_size)
            return StepResult.SYSCALL

        return StepResult.OK

    def _describe_trap(self, pc: int) -> Optional[str]:
        """Explain a trap raised by a breakpoint instruction at ``pc``, if any.

        Assemblers use these for runtime checks: MIPS div/rem expand to
        code that executes 'break 7' on division by zero and 'break 6' on
        overflow, as SPIM and GNU as do.
        """
        try:
            word = self.read_mem(pc, 4)
        except RuntimeError:
            return None
        if self._isa == ISA.MIPS:
            instr = int.from_bytes(word, "big")
            if instr & 0xFC00003F == 0x0000000D:  # break
                code = (instr >> 16) & 0x3FF
                if code == 7:
                    return "Division by zero"
                if code == 6:
                    return "Integer overflow in division (-2147483648 / -1)"
                return f"Break instruction executed (break {code})"
        elif self._isa == ISA.RISCV:
            if int.from_bytes(word, "little") == 0x00100073:
                return "ebreak instruction executed"
        elif self._isa == ISA.ARM:
            instr = int.from_bytes(word, "little")
            if instr & 0xFFE0001F == 0xD4200000:  # brk #imm
                return f"brk instruction executed (brk #{(instr >> 5) & 0xFFFF})"
        return None

    def run(self, max_steps: Optional[int] = None) -> int:
        """
        Run until halt, syscall exit, or max_steps reached

        Args:
            max_steps (int, optional): Maximum number of instructions to execute

        Returns:
            int: Number of instructions executed
        """
        steps_executed = 0

        while max_steps is None or steps_executed < max_steps:
            result = self.step()
            steps_executed += 1

            # Check for termination
            should_terminate, reason = self.check_termination(result)
            if should_terminate:
                break

        return steps_executed

    def get_pc(self) -> int:
        """Get the program counter"""
        if self._uc is None:
            return 0
        return self._uc.reg_read(self._config.get_pc_reg())

    def set_pc(self, pc: int) -> None:
        """Set the program counter"""
        if self._uc is not None:
            self._uc.reg_write(self._config.get_pc_reg(), pc)

    def get_reg(self, reg_num: int) -> int:
        """
        Get register value

        Args:
            reg_num (int): Register number (0-31 for RISC-V/ARM, 0-15 for x86-64)

        Returns:
            int: Register value (64-bit)
        """
        if self._uc is None:
            return 0

        max_reg = 15 if self._isa == ISA.X86_64 else 31
        if not 0 <= reg_num <= max_reg:
            raise ValueError(f"Register number must be 0-{max_reg}, got {reg_num}")

        reg = self._config.get_gpr_reg(reg_num)
        return self._uc.reg_read(reg)

    def set_reg(self, reg_num: int, value: int) -> None:
        """
        Set register value

        Args:
            reg_num (int): Register number (1-31 for RISC-V, 0-15 for x86-64)
                          x0 is read-only on RISC-V
            value (int): Value to set (64-bit)
        """
        if self._uc is None:
            return

        if self._isa == ISA.X86_64:
            # x86-64: all 16 registers (0-15) are writable
            if not 0 <= reg_num <= 15:
                raise ValueError(f"Register number must be 0-15, got {reg_num}")
        else:
            # RISC-V/ARM: x0 is read-only
            if not 1 <= reg_num <= 31:
                raise ValueError(f"Register number must be 1-31, got {reg_num}")

        reg = self._config.get_gpr_reg(reg_num)
        self._uc.reg_write(reg, value & 0xFFFFFFFFFFFFFFFF)

    def read_mem(self, addr: int, length: int) -> bytes:
        """
        Read memory

        Args:
            addr (int): Memory address
            length (int): Number of bytes to read

        Returns:
            bytes: Memory contents
        """
        if self._uc is None:
            raise RuntimeError("Simulator not initialized")

        try:
            data = self._uc.mem_read(addr, length)
            # Unicorn returns bytearray, but API expects bytes
            return bytes(data)
        except UcError as e:
            raise RuntimeError(f"Failed to read memory at 0x{addr:x}: {e}")

    def write_mem(self, addr: int, data: Union[bytes, str]) -> bool:
        """
        Write memory

        Args:
            addr (int): Memory address
            data (bytes): Data to write

        Returns:
            bool: True if successful
        """
        if self._uc is None:
            raise RuntimeError("Simulator not initialized")

        if isinstance(data, str):
            data = data.encode("utf-8")

        try:
            self._uc.mem_write(addr, bytes(data))
            return True
        except UcError as e:
            raise RuntimeError(f"Failed to write memory at 0x{addr:x}: {e}")

    def disasm(self, addr: int) -> str:
        """
        Disassemble instruction at address

        Args:
            addr (int): Address of instruction to disassemble

        Returns:
            str: Disassembled instruction string
        """
        if self._disasm is None:
            raise RuntimeError("Simulator not initialized")

        return self._disasm.disassemble_one(self, addr)

    def disasm_with_size(self, addr: int) -> Tuple[str, int]:
        """
        Disassemble instruction at address and return its size in bytes

        Returns:
            tuple: (instruction text, instruction length in bytes)
        """
        if self._disasm is None:
            raise RuntimeError("Simulator not initialized")

        return self._disasm.disassemble_with_size(self, addr)

    def get_symbols(self) -> Dict[str, int]:
        """
        Get all symbols from the symbol table

        Returns:
            dict: Dictionary mapping symbol names to addresses
        """
        return self._symbols.copy()

    def lookup_symbol(self, name: str) -> Optional[int]:
        """
        Look up symbol address by name

        Args:
            name (str): Symbol name to look up

        Returns:
            int: Symbol address, or None if not found
        """
        return self._symbols.get(name)

    def addr_to_symbol(self, addr: int) -> Tuple[Optional[str], Optional[int]]:
        """
        Convert address to symbol name + offset

        Args:
            addr (int): Address to look up

        Returns:
            tuple: (symbol_name, offset) if found, or (None, None) if not found
        """
        # Maximum distance to consider a symbol match (1MB)
        MAX_SYMBOL_DISTANCE = 0x100000

        # Exact match
        if addr in self._addr_to_symbol:
            return (self._addr_to_symbol[addr], 0)

        # Find closest symbol before this address
        best_match = None
        best_addr = None

        for sym_name, sym_addr in self._symbols.items():
            if sym_addr <= addr:
                if best_addr is None or sym_addr > best_addr:
                    best_addr = sym_addr
                    best_match = sym_name

        if best_match:
            offset = addr - best_addr
            # Only return if within reasonable distance
            if offset <= MAX_SYMBOL_DISTANCE:
                return (best_match, offset)

        return (None, None)

    def reset(self) -> None:
        """Reset the simulator to its initial state

        If an ELF file was loaded it is reloaded from disk, restoring memory,
        registers, and the entry point, so the program can be run again.
        """
        if self._elf_path is not None:
            self.load_elf(self._elf_path)
        elif self._isa is not None:
            # Unicorn doesn't have a native reset, so we reinitialize
            self._init_unicorn(self._isa)

    @property
    def last_error(self) -> Optional[str]:
        """Description of the most recent execution error, if any"""
        return self._last_error

    @property
    def exited(self) -> bool:
        """True once the program has exited via an exit syscall"""
        return self._exited

    @property
    def exit_code(self) -> Optional[int]:
        """Exit code passed to the exit syscall (None if not exited)"""
        return self._exit_code

    @property
    def output_needs_newline(self) -> bool:
        """True if program output so far did not end with a newline

        Consoles use this to avoid printing their own messages on the same
        line as program output.
        """
        return self._output_needs_newline

    @output_needs_newline.setter
    def output_needs_newline(self, value: bool) -> None:
        self._output_needs_newline = value

    def get_all_regs(self) -> List[int]:
        """
        Get all register values as a list

        Returns:
            list: List of register values (32 for RISC-V/ARM, 16 for x86-64)
        """
        num_regs = 16 if self._isa == ISA.X86_64 else 32
        return [self.get_reg(i) for i in range(num_regs)]

    def get_isa(self) -> Optional[ISA]:
        """
        Get the current ISA

        Returns:
            ISA: The current ISA enum value (ISA.RISCV, ISA.ARM, ISA.X86_64), or None if not set
        """
        return self._isa

    def get_isa_name(self) -> str:
        """
        Get human-readable name of the current ISA

        Returns:
            str: ISA name (e.g., "RISCV", "ARM", "X86_64") or "Unknown" if not set
        """
        return self._isa.name if self._isa is not None else "Unknown"

    def get_register_count(self) -> int:
        """
        Get the number of general-purpose registers for the current ISA

        Returns:
            int: Number of GPRs (32 for RISC-V/ARM, 16 for x86-64)
        """
        if self._isa == ISA.X86_64:
            return 16
        return 32

    def get_reg_name(self, n: int) -> str:
        """
        Get the ABI/conventional name for register n

        Args:
            n: Register number

        Returns:
            str: Register name (e.g., "ra", "sp", "x0", "rax")
        """
        if self._config is None:
            return f"r{n}"
        return self._config.get_reg_name(n)

    def _get_syscall_regs(self) -> Tuple[int, int, int]:
        """
        Get syscall register mappings for current ISA

        Returns:
            tuple: (syscall_num_reg, arg0_reg, result_reg)
        """
        if self._isa == ISA.X86_64:
            # x86-64 Linux syscall ABI: rax=syscall#, rdi=arg0, return in rax
            # Our register indices: rax=0, rdi=7
            return (0, 7, 0)
        elif self._isa == ISA.MIPS:
            # MIPS SPIM ABI: $v0=syscall# (reg 2), $a0=arg0 (reg 4), return in $v0
            return (2, 4, 2)
        elif self._isa == ISA.ARM:
            # ARM64: x8=syscall#, x0=arg0, return in x0
            return (8, 0, 0)
        else:
            # RISC-V: a7=syscall# (x17), a0=arg0 (x10), return in a0
            return (17, 10, 10)

    def _write_output(self, text: str) -> None:
        """Write program output (from a print syscall)"""
        if not text:
            return
        stream = self.stdout if self.stdout is not None else sys.stdout
        stream.write(text)
        stream.flush()
        self._output_needs_newline = not text.endswith("\n")

    def _read_input_line(self) -> Optional[str]:
        """Read one line of program input, without the newline (None on EOF)"""
        # Make sure any prompt the program printed is visible first
        out = self.stdout if self.stdout is not None else sys.stdout
        out.flush()
        # Pressing Enter echoes a newline, so the console is at a line start
        self._output_needs_newline = False
        if self.stdin is not None:
            line = self.stdin.readline()
            if line == "":
                return None
            return line.rstrip("\r\n")
        try:
            # input() gives line editing on interactive terminals
            return input()
        except EOFError:
            return None

    def _signed(self, value: int) -> int:
        """Interpret a register value as a signed integer of the ISA's width"""
        bits = 32 if self._isa == ISA.MIPS else 64
        value &= (1 << bits) - 1
        if value & (1 << (bits - 1)):
            value -= 1 << bits
        return value

    def _read_c_string(self, addr: int, limit: int = 65536) -> str:
        """Read a NUL-terminated string from simulated memory"""
        data = bytearray()
        while len(data) < limit:
            # Read a chunk, shrinking near the end of a mapped region
            chunk = b""
            size = 256 - (addr % 256)
            while size > 0:
                try:
                    chunk = self.read_mem(addr, size)
                    break
                except RuntimeError:
                    size //= 2
            if not chunk:
                if not data:
                    raise RuntimeError(f"print_string: address 0x{addr:x} is not mapped")
                break
            nul = chunk.find(0)
            if nul >= 0:
                data += chunk[:nul]
                break
            data += chunk
            addr += len(chunk)
        return data.decode("utf-8", errors="replace")

    def _handle_syscall(self) -> Optional[str]:
        """
        Handle SPIM-compatible syscalls

        Returns:
            None to continue, "syscall_exit" if the program exited, or "error"
            (with ``last_error`` set) if the syscall could not be performed.
        """
        syscall_reg, arg_reg, result_reg = self._get_syscall_regs()
        syscall_num = self.get_reg(syscall_reg)

        if syscall_num == SYSCALL_PRINT_INT:
            self._write_output(str(self._signed(self.get_reg(arg_reg))))

        elif syscall_num == SYSCALL_PRINT_STRING:
            try:
                self._write_output(self._read_c_string(self.get_reg(arg_reg)))
            except RuntimeError as e:
                self._last_error = str(e)
                return "error"

        elif syscall_num == SYSCALL_READ_INT:
            # A partially consumed line (from read_char) is used first
            if self._input_buffer.strip():
                line: Optional[str] = self._input_buffer
            else:
                line = self._read_input_line()
            self._input_buffer = ""
            try:
                value = int((line or "").strip(), 0)
            except ValueError:
                value = 0
            self.set_reg(result_reg, value & 0xFFFFFFFFFFFFFFFF)

        elif syscall_num == SYSCALL_READ_CHAR:
            # Characters come from a line buffer so "ab<Enter>" yields a, b, \n
            if not self._input_buffer:
                line = self._read_input_line()
                self._input_buffer = "" if line is None else line + "\n"
            if self._input_buffer:
                char, self._input_buffer = self._input_buffer[0], self._input_buffer[1:]
                self.set_reg(result_reg, ord(char) & 0xFF)
            else:
                self.set_reg(result_reg, 0)  # EOF

        elif syscall_num == SYSCALL_PRINT_CHAR:
            self._write_output(chr(self.get_reg(arg_reg) & 0xFF))

        elif syscall_num == SYSCALL_EXIT:
            self._exited = True
            self._exit_code = 0
            return "syscall_exit"

        elif syscall_num in (SYSCALL_EXIT2, SYSCALL_EXIT_CODE):
            self._exited = True
            self._exit_code = self._signed(self.get_reg(arg_reg)) & 0xFF
            return "syscall_exit"

        else:
            reg_name = self.get_reg_name(syscall_reg)
            supported = ", ".join(str(n) for n in SUPPORTED_SYSCALLS)
            self._last_error = (
                f"Unknown syscall number {self._signed(syscall_num)} in {reg_name} "
                f"(supported: {supported})"
            )
            return "error"

        return None

    def check_termination(self, step_result: StepResult) -> Tuple[bool, Optional[str]]:
        """
        Check if program should terminate based on step result

        Performs the syscall if ``step_result`` is SYSCALL.

        Args:
            step_result: Result from step()

        Returns:
            tuple: (should_terminate, reason) where reason is one of
            "syscall_exit", "halt", "error", "tohost", or None
        """
        if step_result == StepResult.SYSCALL:
            reason = self._handle_syscall()
            if reason is not None:
                return (True, reason)

        if step_result == StepResult.HALT:
            return (True, "halt")

        if step_result == StepResult.ERROR:
            return (True, "error")

        # Check for tohost write (HTIF mechanism)
        if self._tohost_addr is not None:
            try:
                tohost_bytes = self.read_mem(self._tohost_addr, 8)
                if int.from_bytes(tohost_bytes, byteorder="little") != 0:
                    return (True, "tohost")
            except RuntimeError:
                pass

        return (False, None)

    def __del__(self) -> None:
        """Cleanup when object is destroyed"""
        # Unicorn handles its own cleanup
        pass

    def __enter__(self) -> UnicornSimulator:
        """Context manager support"""
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> None:
        """Context manager cleanup"""
        # Unicorn handles its own cleanup
        pass


def detect_elf_isa(elf_path: str) -> ISA:
    """
    Detect the ISA of an ELF file without loading it

    Args:
        elf_path (str): Path to ELF file

    Returns:
        ISA: ISA type (ISA.RISCV, ISA.ARM, ISA.X86_64, ISA.MIPS, or ISA.UNKNOWN)
    """
    try:
        elf_info = load_elf_file(elf_path)
        if elf_info.isa == ELF_ISA.RISCV:
            return ISA.RISCV
        elif elf_info.isa == ELF_ISA.ARM:
            return ISA.ARM
        elif elf_info.isa == ELF_ISA.X86_64:
            return ISA.X86_64
        elif elf_info.isa == ELF_ISA.MIPS:
            return ISA.MIPS
    except Exception:
        pass

    return ISA.UNKNOWN


def create_simulator(
    elf_path: Optional[str] = None, config_file: Optional[str] = None
) -> UnicornSimulator:
    """
    Factory function to create a simulator with automatic ISA detection

    Args:
        elf_path (str, optional): Path to ELF file for ISA auto-detection
        config_file (str, optional): Not used by Unicorn backend

    Returns:
        UnicornSimulator: Initialized simulator instance
    """
    if elf_path:
        # Detect ISA from ELF file
        isa = detect_elf_isa(elf_path)
        if isa == ISA.UNKNOWN:
            raise RuntimeError(f"Could not detect ISA from ELF file: {elf_path}")

        # Create simulator with detected ISA
        sim = UnicornSimulator(isa=isa, config_file=config_file)

        # Load the ELF file
        sim.load_elf(elf_path)

        return sim
    else:
        # Default to RISC-V
        return UnicornSimulator(isa=ISA.RISCV, config_file=config_file)
