"""
Python bindings for Unicorn Engine-based simulator

Provides a Pythonic interface to the Unicorn CPU emulator for RISC-V and ARM.
This replaces the SAIL-based backend with a more stable, battle-tested emulation engine.
"""

import struct
from enum import IntEnum
from pathlib import Path

try:
    from unicorn import Uc, UcError, UC_ARCH_RISCV, UC_MODE_RISCV64, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import UC_ARCH_X86, UC_MODE_64
    from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.riscv_const import UC_RISCV_REG_PC, UC_RISCV_REG_X0, UC_RISCV_REG_SP
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_SP
    from unicorn.x86_const import (
        UC_X86_REG_RIP, UC_X86_REG_RSP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
    )
except ImportError as e:
    raise ImportError(
        "Unicorn Engine not installed. Install with: pip install unicorn\n"
        f"Original error: {e}"
    )

try:
    from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV64, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone import CS_ARCH_X86, CS_MODE_64 as CS_MODE_X86_64
except ImportError as e:
    raise ImportError(
        "Capstone not installed. Install with: pip install capstone\n"
        f"Original error: {e}"
    )

from .elf_loader import load_elf_file, ELFInfo, ISA as ELF_ISA


class ISA(IntEnum):
    """ISA types supported by the simulator"""
    RISCV = 0
    ARM = 1
    X86_64 = 2
    UNKNOWN = -1


class StepResult(IntEnum):
    """Result codes from step()"""
    OK = 0
    HALT = 1
    WAITING = 2
    SYSCALL = 3
    ERROR = -1


# Memory layout constants
# Stack grows downward from 0x83F00000 (this is the TOP of the stack)
STACK_TOP = 0x83F00000
STACK_SIZE = 0x100000  # 1MB stack
STACK_ADDR = STACK_TOP - STACK_SIZE  # Bottom of stack


class ISAConfig:
    """Base class for ISA-specific configuration"""

    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode

    def get_pc_reg(self):
        """Get the program counter register constant"""
        raise NotImplementedError

    def get_sp_reg(self):
        """Get the stack pointer register constant"""
        raise NotImplementedError

    def get_gpr_reg(self, n):
        """Get general purpose register constant for register n (0-31)"""
        raise NotImplementedError

    def get_reg_name(self, n):
        """Get register name for register n"""
        raise NotImplementedError

    def detect_syscall(self, uc, pc):
        """Detect if instruction at PC is a syscall"""
        raise NotImplementedError


class RISCVConfig(ISAConfig):
    """RISC-V 64-bit configuration"""

    def __init__(self):
        super().__init__(UC_ARCH_RISCV, UC_MODE_RISCV64)

    def get_pc_reg(self):
        return UC_RISCV_REG_PC

    def get_sp_reg(self):
        return UC_RISCV_REG_SP

    def get_gpr_reg(self, n):
        """Get RISC-V register constant for x0-x31"""
        if not 0 <= n <= 31:
            raise ValueError(f"Register number must be 0-31, got {n}")
        return UC_RISCV_REG_X0 + n

    def get_reg_name(self, n):
        """Get RISC-V register ABI name"""
        abi_names = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
            "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
            "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
        ]
        return abi_names[n] if 0 <= n <= 31 else f"x{n}"

    def detect_syscall(self, uc, pc):
        """Check if instruction at PC is 'ecall' (0x00000073)"""
        try:
            instr_bytes = uc.mem_read(pc, 4)
            instr = struct.unpack('<I', instr_bytes)[0]
            return instr == 0x00000073  # ecall instruction
        except Exception:
            return False


class ARM64Config(ISAConfig):
    """ARM64 (AArch64) configuration - Placeholder for Phase 3"""

    def __init__(self):
        super().__init__(UC_ARCH_ARM64, UC_MODE_ARM)

    def get_pc_reg(self):
        return UC_ARM64_REG_PC

    def get_sp_reg(self):
        return UC_ARM64_REG_SP

    def get_gpr_reg(self, n):
        """Get ARM64 register constant for x0-x30, sp"""
        if not 0 <= n <= 31:
            raise ValueError(f"Register number must be 0-31, got {n}")
        if n == 31:
            return UC_ARM64_REG_SP
        return UC_ARM64_REG_X0 + n

    def get_reg_name(self, n):
        """Get ARM64 register name"""
        if n == 31:
            return "sp"
        return f"x{n}" if 0 <= n <= 30 else f"?{n}"

    def detect_syscall(self, uc, pc):
        """Check if instruction at PC is 'svc #0' or similar"""
        try:
            instr_bytes = uc.mem_read(pc, 4)
            instr = struct.unpack('<I', instr_bytes)[0]
            # SVC instruction: 1101 0100 000x xxxx xxxx xxxx xxx0 0001
            return (instr & 0xFFE0001F) == 0xD4000001
        except Exception:
            return False


class X86_64Config(ISAConfig):
    """x86-64 configuration"""

    # x86-64 register constants ordered for our API
    _GPR_REGS = [
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
    ]

    _GPR_NAMES = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    ]

    def __init__(self):
        super().__init__(UC_ARCH_X86, UC_MODE_64)

    def get_pc_reg(self):
        return UC_X86_REG_RIP

    def get_sp_reg(self):
        return UC_X86_REG_RSP

    def get_gpr_reg(self, n):
        """Get x86-64 register constant for register n (0-15)"""
        if not 0 <= n <= 15:
            raise ValueError(f"Register number must be 0-15 for x86-64, got {n}")
        return self._GPR_REGS[n]

    def get_reg_name(self, n):
        """Get x86-64 register name"""
        if 0 <= n <= 15:
            return self._GPR_NAMES[n]
        return f"?{n}"

    def detect_syscall(self, uc, pc):
        """Check if instruction at PC is 'syscall' (0x0F 0x05)"""
        try:
            instr_bytes = uc.mem_read(pc, 2)
            return instr_bytes[0] == 0x0F and instr_bytes[1] == 0x05
        except Exception:
            return False


class Disassembler:
    """Capstone-based disassembler for RISC-V, ARM64, and x86-64"""

    def __init__(self, isa):
        if isa == ISA.RISCV:
            self._cs = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        elif isa == ISA.ARM:
            self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif isa == ISA.X86_64:
            self._cs = Cs(CS_ARCH_X86, CS_MODE_X86_64)
        else:
            raise ValueError(f"Unsupported ISA for disassembly: {isa}")
        self._isa = isa

        self._cs.detail = False  # We don't need detailed instruction info

    def disassemble_one(self, simulator, addr):
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
        if self._isa == ISA.X86_64:
            # Show first 4 bytes for x86
            word = int.from_bytes(code[:4], byteorder='little')
        else:
            word = int.from_bytes(code, byteorder='little')
        return f".word 0x{word:08x}"


class UnicornSimulator:
    """
    Unicorn Engine-based CPU emulator for RISC-V and ARM

    Provides step-by-step execution, register/memory access, and state inspection
    compatible with the original SAIL-based backend.
    """

    def __init__(self, isa=None, config_file=None):
        """
        Initialize the simulator

        Args:
            isa (ISA, optional): ISA to use (ISA.RISCV or ISA.ARM).
                                If None, will be auto-detected from ELF file during load_elf()
            config_file (str, optional): Not used by Unicorn backend (for compatibility)
        """
        self._isa = isa
        self._config = None
        self._uc = None
        self._symbols = {}
        self._addr_to_symbol = {}
        self._disasm = None
        self._entry_point = None
        self._pending_syscall = False
        self._last_error = None

        # If ISA is specified, initialize Unicorn now
        if isa is not None:
            self._init_unicorn(isa)

    def _init_unicorn(self, isa):
        """Initialize Unicorn engine with ISA-specific configuration"""
        if isa == ISA.RISCV:
            self._config = RISCVConfig()
        elif isa == ISA.ARM:
            self._config = ARM64Config()
        elif isa == ISA.X86_64:
            self._config = X86_64Config()
        else:
            raise ValueError(f"Unsupported ISA: {isa}")

        # Create Unicorn instance
        try:
            self._uc = Uc(self._config.arch, self._config.mode)
        except UcError as e:
            raise RuntimeError(f"Failed to initialize Unicorn: {e}")

        # Create disassembler
        self._disasm = Disassembler(isa)

        # Map a default memory region for tests that don't load ELF files
        # This ensures basic operations like write_mem work even without load_elf
        self._map_default_memory()

        # Install syscall detection hook
        self._install_syscall_hook()

        # Install unmapped memory handler
        self._install_unmapped_handler()

    def _install_syscall_hook(self):
        """Install code hook to detect syscalls"""
        def syscall_hook(uc, address, size, user_data):
            # Check if this is a syscall instruction
            if self._config.detect_syscall(uc, address):
                self._pending_syscall = True
                uc.emu_stop()

        self._uc.hook_add(UC_HOOK_CODE, syscall_hook)

    def _install_unmapped_handler(self):
        """Install hook to handle unmapped memory accesses"""
        def unmapped_handler(uc, access, address, size, value, user_data):
            self._last_error = f"Unmapped memory access at 0x{address:x}"
            return False  # Don't handle it, let it error

        self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_handler)

    def _map_default_memory(self):
        """Map default memory regions for tests without ELF files"""
        if self._config.arch == UC_ARCH_ARM64:
            # Map 1MB at address 0 for ARM tests
            try:
                self._uc.mem_map(0x0, 0x100000, UC_PROT_ALL)
            except UcError:
                pass
        elif self._config.arch == UC_ARCH_X86:
            # Map main region (4MB from 0x400000) for x86-64 executables
            try:
                self._uc.mem_map(0x400000, 0x400000, UC_PROT_ALL)
            except UcError:
                pass
            # Map stack region (2MB ending near 0x7FFFFFFFFFFF - typical Linux)
            try:
                self._uc.mem_map(0x7FFFFE00000, 0x200000, UC_PROT_ALL)
            except UcError:
                pass
        else:  # RISC-V
            # Map main region (4MB from 0x80000000)
            try:
                self._uc.mem_map(0x80000000, 0x400000, UC_PROT_ALL)
            except UcError:
                pass

            # Also map stack region for tests (include STACK_TOP itself)
            try:
                self._uc.mem_map(STACK_ADDR, STACK_SIZE + 0x100000, UC_PROT_ALL)
            except UcError:
                pass

    def _map_memory_for_segments(self, segments):
        """Map memory regions for ELF segments with page alignment"""
        for segment in segments:
            # Calculate page-aligned region
            page_size = 0x1000  # 4KB pages
            page_aligned_addr = segment.vaddr & ~(page_size - 1)
            end_addr = segment.vaddr + segment.memsz
            page_aligned_end = (end_addr + page_size - 1) & ~(page_size - 1)
            size = page_aligned_end - page_aligned_addr

            # Map memory with RWX permissions
            try:
                self._uc.mem_map(page_aligned_addr, size, UC_PROT_ALL)
            except UcError as e:
                # Region might overlap with already-mapped memory
                # This is OK - Unicorn will handle it
                pass

            # Write segment data
            if segment.data:
                self._uc.mem_write(segment.vaddr, segment.data)

            # Zero-fill BSS (if memsz > filesz)
            if segment.memsz > segment.filesz:
                bss_size = segment.memsz - segment.filesz
                bss_addr = segment.vaddr + segment.filesz
                self._uc.mem_write(bss_addr, b'\x00' * bss_size)

    def _setup_stack(self):
        """Map and initialize stack memory"""
        try:
            self._uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        except UcError as e:
            # Stack mapping can fail if already mapped - that's OK
            if "already" not in str(e).lower() and "map" not in str(e).lower():
                raise RuntimeError(f"Failed to setup stack: {e}")

        # Set stack pointer to top of stack (grows downward)
        # Note: Some programs set their own SP, which will override this
        sp_reg = self._config.get_sp_reg()
        self._uc.reg_write(sp_reg, STACK_TOP - 8)

    def load_elf(self, elf_path):
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
        else:
            raise RuntimeError(f"Unknown ISA in ELF file: {elf_path}")

        # Initialize Unicorn if not already done
        if self._isa is None:
            self._isa = detected_isa
            self._init_unicorn(detected_isa)
        elif self._isa != detected_isa:
            raise RuntimeError(
                f"ELF ISA ({detected_isa.name}) doesn't match simulator ISA ({self._isa.name})"
            )

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

        return True

    def step(self):
        """
        Execute one instruction

        Returns:
            StepResult: Result code (OK, HALT, WAITING, SYSCALL, or ERROR)
        """
        if self._uc is None:
            return StepResult.ERROR

        self._pending_syscall = False
        pc = self.get_pc()

        try:
            # Execute one instruction
            # x86 instructions can be up to 15 bytes, RISC-V/ARM are 4 bytes
            max_instr_size = 15 if self._isa == ISA.X86_64 else 4
            # The hook will stop execution if a syscall is detected
            self._uc.emu_start(pc, pc + max_instr_size, count=1)
        except UcError as e:
            self._last_error = f"Execution error at PC=0x{pc:x}: {e}"
            return StepResult.ERROR

        # Check if we hit a syscall
        if self._pending_syscall:
            # Advance PC past the syscall instruction
            # x86-64 syscall is 2 bytes, RISC-V ecall/ARM svc are 4 bytes
            syscall_size = 2 if self._isa == ISA.X86_64 else 4
            self.set_pc(pc + syscall_size)
            return StepResult.SYSCALL

        return StepResult.OK

    def run(self, max_steps=None):
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

    def get_pc(self):
        """Get the program counter"""
        if self._uc is None:
            return 0
        return self._uc.reg_read(self._config.get_pc_reg())

    def set_pc(self, pc):
        """Set the program counter"""
        if self._uc is not None:
            self._uc.reg_write(self._config.get_pc_reg(), pc)

    def get_reg(self, reg_num):
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

    def set_reg(self, reg_num, value):
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

    def read_mem(self, addr, length):
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

    def write_mem(self, addr, data):
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
            data = data.encode('utf-8')

        try:
            self._uc.mem_write(addr, bytes(data))
            return True
        except UcError as e:
            raise RuntimeError(f"Failed to write memory at 0x{addr:x}: {e}")

    def disasm(self, addr):
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

    def get_symbols(self):
        """
        Get all symbols from the symbol table

        Returns:
            dict: Dictionary mapping symbol names to addresses
        """
        return self._symbols.copy()

    def lookup_symbol(self, name):
        """
        Look up symbol address by name

        Args:
            name (str): Symbol name to look up

        Returns:
            int: Symbol address, or None if not found
        """
        return self._symbols.get(name)

    def addr_to_symbol(self, addr):
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

    def reset(self):
        """Reset the simulator to initial state"""
        # Unicorn doesn't have a native reset, so we reinitialize
        if self._isa is not None:
            self._init_unicorn(self._isa)
            if self._entry_point is not None:
                self.set_pc(self._entry_point)

    def get_all_regs(self):
        """
        Get all register values as a list

        Returns:
            list: List of register values (32 for RISC-V/ARM, 16 for x86-64)
        """
        num_regs = 16 if self._isa == ISA.X86_64 else 32
        return [self.get_reg(i) for i in range(num_regs)]

    def _get_syscall_regs(self):
        """
        Get syscall register mappings for current ISA

        Returns:
            tuple: (syscall_num_reg, arg0_reg, result_reg)
        """
        if self._isa == ISA.X86_64:
            # x86-64 Linux syscall ABI: rax=syscall#, rdi=arg0, return in rax
            # Our register indices: rax=0, rdi=7
            return (0, 7, 0)
        else:
            # RISC-V/ARM: a7=syscall# (x17), a0=arg0 (x10), return in a0
            return (17, 10, 10)

    def _handle_syscall(self):
        """
        Handle SPIM-compatible syscalls

        Returns:
            bool: True if program should exit, False otherwise
        """
        syscall_reg, arg_reg, result_reg = self._get_syscall_regs()
        syscall_num = self.get_reg(syscall_reg)

        if syscall_num == 1:
            # print_int - Print integer in arg0
            value = self.get_reg(arg_reg)
            # Convert to signed 64-bit for proper display
            if value & (1 << 63):
                value = value - (1 << 64)
            print(value, end='')

        elif syscall_num == 4:
            # print_string - Print null-terminated string at address in arg0
            addr = self.get_reg(arg_reg)
            chars = []
            try:
                while True:
                    byte = self.read_mem(addr, 1)[0]
                    if byte == 0:
                        break
                    chars.append(chr(byte))
                    addr += 1
                    if len(chars) > 4096:  # Safety limit
                        break
                print(''.join(chars), end='')
            except Exception:
                pass

        elif syscall_num == 5:
            # read_int - Read integer from stdin, return in result reg
            try:
                value = int(input())
                self.set_reg(result_reg, value & 0xFFFFFFFFFFFFFFFF)
            except Exception:
                self.set_reg(result_reg, 0)

        elif syscall_num == 10:
            # exit - Terminate program
            return True

        elif syscall_num == 11:
            # print_char - Print character in arg0
            char_code = self.get_reg(arg_reg) & 0xFF
            print(chr(char_code), end='')

        elif syscall_num == 12:
            # read_char - Read character from stdin, return in result reg
            try:
                char = input()[0] if input() else '\0'
                self.set_reg(result_reg, ord(char))
            except Exception:
                self.set_reg(result_reg, 0)

        elif syscall_num == 93:
            # exit_code - Exit with code in a0
            return True

        return False

    def check_termination(self, step_result):
        """
        Check if program should terminate based on step result

        Args:
            step_result: Result from step()

        Returns:
            tuple: (should_terminate: bool, reason: str or None)
        """
        # Handle syscall - perform I/O and check for exit
        if step_result == StepResult.SYSCALL:
            if self._handle_syscall():
                return (True, 'syscall_exit')

        # Check for HALT
        if step_result == StepResult.HALT:
            return (True, 'halt')

        # Check for ERROR
        if step_result == StepResult.ERROR:
            return (True, 'error')

        # Check for tohost write (HTIF mechanism)
        tohost_addr = self.lookup_symbol('tohost')
        if tohost_addr is not None:
            try:
                tohost_bytes = self.read_mem(tohost_addr, 8)
                tohost_value = int.from_bytes(tohost_bytes, byteorder='little', signed=False)
                if tohost_value != 0:
                    return (True, 'tohost')
            except Exception:
                pass

        return (False, None)

    def __del__(self):
        """Cleanup when object is destroyed"""
        # Unicorn handles its own cleanup
        pass

    def __enter__(self):
        """Context manager support"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        # Unicorn handles its own cleanup
        pass


def detect_elf_isa(elf_path):
    """
    Detect the ISA of an ELF file without loading it

    Args:
        elf_path (str): Path to ELF file

    Returns:
        ISA: ISA type (ISA.RISCV, ISA.ARM, ISA.X86_64, or ISA.UNKNOWN)
    """
    try:
        elf_info = load_elf_file(elf_path)
        if elf_info.isa == ELF_ISA.RISCV:
            return ISA.RISCV
        elif elf_info.isa == ELF_ISA.ARM:
            return ISA.ARM
        elif elf_info.isa == ELF_ISA.X86_64:
            return ISA.X86_64
    except Exception:
        pass

    return ISA.UNKNOWN


def create_simulator(elf_path=None, config_file=None):
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
