"""
Python ctypes bindings for libsailsim C API

Provides a Pythonic interface to the Sail RISC-V simulator.
"""

import ctypes
import os
from enum import IntEnum
from pathlib import Path


class StepResult(IntEnum):
    """Result codes from sailsim_step()"""
    OK = 0
    HALT = 1
    WAITING = 2
    ERROR = -1


class SailSimulator:
    """
    Python wrapper for Sail RISC-V simulator

    Provides step-by-step execution, register/memory access, and state inspection
    for RISC-V programs using the formal Sail specification.
    """

    def __init__(self, config_file=None):
        """
        Initialize the simulator

        Args:
            config_file (str, optional): Path to Sail config JSON file.
                                        If None, uses built-in default config.
        """
        # Find the libsailsim shared library
        self._lib = self._load_library()

        # Define ctypes function signatures
        self._setup_functions()

        # Initialize the simulator context
        config_bytes = config_file.encode('utf-8') if config_file else None
        self._ctx = self._lib.sailsim_init(config_bytes)

        if not self._ctx:
            raise RuntimeError("Failed to initialize Sail simulator")

    def _load_library(self):
        """Load the libsailsim shared library"""
        # Get the package directory
        pkg_dir = Path(__file__).parent.parent
        lib_dir = pkg_dir / "libsailsim" / "build"

        # Try different library names
        lib_names = [
            "libsailsim.dylib",      # macOS
            "libsailsim.so",         # Linux
            "libsailsim.dll"         # Windows
        ]

        for lib_name in lib_names:
            lib_path = lib_dir / lib_name
            if lib_path.exists():
                return ctypes.CDLL(str(lib_path))

        raise FileNotFoundError(
            f"Could not find libsailsim in {lib_dir}. "
            "Make sure you've built libsailsim first."
        )

    def _setup_functions(self):
        """Define ctypes function signatures for all C API functions"""
        lib = self._lib

        # sailsim_init(const char* config_file) -> sailsim_context_t*
        lib.sailsim_init.argtypes = [ctypes.c_char_p]
        lib.sailsim_init.restype = ctypes.c_void_p

        # sailsim_destroy(sailsim_context_t* ctx) -> void
        lib.sailsim_destroy.argtypes = [ctypes.c_void_p]
        lib.sailsim_destroy.restype = None

        # sailsim_load_elf(sailsim_context_t* ctx, const char* elf_path) -> bool
        lib.sailsim_load_elf.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.sailsim_load_elf.restype = ctypes.c_bool

        # sailsim_step(sailsim_context_t* ctx) -> sailsim_step_result_t
        lib.sailsim_step.argtypes = [ctypes.c_void_p]
        lib.sailsim_step.restype = ctypes.c_int

        # sailsim_run(sailsim_context_t* ctx, uint64_t max_steps) -> uint64_t
        lib.sailsim_run.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        lib.sailsim_run.restype = ctypes.c_uint64

        # sailsim_get_pc(sailsim_context_t* ctx) -> uint64_t
        lib.sailsim_get_pc.argtypes = [ctypes.c_void_p]
        lib.sailsim_get_pc.restype = ctypes.c_uint64

        # sailsim_set_pc(sailsim_context_t* ctx, uint64_t pc) -> void
        lib.sailsim_set_pc.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        lib.sailsim_set_pc.restype = None

        # sailsim_get_reg(sailsim_context_t* ctx, int reg_num) -> uint64_t
        lib.sailsim_get_reg.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.sailsim_get_reg.restype = ctypes.c_uint64

        # sailsim_set_reg(sailsim_context_t* ctx, int reg_num, uint64_t value) -> void
        lib.sailsim_set_reg.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64]
        lib.sailsim_set_reg.restype = None

        # sailsim_read_mem(sailsim_context_t* ctx, uint64_t addr, void* buf, size_t len) -> bool
        lib.sailsim_read_mem.argtypes = [ctypes.c_void_p, ctypes.c_uint64,
                                         ctypes.c_void_p, ctypes.c_size_t]
        lib.sailsim_read_mem.restype = ctypes.c_bool

        # sailsim_write_mem(sailsim_context_t* ctx, uint64_t addr, const void* buf, size_t len) -> bool
        lib.sailsim_write_mem.argtypes = [ctypes.c_void_p, ctypes.c_uint64,
                                          ctypes.c_void_p, ctypes.c_size_t]
        lib.sailsim_write_mem.restype = ctypes.c_bool

        # sailsim_disasm(sailsim_context_t* ctx, uint64_t addr, char* buf, size_t bufsize) -> bool
        lib.sailsim_disasm.argtypes = [ctypes.c_void_p, ctypes.c_uint64,
                                       ctypes.c_char_p, ctypes.c_size_t]
        lib.sailsim_disasm.restype = ctypes.c_bool

        # sailsim_reset(sailsim_context_t* ctx) -> void
        lib.sailsim_reset.argtypes = [ctypes.c_void_p]
        lib.sailsim_reset.restype = None

        # sailsim_get_error(sailsim_context_t* ctx) -> const char*
        lib.sailsim_get_error.argtypes = [ctypes.c_void_p]
        lib.sailsim_get_error.restype = ctypes.c_char_p

        # Symbol table API
        # sailsim_get_symbol_count(sailsim_context_t* ctx) -> size_t
        lib.sailsim_get_symbol_count.argtypes = [ctypes.c_void_p]
        lib.sailsim_get_symbol_count.restype = ctypes.c_size_t

        # sailsim_get_symbol_by_index(ctx, index, name_buf, name_bufsize, addr) -> bool
        lib.sailsim_get_symbol_by_index.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                                      ctypes.c_char_p, ctypes.c_size_t,
                                                      ctypes.POINTER(ctypes.c_uint64)]
        lib.sailsim_get_symbol_by_index.restype = ctypes.c_bool

        # sailsim_lookup_symbol(ctx, name, addr) -> bool
        lib.sailsim_lookup_symbol.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                               ctypes.POINTER(ctypes.c_uint64)]
        lib.sailsim_lookup_symbol.restype = ctypes.c_bool

        # sailsim_addr_to_symbol(ctx, addr, name_buf, name_bufsize, offset) -> bool
        lib.sailsim_addr_to_symbol.argtypes = [ctypes.c_void_p, ctypes.c_uint64,
                                                 ctypes.c_char_p, ctypes.c_size_t,
                                                 ctypes.POINTER(ctypes.c_uint64)]
        lib.sailsim_addr_to_symbol.restype = ctypes.c_bool

    def load_elf(self, elf_path):
        """
        Load an ELF file into simulator memory

        Args:
            elf_path (str): Path to RISC-V ELF executable

        Returns:
            bool: True if successful, False otherwise
        """
        result = self._lib.sailsim_load_elf(self._ctx, elf_path.encode('utf-8'))
        if not result:
            error = self._lib.sailsim_get_error(self._ctx)
            raise RuntimeError(f"Failed to load ELF: {error.decode('utf-8')}")
        return result

    def step(self):
        """
        Execute one instruction

        Returns:
            StepResult: Result code (OK, HALT, WAITING, or ERROR)
        """
        result = self._lib.sailsim_step(self._ctx)
        return StepResult(result)

    def run(self, max_steps=0):
        """
        Run until halt or max_steps reached

        Args:
            max_steps (int): Maximum number of instructions to execute (0 = unlimited)

        Returns:
            int: Number of instructions executed
        """
        return self._lib.sailsim_run(self._ctx, max_steps)

    def get_pc(self):
        """Get the program counter"""
        return self._lib.sailsim_get_pc(self._ctx)

    def set_pc(self, pc):
        """Set the program counter"""
        self._lib.sailsim_set_pc(self._ctx, pc)

    def get_reg(self, reg_num):
        """
        Get register value

        Args:
            reg_num (int): Register number (0-31)

        Returns:
            int: Register value (64-bit)
        """
        if not 0 <= reg_num <= 31:
            raise ValueError(f"Register number must be 0-31, got {reg_num}")
        return self._lib.sailsim_get_reg(self._ctx, reg_num)

    def set_reg(self, reg_num, value):
        """
        Set register value

        Args:
            reg_num (int): Register number (1-31, x0 is read-only)
            value (int): Value to set (64-bit)
        """
        if not 1 <= reg_num <= 31:
            raise ValueError(f"Register number must be 1-31, got {reg_num}")
        self._lib.sailsim_set_reg(self._ctx, reg_num, value & 0xFFFFFFFFFFFFFFFF)

    def read_mem(self, addr, length):
        """
        Read memory

        Args:
            addr (int): Memory address
            length (int): Number of bytes to read

        Returns:
            bytes: Memory contents
        """
        buf = ctypes.create_string_buffer(length)
        result = self._lib.sailsim_read_mem(self._ctx, addr, buf, length)
        if not result:
            error = self._lib.sailsim_get_error(self._ctx)
            raise RuntimeError(f"Failed to read memory: {error.decode('utf-8')}")
        return buf.raw

    def write_mem(self, addr, data):
        """
        Write memory

        Args:
            addr (int): Memory address
            data (bytes): Data to write

        Returns:
            bool: True if successful
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        buf = ctypes.create_string_buffer(data)
        result = self._lib.sailsim_write_mem(self._ctx, addr, buf, len(data))
        if not result:
            error = self._lib.sailsim_get_error(self._ctx)
            raise RuntimeError(f"Failed to write memory: {error.decode('utf-8')}")
        return result

    def disasm(self, addr):
        """
        Disassemble instruction at address

        Args:
            addr (int): Address of instruction to disassemble

        Returns:
            str: Disassembled instruction string
        """
        buf = ctypes.create_string_buffer(256)
        result = self._lib.sailsim_disasm(self._ctx, addr, buf, 256)
        if not result:
            error = self._lib.sailsim_get_error(self._ctx)
            raise RuntimeError(f"Failed to disassemble: {error.decode('utf-8')}")
        return buf.value.decode('utf-8')

    def get_symbols(self):
        """
        Get all symbols from the symbol table

        Returns:
            dict: Dictionary mapping symbol names to addresses
        """
        count = self._lib.sailsim_get_symbol_count(self._ctx)
        symbols = {}

        name_buf = ctypes.create_string_buffer(256)
        addr = ctypes.c_uint64()

        for i in range(count):
            if self._lib.sailsim_get_symbol_by_index(self._ctx, i, name_buf, 256,
                                                       ctypes.byref(addr)):
                symbols[name_buf.value.decode('utf-8')] = addr.value

        return symbols

    def lookup_symbol(self, name):
        """
        Look up symbol address by name

        Args:
            name (str): Symbol name to look up

        Returns:
            int: Symbol address, or None if not found
        """
        addr = ctypes.c_uint64()
        result = self._lib.sailsim_lookup_symbol(self._ctx, name.encode('utf-8'),
                                                   ctypes.byref(addr))
        return addr.value if result else None

    def addr_to_symbol(self, addr):
        """
        Convert address to symbol name + offset

        Args:
            addr (int): Address to look up

        Returns:
            tuple: (symbol_name, offset) if found, or (None, None) if not found
        """
        name_buf = ctypes.create_string_buffer(256)
        offset = ctypes.c_uint64()
        result = self._lib.sailsim_addr_to_symbol(self._ctx, addr, name_buf, 256,
                                                    ctypes.byref(offset))
        if result:
            return (name_buf.value.decode('utf-8'), offset.value)
        return (None, None)

    def reset(self):
        """Reset the simulator to initial state"""
        self._lib.sailsim_reset(self._ctx)

    def get_all_regs(self):
        """
        Get all register values as a list

        Returns:
            list: List of 32 register values (x0-x31)
        """
        return [self.get_reg(i) for i in range(32)]

    def __del__(self):
        """Cleanup when object is destroyed"""
        if hasattr(self, '_ctx') and self._ctx:
            self._lib.sailsim_destroy(self._ctx)

    def __enter__(self):
        """Context manager support"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        if self._ctx:
            self._lib.sailsim_destroy(self._ctx)
            self._ctx = None
