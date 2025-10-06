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

        # sailsim_reset(sailsim_context_t* ctx) -> void
        lib.sailsim_reset.argtypes = [ctypes.c_void_p]
        lib.sailsim_reset.restype = None

        # sailsim_get_error(sailsim_context_t* ctx) -> const char*
        lib.sailsim_get_error.argtypes = [ctypes.c_void_p]
        lib.sailsim_get_error.restype = ctypes.c_char_p

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
