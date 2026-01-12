"""
DWARF v2 debug information generator.

Generates minimal DWARF v2 sections for source-level debugging:
- .debug_abbrev: DIE schema definitions
- .debug_info: Compilation unit header
- .debug_line: Address-to-line mappings
"""

from __future__ import annotations

import struct
from typing import List, Tuple


# DWARF constants
DW_TAG_compile_unit = 0x11

DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_name = 0x03
DW_AT_producer = 0x25

DW_FORM_addr = 0x01
DW_FORM_data4 = 0x06
DW_FORM_string = 0x08  # Inline null-terminated string

# Line program opcodes
DW_LNS_copy = 1
DW_LNS_advance_pc = 2
DW_LNS_advance_line = 3
DW_LNS_set_file = 4
DW_LNS_set_column = 5
DW_LNS_negate_stmt = 6
DW_LNS_set_basic_block = 7
DW_LNS_const_add_pc = 8
DW_LNS_fixed_advance_pc = 9

# Extended opcodes (prefixed with 0x00)
DW_LNE_end_sequence = 1
DW_LNE_set_address = 2
DW_LNE_define_file = 3

# Line program parameters
LINE_BASE = -5
LINE_RANGE = 14
OPCODE_BASE = 10


def _uleb128(value: int) -> bytes:
    """Encode an unsigned integer as ULEB128."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def _sleb128(value: int) -> bytes:
    """Encode a signed integer as SLEB128."""
    result = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        # Check if more bytes needed
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


class DWARFv2Builder:
    """
    Generate minimal DWARF v2 debug sections.

    Creates three sections:
    - .debug_abbrev: Fixed schema for compile_unit DIE
    - .debug_info: Single compile_unit with addresses and filename
    - .debug_line: Line number program mapping addresses to source lines

    Example:
        builder = DWARFv2Builder(addr_size=8)
        lines = [(0x80000000, 10), (0x80000004, 11), (0x80000008, 12)]

        abbrev = builder.build_debug_abbrev()
        info = builder.build_debug_info("hello.s", 0x80000000, 0x8000000c)
        line = builder.build_debug_line("hello.s", lines)
    """

    def __init__(self, addr_size: int = 8):
        """
        Initialize DWARF builder.

        Args:
            addr_size: Address size in bytes (8 for 64-bit, 4 for 32-bit).
        """
        self.addr_size = addr_size

    def build_debug_abbrev(self) -> bytes:
        """
        Build .debug_abbrev section.

        Returns fixed abbreviation table with one entry for compile_unit.
        """
        return bytes([
            # Abbreviation 1: DW_TAG_compile_unit
            0x01,                   # abbrev number
            DW_TAG_compile_unit,    # tag
            0x00,                   # no children

            # Attributes
            DW_AT_stmt_list, DW_FORM_data4,   # stmt_list: offset into .debug_line
            DW_AT_low_pc, DW_FORM_addr,       # low_pc: start address
            DW_AT_high_pc, DW_FORM_addr,      # high_pc: end address
            DW_AT_name, DW_FORM_string,       # name: source filename (inline)
            DW_AT_producer, DW_FORM_string,   # producer: assembler name (inline)

            0x00, 0x00,             # end of attributes

            0x00,                   # end of abbreviations
        ])

    def build_debug_info(
        self,
        filename: str,
        low_pc: int,
        high_pc: int,
        stmt_list_offset: int = 0,
    ) -> bytes:
        """
        Build .debug_info section.

        Args:
            filename: Source filename.
            low_pc: Start address of code.
            high_pc: End address of code.
            stmt_list_offset: Offset into .debug_line section (usually 0).

        Returns:
            Bytes for .debug_info section.
        """
        producer = "mapachespim-as"

        # Build DIE content
        die_content = bytearray()
        die_content.append(0x01)  # abbrev number 1

        # stmt_list (4 bytes)
        die_content.extend(struct.pack('<I', stmt_list_offset))

        # low_pc and high_pc (addr_size bytes each)
        if self.addr_size == 8:
            die_content.extend(struct.pack('<Q', low_pc))
            die_content.extend(struct.pack('<Q', high_pc))
        else:
            die_content.extend(struct.pack('<I', low_pc))
            die_content.extend(struct.pack('<I', high_pc))

        # name (null-terminated string)
        die_content.extend(filename.encode('utf-8'))
        die_content.append(0x00)

        # producer (null-terminated string)
        die_content.extend(producer.encode('utf-8'))
        die_content.append(0x00)

        # Build CU header
        # unit_length doesn't include itself (4 bytes)
        cu_header_size = 2 + 4 + 1  # version(2) + abbrev_offset(4) + addr_size(1)
        unit_length = cu_header_size + len(die_content)

        header = bytearray()
        header.extend(struct.pack('<I', unit_length))  # unit_length
        header.extend(struct.pack('<H', 2))            # version = 2
        header.extend(struct.pack('<I', 0))            # abbrev_offset = 0
        header.append(self.addr_size)                  # address_size

        return bytes(header + die_content)

    def build_debug_line(
        self,
        filename: str,
        lines: List[Tuple[int, int]],
        min_instr_length: int = 4,
    ) -> bytes:
        """
        Build .debug_line section.

        Args:
            filename: Source filename.
            lines: List of (address, line_number) tuples, sorted by address.
            min_instr_length: Minimum instruction length (4 for RISC-V/ARM/MIPS, 1 for x86).

        Returns:
            Bytes for .debug_line section.
        """
        # Standard opcode lengths for opcodes 1-9
        std_opcode_lengths = bytes([0, 1, 1, 1, 1, 0, 0, 0, 1])

        # Build directory table
        dir_table = bytearray()
        dir_table.extend(b'.\x00')  # current directory
        dir_table.append(0x00)      # end of directories

        # Build file table
        file_table = bytearray()
        file_table.extend(filename.encode('utf-8'))
        file_table.append(0x00)     # null terminator
        file_table.append(0x01)     # directory index
        file_table.append(0x00)     # mtime (ULEB128 0)
        file_table.append(0x00)     # size (ULEB128 0)
        file_table.append(0x00)     # end of files

        # Build line program
        program = self._build_line_program(lines, min_instr_length)

        # Calculate header length (bytes after header_length field, before program)
        # header_length includes: min_instr_len(1) + default_is_stmt(1) + line_base(1) +
        #                         line_range(1) + opcode_base(1) + std_opcode_lengths(9) +
        #                         dir_table + file_table
        header_content_len = 1 + 1 + 1 + 1 + 1 + len(std_opcode_lengths) + len(dir_table) + len(file_table)

        # Build header
        header = bytearray()
        # Placeholder for unit_length (filled in later)
        header.extend(b'\x00\x00\x00\x00')
        header.extend(struct.pack('<H', 2))  # version = 2
        header.extend(struct.pack('<I', header_content_len))  # header_length
        header.append(min_instr_length)      # minimum_instruction_length
        header.append(1)                     # default_is_stmt
        header.append(LINE_BASE & 0xFF)      # line_base (signed, -5)
        header.append(LINE_RANGE)            # line_range (14)
        header.append(OPCODE_BASE)           # opcode_base (10)
        header.extend(std_opcode_lengths)    # standard_opcode_lengths
        header.extend(dir_table)
        header.extend(file_table)

        # Combine header and program
        result = header + program

        # Fill in unit_length (total length minus the 4-byte length field itself)
        unit_length = len(result) - 4
        struct.pack_into('<I', result, 0, unit_length)

        return bytes(result)

    def _build_line_program(
        self,
        lines: List[Tuple[int, int]],
        min_instr_length: int,
    ) -> bytes:
        """Build the line number program opcodes."""
        program = bytearray()

        if not lines:
            # Empty program - just end sequence
            program.extend(self._extended_opcode(DW_LNE_end_sequence, b''))
            return bytes(program)

        # Sort lines by address
        sorted_lines = sorted(lines, key=lambda x: x[0])

        # State machine initial values
        current_addr = 0
        current_line = 1
        current_file = 1

        for addr, line in sorted_lines:
            # Set address if this is first entry or we need a big jump
            if current_addr == 0 or addr < current_addr:
                # Use extended opcode to set address
                if self.addr_size == 8:
                    addr_bytes = struct.pack('<Q', addr)
                else:
                    addr_bytes = struct.pack('<I', addr)
                program.extend(self._extended_opcode(DW_LNE_set_address, addr_bytes))
                current_addr = addr

            # Calculate deltas
            addr_delta = (addr - current_addr) // min_instr_length
            line_delta = line - current_line

            # Try to use a special opcode
            special = self._try_special_opcode(addr_delta, line_delta)
            if special is not None:
                program.append(special)
            else:
                # Use standard opcodes
                if addr_delta > 0:
                    program.append(DW_LNS_advance_pc)
                    program.extend(_uleb128(addr_delta))

                if line_delta != 0:
                    program.append(DW_LNS_advance_line)
                    program.extend(_sleb128(line_delta))

                program.append(DW_LNS_copy)

            current_addr = addr
            current_line = line

        # End sequence
        program.extend(self._extended_opcode(DW_LNE_end_sequence, b''))

        return bytes(program)

    def _extended_opcode(self, opcode: int, data: bytes) -> bytes:
        """Build an extended opcode sequence."""
        result = bytearray()
        result.append(0x00)  # Extended opcode marker
        result.extend(_uleb128(1 + len(data)))  # Length (opcode + data)
        result.append(opcode)
        result.extend(data)
        return bytes(result)

    def _try_special_opcode(self, addr_delta: int, line_delta: int) -> int | None:
        """
        Try to encode address and line change as a special opcode.

        Returns the opcode value if possible, None otherwise.
        """
        adjusted_line = line_delta - LINE_BASE
        if adjusted_line < 0 or adjusted_line >= LINE_RANGE:
            return None

        opcode = adjusted_line + (LINE_RANGE * addr_delta) + OPCODE_BASE
        if opcode > 255:
            return None

        return opcode
