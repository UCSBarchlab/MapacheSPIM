"""
Minimal ELF file builder for MapacheSPIM toolchain.

Generates bare-metal ELF executables from assembled sections.
Uses struct for binary generation and pyelftools constants for ELF values.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .memory_map import MemoryLayout, get_layout

# ELF constants (from pyelftools, but defined here to avoid deep imports)
# ELF identification
EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3 = 0, 1, 2, 3
ELFMAG = b"\x7fELF"
EI_CLASS = 4
ELFCLASS32, ELFCLASS64 = 1, 2
EI_DATA = 5
ELFDATA2LSB, ELFDATA2MSB = 1, 2
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8
EV_CURRENT = 1

# ELF type
ET_EXEC = 2

# Machine types
EM_MIPS = 8
EM_X86_64 = 62
EM_AARCH64 = 183
EM_RISCV = 243

# Program header types
PT_NULL = 0
PT_LOAD = 1

# Program header flags
PF_X = 1  # Execute
PF_W = 2  # Write
PF_R = 4  # Read

# Section header types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8

# Section header flags
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4

# Symbol binding
STB_LOCAL = 0
STB_GLOBAL = 1

# Symbol type
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2

# Special section indices
SHN_UNDEF = 0
SHN_ABS = 0xFFF1

# Map ISA names to ELF machine types
ISA_TO_MACHINE = {
    "riscv64": EM_RISCV,
    "riscv": EM_RISCV,
    "arm64": EM_AARCH64,
    "aarch64": EM_AARCH64,
    "x86_64": EM_X86_64,
    "x86-64": EM_X86_64,
    "x64": EM_X86_64,
    "mips32": EM_MIPS,
    "mips": EM_MIPS,
}


@dataclass
class Section:
    """A section in the ELF file."""

    name: str
    """Section name (e.g., ".text", ".data")."""

    data: bytes
    """Section content."""

    address: int
    """Virtual address where section is loaded."""

    sh_type: int = SHT_PROGBITS
    """Section type (SHT_*)."""

    sh_flags: int = SHF_ALLOC
    """Section flags (SHF_*)."""

    alignment: int = 4
    """Section alignment."""

    def __post_init__(self) -> None:
        # Set default flags based on section name
        if self.name == ".text":
            self.sh_flags = SHF_ALLOC | SHF_EXECINSTR
        elif self.name == ".data":
            self.sh_flags = SHF_ALLOC | SHF_WRITE
        elif self.name == ".rodata":
            self.sh_flags = SHF_ALLOC
        elif self.name == ".bss":
            self.sh_type = SHT_NOBITS
            self.sh_flags = SHF_ALLOC | SHF_WRITE


@dataclass
class Symbol:
    """A symbol in the ELF file."""

    name: str
    """Symbol name."""

    address: int
    """Symbol value (address)."""

    size: int = 0
    """Symbol size (0 for unknown)."""

    sym_type: int = STT_NOTYPE
    """Symbol type (STT_*)."""

    binding: int = STB_LOCAL
    """Symbol binding (STB_*)."""

    section_index: int = 0
    """Index of section containing symbol."""


@dataclass
class ELFBuilder:
    """
    Builder for minimal ELF executables.

    Example:
        >>> builder = ELFBuilder("riscv64", entry=0x80000000)
        >>> builder.add_section(Section(".text", code_bytes, 0x80000000))
        >>> builder.add_symbol(Symbol("_start", 0x80000000, sym_type=STT_FUNC))
        >>> elf_bytes = builder.build()
    """

    isa: str
    """Target ISA."""

    entry: int
    """Entry point address."""

    sections: List[Section] = field(default_factory=list)
    """List of sections."""

    symbols: List[Symbol] = field(default_factory=list)
    """List of symbols."""

    _layout: Optional[MemoryLayout] = field(default=None, init=False)
    """Memory layout for the ISA."""

    def __post_init__(self) -> None:
        self._layout = get_layout(self.isa)

    @property
    def is_64bit(self) -> bool:
        """Return True if this is a 64-bit ELF."""
        return self._layout.is_64bit if self._layout else True

    @property
    def is_little_endian(self) -> bool:
        """Return True if this is a little-endian ELF."""
        return self._layout.is_little_endian if self._layout else True

    @property
    def machine(self) -> int:
        """Return the ELF machine type."""
        return ISA_TO_MACHINE.get(self.isa.lower(), EM_RISCV)

    def add_section(self, section: Section) -> None:
        """Add a section to the ELF."""
        self.sections.append(section)

    def add_symbol(self, symbol: Symbol) -> None:
        """Add a symbol to the ELF."""
        self.symbols.append(symbol)

    def build(self) -> bytes:
        """
        Build the complete ELF file.

        Returns:
            The ELF file as bytes.
        """
        if self.is_64bit:
            return self._build_elf64()
        else:
            return self._build_elf32()

    def _build_elf64(self) -> bytes:
        """Build a 64-bit ELF file."""
        # Endianness
        endian = "<" if self.is_little_endian else ">"

        # ELF header size
        ehdr_size = 64
        phdr_size = 56
        shdr_size = 64

        # Count program headers (one per loadable section + null)
        loadable_sections = [s for s in self.sections if s.sh_flags & SHF_ALLOC]
        num_phdrs = len(loadable_sections)

        # Count section headers
        # 0: null, 1+: sections, then .shstrtab, .strtab, .symtab
        num_shdrs = 1 + len(self.sections) + 3
        shstrtab_idx = 1 + len(self.sections)
        strtab_idx = shstrtab_idx + 1
        symtab_idx = strtab_idx + 1

        # Build section name string table
        shstrtab = b"\x00"
        shstrtab_offsets: Dict[str, int] = {"": 0}
        section_names = [s.name for s in self.sections] + [".shstrtab", ".strtab", ".symtab"]
        for name in section_names:
            if name not in shstrtab_offsets:
                shstrtab_offsets[name] = len(shstrtab)
                shstrtab += name.encode("ascii") + b"\x00"

        # Build symbol string table
        strtab = b"\x00"
        strtab_offsets: Dict[str, int] = {"": 0}
        for sym in self.symbols:
            if sym.name and sym.name not in strtab_offsets:
                strtab_offsets[sym.name] = len(strtab)
                strtab += sym.name.encode("ascii") + b"\x00"

        # Build symbol table
        symtab = b""
        # First entry is null symbol
        symtab += struct.pack(f"{endian}IBBHQQ", 0, 0, 0, 0, 0, 0)
        for sym in self.symbols:
            st_name = strtab_offsets.get(sym.name, 0)
            st_info = (sym.binding << 4) | sym.sym_type
            st_other = 0
            st_shndx = sym.section_index if sym.section_index else SHN_ABS
            symtab += struct.pack(
                f"{endian}IBBHQQ",
                st_name, st_info, st_other, st_shndx, sym.address, sym.size
            )

        # Calculate offsets
        phdr_offset = ehdr_size
        section_offset = ehdr_size + (num_phdrs * phdr_size)

        # Align section offset
        section_offset = (section_offset + 7) & ~7

        # Calculate section data positions
        section_file_offsets: List[int] = []
        current_offset = section_offset
        for section in self.sections:
            # Align to section alignment
            align = max(section.alignment, 1)
            current_offset = (current_offset + align - 1) & ~(align - 1)
            section_file_offsets.append(current_offset)
            if section.sh_type != SHT_NOBITS:
                current_offset += len(section.data)

        # Add string tables and symbol table
        shstrtab_offset = (current_offset + 7) & ~7
        current_offset = shstrtab_offset + len(shstrtab)

        strtab_offset = (current_offset + 7) & ~7
        current_offset = strtab_offset + len(strtab)

        symtab_offset = (current_offset + 7) & ~7
        current_offset = symtab_offset + len(symtab)

        # Section header offset
        shdr_offset = (current_offset + 7) & ~7

        # Build ELF header
        e_ident = bytearray(16)
        e_ident[0:4] = ELFMAG
        e_ident[EI_CLASS] = ELFCLASS64
        e_ident[EI_DATA] = ELFDATA2LSB if self.is_little_endian else ELFDATA2MSB
        e_ident[EI_VERSION] = EV_CURRENT
        e_ident[EI_OSABI] = 0
        e_ident[EI_ABIVERSION] = 0

        ehdr = bytes(e_ident) + struct.pack(
            f"{endian}HHIQQQIHHHHHH",
            ET_EXEC,           # e_type
            self.machine,      # e_machine
            EV_CURRENT,        # e_version
            self.entry,        # e_entry
            phdr_offset,       # e_phoff
            shdr_offset,       # e_shoff
            0,                 # e_flags
            ehdr_size,         # e_ehsize
            phdr_size,         # e_phentsize
            num_phdrs,         # e_phnum
            shdr_size,         # e_shentsize
            num_shdrs,         # e_shnum
            shstrtab_idx,      # e_shstrndx
        )

        # Build program headers
        phdrs = b""
        for i, section in enumerate(loadable_sections):
            idx = self.sections.index(section)
            file_offset = section_file_offsets[idx]
            file_size = 0 if section.sh_type == SHT_NOBITS else len(section.data)
            mem_size = len(section.data) if section.data else 0

            flags = PF_R
            if section.sh_flags & SHF_WRITE:
                flags |= PF_W
            if section.sh_flags & SHF_EXECINSTR:
                flags |= PF_X

            phdrs += struct.pack(
                f"{endian}IIQQQQQQ",
                PT_LOAD,           # p_type
                flags,             # p_flags
                file_offset,       # p_offset
                section.address,   # p_vaddr
                section.address,   # p_paddr
                file_size,         # p_filesz
                mem_size,          # p_memsz
                section.alignment, # p_align
            )

        # Build section data
        section_data = b""
        for i, section in enumerate(self.sections):
            # Pad to alignment
            target_offset = section_file_offsets[i]
            current_len = section_offset + len(section_data)
            if current_len < target_offset:
                section_data += b"\x00" * (target_offset - current_len)
            if section.sh_type != SHT_NOBITS:
                section_data += section.data

        # Pad and add string tables
        current_len = section_offset + len(section_data)
        if current_len < shstrtab_offset:
            section_data += b"\x00" * (shstrtab_offset - current_len)
        section_data += shstrtab

        current_len = section_offset + len(section_data)
        if current_len < strtab_offset:
            section_data += b"\x00" * (strtab_offset - current_len)
        section_data += strtab

        current_len = section_offset + len(section_data)
        if current_len < symtab_offset:
            section_data += b"\x00" * (symtab_offset - current_len)
        section_data += symtab

        # Pad to section header offset
        current_len = section_offset + len(section_data)
        if current_len < shdr_offset:
            section_data += b"\x00" * (shdr_offset - current_len)

        # Build section headers
        shdrs = b""
        # Null section header
        shdrs += struct.pack(f"{endian}IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        # Regular sections
        for i, section in enumerate(self.sections):
            sh_name = shstrtab_offsets.get(section.name, 0)
            sh_offset = section_file_offsets[i]
            sh_size = len(section.data) if section.data else 0

            shdrs += struct.pack(
                f"{endian}IIQQQQIIQQ",
                sh_name,           # sh_name
                section.sh_type,   # sh_type
                section.sh_flags,  # sh_flags
                section.address,   # sh_addr
                sh_offset,         # sh_offset
                sh_size,           # sh_size
                0,                 # sh_link
                0,                 # sh_info
                section.alignment, # sh_addralign
                0,                 # sh_entsize
            )

        # .shstrtab section header
        shdrs += struct.pack(
            f"{endian}IIQQQQIIQQ",
            shstrtab_offsets[".shstrtab"],
            SHT_STRTAB,
            0,
            0,
            shstrtab_offset,
            len(shstrtab),
            0, 0, 1, 0,
        )

        # .strtab section header
        shdrs += struct.pack(
            f"{endian}IIQQQQIIQQ",
            shstrtab_offsets[".strtab"],
            SHT_STRTAB,
            0,
            0,
            strtab_offset,
            len(strtab),
            0, 0, 1, 0,
        )

        # .symtab section header
        num_symbols = 1 + len(self.symbols)
        shdrs += struct.pack(
            f"{endian}IIQQQQIIQQ",
            shstrtab_offsets[".symtab"],
            SHT_SYMTAB,
            0,
            0,
            symtab_offset,
            len(symtab),
            strtab_idx,        # sh_link = string table index
            1,                 # sh_info = first global symbol
            8,
            24,                # entry size for 64-bit symbols
        )

        return ehdr + phdrs + section_data + shdrs

    def _build_elf32(self) -> bytes:
        """Build a 32-bit ELF file (for MIPS32)."""
        endian = "<" if self.is_little_endian else ">"

        # ELF header size
        ehdr_size = 52
        phdr_size = 32
        shdr_size = 40

        # Count program headers
        loadable_sections = [s for s in self.sections if s.sh_flags & SHF_ALLOC]
        num_phdrs = len(loadable_sections)

        # Count section headers
        num_shdrs = 1 + len(self.sections) + 3
        shstrtab_idx = 1 + len(self.sections)
        strtab_idx = shstrtab_idx + 1
        symtab_idx = strtab_idx + 1

        # Build section name string table
        shstrtab = b"\x00"
        shstrtab_offsets: Dict[str, int] = {"": 0}
        section_names = [s.name for s in self.sections] + [".shstrtab", ".strtab", ".symtab"]
        for name in section_names:
            if name not in shstrtab_offsets:
                shstrtab_offsets[name] = len(shstrtab)
                shstrtab += name.encode("ascii") + b"\x00"

        # Build symbol string table
        strtab = b"\x00"
        strtab_offsets: Dict[str, int] = {"": 0}
        for sym in self.symbols:
            if sym.name and sym.name not in strtab_offsets:
                strtab_offsets[sym.name] = len(strtab)
                strtab += sym.name.encode("ascii") + b"\x00"

        # Build symbol table (32-bit format)
        symtab = b""
        # First entry is null symbol
        symtab += struct.pack(f"{endian}IIIBBH", 0, 0, 0, 0, 0, 0)
        for sym in self.symbols:
            st_name = strtab_offsets.get(sym.name, 0)
            st_info = (sym.binding << 4) | sym.sym_type
            st_other = 0
            st_shndx = sym.section_index if sym.section_index else SHN_ABS
            symtab += struct.pack(
                f"{endian}IIIBBH",
                st_name, sym.address, sym.size, st_info, st_other, st_shndx
            )

        # Calculate offsets
        phdr_offset = ehdr_size
        section_offset = ehdr_size + (num_phdrs * phdr_size)
        section_offset = (section_offset + 3) & ~3

        # Calculate section data positions
        section_file_offsets: List[int] = []
        current_offset = section_offset
        for section in self.sections:
            align = max(section.alignment, 1)
            current_offset = (current_offset + align - 1) & ~(align - 1)
            section_file_offsets.append(current_offset)
            if section.sh_type != SHT_NOBITS:
                current_offset += len(section.data)

        # Add string tables and symbol table
        shstrtab_offset = (current_offset + 3) & ~3
        current_offset = shstrtab_offset + len(shstrtab)

        strtab_offset = (current_offset + 3) & ~3
        current_offset = strtab_offset + len(strtab)

        symtab_offset = (current_offset + 3) & ~3
        current_offset = symtab_offset + len(symtab)

        shdr_offset = (current_offset + 3) & ~3

        # Build ELF header
        e_ident = bytearray(16)
        e_ident[0:4] = ELFMAG
        e_ident[EI_CLASS] = ELFCLASS32
        e_ident[EI_DATA] = ELFDATA2LSB if self.is_little_endian else ELFDATA2MSB
        e_ident[EI_VERSION] = EV_CURRENT

        # For MIPS, set flags (e.g., MIPS32 ABI)
        e_flags = 0
        if self.machine == EM_MIPS:
            e_flags = 0x50001000  # MIPS32R2, O32 ABI

        ehdr = bytes(e_ident) + struct.pack(
            f"{endian}HHIIIIIHHHHHH",
            ET_EXEC,
            self.machine,
            EV_CURRENT,
            self.entry,
            phdr_offset,
            shdr_offset,
            e_flags,
            ehdr_size,
            phdr_size,
            num_phdrs,
            shdr_size,
            num_shdrs,
            shstrtab_idx,
        )

        # Build program headers
        phdrs = b""
        for section in loadable_sections:
            idx = self.sections.index(section)
            file_offset = section_file_offsets[idx]
            file_size = 0 if section.sh_type == SHT_NOBITS else len(section.data)
            mem_size = len(section.data) if section.data else 0

            flags = PF_R
            if section.sh_flags & SHF_WRITE:
                flags |= PF_W
            if section.sh_flags & SHF_EXECINSTR:
                flags |= PF_X

            phdrs += struct.pack(
                f"{endian}IIIIIIII",
                PT_LOAD,
                file_offset,
                section.address,
                section.address,
                file_size,
                mem_size,
                flags,
                section.alignment,
            )

        # Build section data
        section_data = b""
        for i, section in enumerate(self.sections):
            target_offset = section_file_offsets[i]
            current_len = section_offset + len(section_data)
            if current_len < target_offset:
                section_data += b"\x00" * (target_offset - current_len)
            if section.sh_type != SHT_NOBITS:
                section_data += section.data

        # Pad and add tables
        current_len = section_offset + len(section_data)
        if current_len < shstrtab_offset:
            section_data += b"\x00" * (shstrtab_offset - current_len)
        section_data += shstrtab

        current_len = section_offset + len(section_data)
        if current_len < strtab_offset:
            section_data += b"\x00" * (strtab_offset - current_len)
        section_data += strtab

        current_len = section_offset + len(section_data)
        if current_len < symtab_offset:
            section_data += b"\x00" * (symtab_offset - current_len)
        section_data += symtab

        current_len = section_offset + len(section_data)
        if current_len < shdr_offset:
            section_data += b"\x00" * (shdr_offset - current_len)

        # Build section headers
        shdrs = b""
        # Null section header
        shdrs += struct.pack(f"{endian}IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        for i, section in enumerate(self.sections):
            sh_name = shstrtab_offsets.get(section.name, 0)
            sh_offset = section_file_offsets[i]
            sh_size = len(section.data) if section.data else 0

            shdrs += struct.pack(
                f"{endian}IIIIIIIIII",
                sh_name,
                section.sh_type,
                section.sh_flags,
                section.address,
                sh_offset,
                sh_size,
                0, 0,
                section.alignment,
                0,
            )

        # .shstrtab
        shdrs += struct.pack(
            f"{endian}IIIIIIIIII",
            shstrtab_offsets[".shstrtab"],
            SHT_STRTAB, 0, 0,
            shstrtab_offset, len(shstrtab),
            0, 0, 1, 0,
        )

        # .strtab
        shdrs += struct.pack(
            f"{endian}IIIIIIIIII",
            shstrtab_offsets[".strtab"],
            SHT_STRTAB, 0, 0,
            strtab_offset, len(strtab),
            0, 0, 1, 0,
        )

        # .symtab
        shdrs += struct.pack(
            f"{endian}IIIIIIIIII",
            shstrtab_offsets[".symtab"],
            SHT_SYMTAB, 0, 0,
            symtab_offset, len(symtab),
            strtab_idx, 1,
            4, 16,
        )

        return ehdr + phdrs + section_data + shdrs
