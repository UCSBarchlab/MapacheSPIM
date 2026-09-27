"""
Minimal ELF file builder for MapacheSPIM toolchain.

Generates bare-metal ELF executables from assembled sections.
Uses struct for binary generation and pyelftools constants for ELF values.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..isa import ISASpec, get_spec

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


@dataclass(frozen=True)
class _ElfClass:
    """Sizes and struct layouts that differ between 32- and 64-bit ELF files."""

    elf_class: int
    ehdr: str  # after e_ident
    phdr: str  # fields in the class's own order; see _program_header
    shdr: str
    sym: str
    word: int  # alignment of tables in the file, and the size of an address

    @property
    def ehdr_size(self) -> int:
        return 16 + struct.calcsize("<" + self.ehdr)

    @property
    def phdr_size(self) -> int:
        return struct.calcsize("<" + self.phdr)

    @property
    def shdr_size(self) -> int:
        return struct.calcsize("<" + self.shdr)

    @property
    def sym_size(self) -> int:
        return struct.calcsize("<" + self.sym)


_ELF64 = _ElfClass(ELFCLASS64, "HHIQQQIHHHHHH", "IIQQQQQQ", "IIQQQQIIQQ", "IBBHQQ", 8)
_ELF32 = _ElfClass(ELFCLASS32, "HHIIIIIHHHHHH", "IIIIIIII", "IIIIIIIIII", "IIIBBH", 4)


def _string_table(names: List[str]) -> Tuple[bytes, Dict[str, int]]:
    """An ELF string table and each name's offset in it."""
    table = b"\x00"
    offsets: Dict[str, int] = {"": 0}
    for name in names:
        if name not in offsets:
            offsets[name] = len(table)
            table += name.encode("ascii") + b"\x00"
    return table, offsets


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


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

    @property
    def spec(self) -> ISASpec:
        return get_spec(self.isa)

    @property
    def is_64bit(self) -> bool:
        """Return True if this is a 64-bit ELF."""
        return self.spec.layout.is_64bit

    @property
    def is_little_endian(self) -> bool:
        """Return True if this is a little-endian ELF."""
        return self.spec.layout.is_little_endian

    @property
    def machine(self) -> int:
        """Return the ELF machine type."""
        return self.spec.elf_machine

    def add_section(self, section: Section) -> None:
        """Add a section to the ELF."""
        self.sections.append(section)

    def add_symbol(self, symbol: Symbol) -> None:
        """Add a symbol to the ELF."""
        self.symbols.append(symbol)

    def add_debug_sections(
        self,
        debug_abbrev: bytes,
        debug_info: bytes,
        debug_line: bytes,
    ) -> None:
        """
        Add DWARF debug sections to the ELF.

        Debug sections are non-loadable (no SHF_ALLOC flag), so they
        only get section headers, not program headers.
        """
        for name, data in (
            (".debug_abbrev", debug_abbrev),
            (".debug_info", debug_info),
            (".debug_line", debug_line),
        ):
            self.sections.append(
                Section(
                    name=name, data=data, address=0, sh_type=SHT_PROGBITS, sh_flags=0, alignment=1
                )
            )

    def _program_header(self, fmt: _ElfClass, endian: str, section: Section, offset: int) -> bytes:
        file_size = 0 if section.sh_type == SHT_NOBITS else len(section.data)
        mem_size = len(section.data)
        flags = PF_R
        if section.sh_flags & SHF_WRITE:
            flags |= PF_W
        if section.sh_flags & SHF_EXECINSTR:
            flags |= PF_X
        address, align = section.address, section.alignment
        if fmt is _ELF64:  # p_flags comes second in 64-bit program headers
            fields = (PT_LOAD, flags, offset, address, address, file_size, mem_size, align)
        else:
            fields = (PT_LOAD, offset, address, address, file_size, mem_size, flags, align)
        return struct.pack(endian + fmt.phdr, *fields)

    @staticmethod
    def _symbol_entry(fmt: _ElfClass, endian: str, name: int, sym: Symbol) -> bytes:
        info = (sym.binding << 4) | sym.sym_type
        shndx = sym.section_index if sym.section_index else SHN_ABS
        if fmt is _ELF64:
            return struct.pack(endian + fmt.sym, name, info, 0, shndx, sym.address, sym.size)
        return struct.pack(endian + fmt.sym, name, sym.address, sym.size, info, 0, shndx)

    def build(self) -> bytes:
        """
        Build the complete ELF file.

        Layout: ELF header, program headers, section contents, then the
        .shstrtab, .strtab, and .symtab tables, then the section headers.

        Returns:
            The ELF file as bytes.
        """
        fmt = _ELF64 if self.is_64bit else _ELF32
        endian = "<" if self.is_little_endian else ">"
        word = fmt.word

        loadable = [s for s in self.sections if s.sh_flags & SHF_ALLOC]

        # Section headers: null, the sections, then .shstrtab, .strtab, .symtab
        shstrtab_idx = 1 + len(self.sections)
        strtab_idx = shstrtab_idx + 1
        num_shdrs = strtab_idx + 2

        shstrtab, shstrtab_offsets = _string_table(
            [s.name for s in self.sections] + [".shstrtab", ".strtab", ".symtab"]
        )
        # Local symbols must come before global ones
        symbols = sorted(self.symbols, key=lambda sym: sym.binding != STB_LOCAL)
        first_global = 1 + sum(sym.binding == STB_LOCAL for sym in symbols)
        strtab, strtab_offsets = _string_table([sym.name for sym in symbols if sym.name])
        symtab = bytes(fmt.sym_size)  # the null symbol
        for sym in symbols:
            symtab += self._symbol_entry(fmt, endian, strtab_offsets.get(sym.name, 0), sym)

        # File offsets of everything after the program headers
        phdr_offset = fmt.ehdr_size
        offset = _align(phdr_offset + len(loadable) * fmt.phdr_size, word)
        section_offsets: List[int] = []
        for section in self.sections:
            offset = _align(offset, max(section.alignment, 1))
            section_offsets.append(offset)
            if section.sh_type != SHT_NOBITS:
                offset += len(section.data)
        table_offsets: List[int] = []
        for table in (shstrtab, strtab, symtab):
            offset = _align(offset, word)
            table_offsets.append(offset)
            offset += len(table)
        shdr_offset = _align(offset, word)

        # ELF header
        e_ident = bytearray(16)
        e_ident[0:4] = ELFMAG
        e_ident[EI_CLASS] = fmt.elf_class
        e_ident[EI_DATA] = ELFDATA2LSB if self.is_little_endian else ELFDATA2MSB
        e_ident[EI_VERSION] = EV_CURRENT
        out = bytearray(e_ident)
        out += struct.pack(
            endian + fmt.ehdr,
            ET_EXEC,  # e_type
            self.machine,  # e_machine
            EV_CURRENT,  # e_version
            self.entry,  # e_entry
            phdr_offset,  # e_phoff
            shdr_offset,  # e_shoff
            self.spec.elf_flags,  # e_flags
            fmt.ehdr_size,  # e_ehsize
            fmt.phdr_size,  # e_phentsize
            len(loadable),  # e_phnum
            fmt.shdr_size,  # e_shentsize
            num_shdrs,  # e_shnum
            shstrtab_idx,  # e_shstrndx
        )

        # Program headers, one per loadable section
        for section in loadable:
            offset = section_offsets[self.sections.index(section)]
            out += self._program_header(fmt, endian, section, offset)

        # Contents
        def place(data: bytes, at: int) -> None:
            out.extend(bytes(at - len(out)))
            out.extend(data)

        for section, at in zip(self.sections, section_offsets):
            if section.sh_type != SHT_NOBITS:
                place(section.data, at)
        for table, at in zip((shstrtab, strtab, symtab), table_offsets):
            place(table, at)
        place(b"", shdr_offset)

        # Section headers
        def shdr(*fields: int) -> None:
            out.extend(struct.pack(endian + fmt.shdr, *fields))

        shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        for section, at in zip(self.sections, section_offsets):
            shdr(
                shstrtab_offsets.get(section.name, 0),  # sh_name
                section.sh_type,  # sh_type
                section.sh_flags,  # sh_flags
                section.address,  # sh_addr
                at,  # sh_offset
                len(section.data),  # sh_size
                0,  # sh_link
                0,  # sh_info
                section.alignment,  # sh_addralign
                0,  # sh_entsize
            )
        shstrtab_at, strtab_at, symtab_at = table_offsets
        shdr(
            shstrtab_offsets[".shstrtab"], SHT_STRTAB, 0, 0, shstrtab_at, len(shstrtab), 0, 0, 1, 0
        )
        shdr(shstrtab_offsets[".strtab"], SHT_STRTAB, 0, 0, strtab_at, len(strtab), 0, 0, 1, 0)
        shdr(
            shstrtab_offsets[".symtab"],
            SHT_SYMTAB,
            0,
            0,
            symtab_at,
            len(symtab),
            strtab_idx,  # sh_link: the string table
            first_global,  # sh_info: index of the first non-local symbol
            word,  # sh_addralign
            fmt.sym_size,  # sh_entsize
        )
        return bytes(out)
