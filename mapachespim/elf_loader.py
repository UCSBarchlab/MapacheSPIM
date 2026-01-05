"""
Pure Python ELF file loader using pyelftools

Replaces the C++ ELFIO-based loader with a clean Python implementation.
Supports RISC-V, ARM64, and x86-64 ELF binaries.
"""

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Dict, List

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError as e:
    raise ImportError(
        "pyelftools not installed. Install with: pip install pyelftools\n"
        f"Original error: {e}"
    )


class ISA(IntEnum):
    """ISA types - matches the C++ enum"""
    RISCV = 0
    ARM = 1
    X86_64 = 2
    UNKNOWN = -1


class Architecture(IntEnum):
    """Architecture variants"""
    RV32 = 0
    RV64 = 1
    ARM32 = 2
    ARM64 = 3
    X86_64 = 4
    UNKNOWN = -1


@dataclass
class ELFSegment:
    """Loadable ELF segment"""
    vaddr: int  # Virtual address
    paddr: int  # Physical address
    filesz: int  # Size in file
    memsz: int  # Size in memory
    data: bytes  # Segment data


@dataclass
class ELFInfo:
    """Parsed ELF file information"""
    isa: ISA
    architecture: Architecture
    entry: int
    segments: List[ELFSegment]
    symbols: Dict[str, int]


def detect_isa_from_elf(elf):
    """
    Detect ISA from ELF file header

    Args:
        elf: ELFFile object

    Returns:
        ISA: Detected ISA type
    """
    machine = elf.header['e_machine']

    if machine == 'EM_RISCV':
        return ISA.RISCV
    elif machine == 'EM_AARCH64':
        return ISA.ARM
    elif machine == 'EM_ARM':
        return ISA.ARM  # 32-bit ARM (we'll treat as ARM for now)
    elif machine == 'EM_X86_64':
        return ISA.X86_64
    else:
        return ISA.UNKNOWN


def detect_architecture(elf, isa):
    """
    Detect specific architecture variant

    Args:
        elf: ELFFile object
        isa: ISA type

    Returns:
        Architecture: Specific architecture
    """
    elf_class = elf.header['e_ident']['EI_CLASS']

    if isa == ISA.RISCV:
        if elf_class == 'ELFCLASS64':
            return Architecture.RV64
        elif elf_class == 'ELFCLASS32':
            return Architecture.RV32
    elif isa == ISA.ARM:
        if elf_class == 'ELFCLASS64':
            return Architecture.ARM64
        elif elf_class == 'ELFCLASS32':
            return Architecture.ARM32
    elif isa == ISA.X86_64:
        # x86-64 is always 64-bit
        return Architecture.X86_64

    return Architecture.UNKNOWN


def extract_loadable_segments(elf):
    """
    Extract PT_LOAD segments from ELF file

    Args:
        elf: ELFFile object

    Returns:
        List[ELFSegment]: List of loadable segments
    """
    segments = []

    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            seg = ELFSegment(
                vaddr=segment['p_vaddr'],
                paddr=segment['p_paddr'],
                filesz=segment['p_filesz'],
                memsz=segment['p_memsz'],
                data=segment.data()
            )
            segments.append(seg)

    return segments


def parse_symbol_table(elf):
    """
    Parse symbol table from ELF file

    Only includes STT_FUNC, STT_OBJECT, STT_COMMON, and STT_NOTYPE symbols
    that are not SHN_UNDEF.

    Args:
        elf: ELFFile object

    Returns:
        Dict[str, int]: Dictionary mapping symbol names to addresses
    """
    symbols = {}

    # Iterate through all sections looking for symbol tables
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue

        for symbol in section.iter_symbols():
            # Skip undefined symbols
            if symbol['st_shndx'] == 'SHN_UNDEF':
                continue

            # Only include specific symbol types
            symbol_type = symbol['st_info']['type']
            if symbol_type not in ('STT_FUNC', 'STT_OBJECT', 'STT_COMMON', 'STT_NOTYPE'):
                continue

            # Skip symbols with empty names
            name = symbol.name
            if not name:
                continue

            # Add to symbol table
            symbols[name] = symbol['st_value']

    return symbols


def load_elf_file(path: str) -> ELFInfo:
    """
    Load and parse an ELF file

    Args:
        path: Path to ELF file

    Returns:
        ELFInfo: Parsed ELF information

    Raises:
        FileNotFoundError: If file doesn't exist
        RuntimeError: If file is not a valid ELF
    """
    elf_path = Path(path)

    if not elf_path.exists():
        raise FileNotFoundError(f"ELF file not found: {path}")

    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)

            # Detect ISA and architecture
            isa = detect_isa_from_elf(elf)
            if isa == ISA.UNKNOWN:
                raise RuntimeError(
                    f"Unsupported ELF machine type: {elf.header['e_machine']}"
                )

            architecture = detect_architecture(elf, isa)

            # Get entry point
            entry = elf.header['e_entry']

            # Extract loadable segments
            segments = extract_loadable_segments(elf)

            # Parse symbol table
            symbols = parse_symbol_table(elf)

            return ELFInfo(
                isa=isa,
                architecture=architecture,
                entry=entry,
                segments=segments,
                symbols=symbols
            )

    except Exception as e:
        raise RuntimeError(f"Failed to parse ELF file {path}: {e}")
