"""
ELF executable loading (using pyelftools).

Reads what the simulator needs from an ELF file: its ISA, entry point,
loadable segments, sections, and symbols.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError as e:
    raise ImportError(
        f"pyelftools not installed. Install with: pip install pyelftools\nOriginal error: {e}"
    )

from .isa import ISA, ISASpec, isa_names, spec_for_elf

__all__ = ["ELFInfo", "ELFSection", "ELFSegment", "ISA", "load_elf_file"]

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


@dataclass
class ELFSegment:
    """Loadable ELF segment"""

    vaddr: int  # Virtual address
    paddr: int  # Physical address
    filesz: int  # Size in file
    memsz: int  # Size in memory
    data: bytes  # Segment data


@dataclass(frozen=True)
class ELFSection:
    """An ELF section header"""

    name: str
    address: int
    size: int
    flags: int

    @property
    def loaded(self) -> bool:
        """True if the section occupies memory when the program runs."""
        return bool(self.flags & SHF_ALLOC) and self.address != 0

    @property
    def flag_letters(self) -> str:
        """Flags as in readelf: W (write), A (alloc), X (execute)."""
        return "".join(
            letter
            for bit, letter in ((SHF_WRITE, "W"), (SHF_ALLOC, "A"), (SHF_EXECINSTR, "X"))
            if self.flags & bit
        )


@dataclass
class ELFInfo:
    """Parsed ELF file information"""

    spec: ISASpec
    entry: int
    segments: List[ELFSegment]
    symbols: Dict[str, int]
    sections: List[ELFSection] = field(default_factory=list)

    @property
    def isa(self) -> ISA:
        return self.spec.isa


def _segments(elf: ELFFile) -> List[ELFSegment]:
    return [
        ELFSegment(
            vaddr=segment["p_vaddr"],
            paddr=segment["p_paddr"],
            filesz=segment["p_filesz"],
            memsz=segment["p_memsz"],
            data=segment.data(),
        )
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_LOAD"
    ]


def _sections(elf: ELFFile) -> List[ELFSection]:
    return [
        ELFSection(s.name, s["sh_addr"], s["sh_size"], s["sh_flags"])
        for s in elf.iter_sections()
        if s.name
    ]


def _symbols(elf: ELFFile) -> Dict[str, int]:
    """Named, defined symbols of type FUNC, OBJECT, COMMON, or NOTYPE."""
    symbols = {}
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            if symbol["st_shndx"] == "SHN_UNDEF" or not symbol.name:
                continue
            if symbol["st_info"]["type"] not in (
                "STT_FUNC",
                "STT_OBJECT",
                "STT_COMMON",
                "STT_NOTYPE",
            ):
                continue
            symbols[symbol.name] = symbol["st_value"]
    return symbols


def load_elf_file(path: str) -> ELFInfo:
    """
    Load and parse an ELF file

    Raises:
        FileNotFoundError: If file doesn't exist
        RuntimeError: If the file is not a valid ELF for a supported ISA
    """
    elf_path = Path(path)
    if not elf_path.exists():
        raise FileNotFoundError(f"ELF file not found: {path}")

    try:
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            machine = elf.header["e_machine"]
            is_64bit = elf.elfclass == 64
            spec = spec_for_elf(machine, is_64bit)
            if spec is None:
                raise RuntimeError(
                    f"Unsupported ELF machine type: {machine} ({elf.elfclass}-bit); "
                    f"supported ISAs: {', '.join(isa_names())}"
                )
            return ELFInfo(
                spec=spec,
                entry=elf.header["e_entry"],
                segments=_segments(elf),
                symbols=_symbols(elf),
                sections=_sections(elf),
            )
    except Exception as e:
        raise RuntimeError(f"Failed to parse ELF file {path}: {e}")
