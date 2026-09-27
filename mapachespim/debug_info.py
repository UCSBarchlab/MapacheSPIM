"""
Source-level debug information: which source line each address came from.

Reads the DWARF line table that ``mapachespim-as -g`` (and GNU tools with
``-g``) put in an ELF file, and caches the source files it refers to.
"""

from __future__ import annotations

import bisect
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from elftools.elf.elffile import ELFFile


class SourceInfo:
    """Cached source code information from DWARF debug info"""

    addr_to_line: Dict[int, Tuple[str, int]]
    source_cache: Dict[str, List[str]]
    has_debug_info: bool
    _sorted_addrs: List[int]  # Cached sorted address list for binary search

    def __init__(self) -> None:
        self.addr_to_line = {}  # address -> (filename, line_number)
        self.source_cache = {}  # filename -> list of source lines
        self.has_debug_info = False
        self._sorted_addrs = []

    def _build_sorted_addrs(self) -> None:
        """Build sorted address list for efficient lookup"""
        if not self._sorted_addrs and self.addr_to_line:
            self._sorted_addrs = sorted(self.addr_to_line.keys())

    def get_location(self, addr: int) -> Optional[Tuple[str, int]]:
        """Get source location for an address.

        Returns (filename, line_num) or None.

        For addresses within multi-instruction pseudo-ops (like 'la' which expands
        to auipc+addi), finds the nearest address <= the query address. This is
        standard debugger behavior - showing the source line that started the
        current instruction sequence.
        """
        # Try exact match first (fast path)
        if addr in self.addr_to_line:
            return self.addr_to_line[addr]

        # Build sorted address list if needed
        self._build_sorted_addrs()

        if not self._sorted_addrs:
            return None

        # Binary search for largest address <= addr
        idx = bisect.bisect_right(self._sorted_addrs, addr) - 1

        if idx >= 0:
            nearest_addr = self._sorted_addrs[idx]
            return self.addr_to_line[nearest_addr]

        return None

    def get_source_lines(
        self, filename: str, start_line: int, count: int = 10
    ) -> Optional[List[Tuple[int, str]]]:
        """Get source lines from cached file. Returns list of (line_num, text)"""
        if filename not in self.source_cache:
            return None

        lines = self.source_cache[filename]
        result: List[Tuple[int, str]] = []

        # Adjust to 0-indexed
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), start_idx + count)

        for i in range(start_idx, end_idx):
            result.append((i + 1, lines[i]))

        return result


def parse_line_info(elf_path: str, source_dirs: Optional[List[Path]] = None) -> SourceInfo:
    """Parse DWARF debug info and return SourceInfo object

    Source files are looked up relative to the current directory, the ELF's
    directory, and any extra ``source_dirs``.
    """
    source_info = SourceInfo()

    try:
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)

            if not elf.has_dwarf_info():
                return source_info

            dwarf_info = elf.get_dwarf_info()
            source_info.has_debug_info = True

            # Parse line programs from all compilation units
            for CU in dwarf_info.iter_CUs():
                line_program = dwarf_info.line_program_for_CU(CU)
                if not line_program:
                    continue

                file_entries = line_program["file_entry"]
                # File numbers start at 1 before DWARF 5 and at 0 from DWARF 5
                first_file = 1 if line_program["version"] < 5 else 0

                for entry in line_program.get_entries():
                    state = entry.state
                    if state is None or state.end_sequence:
                        continue
                    index = state.file - first_file
                    if not 0 <= index < len(file_entries):
                        continue
                    name = file_entries[index].name
                    filename = name.decode("utf-8") if isinstance(name, bytes) else name
                    source_info.addr_to_line[state.address] = (filename, state.line)
                    if filename not in source_info.source_cache:
                        _load_source_file(source_info, filename, elf_path, source_dirs)

            return source_info

    except Exception:
        # If DWARF parsing fails, just return empty source info
        return source_info


def _load_source_file(
    source_info: SourceInfo,
    filename: str,
    elf_path: str,
    source_dirs: Optional[List[Path]] = None,
) -> None:
    """Try to load source file contents into cache"""
    # Extra directories (e.g. where an assembled .s file lives) come first
    search_paths = []
    for directory in source_dirs or []:
        search_paths += [directory / filename, directory / Path(filename).name]

    # Then relative to the current directory and the ELF location
    elf_dir = Path(elf_path).parent
    search_paths += [
        Path(filename),  # Absolute or relative to CWD
        elf_dir / filename,  # Relative to ELF
        elf_dir / Path(filename).name,  # Just filename in ELF dir
    ]

    for path in search_paths:
        try:
            if path.exists() and path.is_file():
                with open(path) as f:
                    source_info.source_cache[filename] = f.read().splitlines()
                return
        except Exception:
            continue

    # If we couldn't find the file, store empty list
    source_info.source_cache[filename] = []
