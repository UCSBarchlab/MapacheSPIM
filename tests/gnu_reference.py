"""
Reference assembly with GNU binutils, for differential testing.

The built-in assemblers promise byte-for-byte the same machine code as GNU as
(with the options below) for every instruction they accept. These helpers
assemble a program with the GNU cross toolchain, link it at MapacheSPIM's
memory layout, and return the .text bytes so tests can compare.

The GNU tools are optional: tests using them are skipped when they are not
installed. On Debian/Ubuntu:

    sudo apt install binutils-riscv64-linux-gnu binutils-mips-linux-gnu \\
        binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from elftools.elf.elffile import ELFFile

from mapachespim.memory_map import get_layout


@dataclass(frozen=True)
class GnuTarget:
    prefix: str
    as_flags: Tuple[str, ...]
    prologue: str  # directives that select MapacheSPIM's conventions


TARGETS: Dict[str, GnuTarget] = {
    "riscv64": GnuTarget(
        "riscv64-linux-gnu-",
        ("-march=rv64im", "-mabi=lp64", "-mno-relax"),
        # No compressed instructions, no linker relaxation, absolute code
        ".option norvc\n.option norelax\n.option nopic\n",
    ),
    "mips32": GnuTarget(
        "mips-linux-gnu-",
        ("-march=mips32", "-EB", "-mno-shared", "-O0", "-32"),
        # Delay slots filled with nop (reorder mode), no optimization
        ".set reorder\n",
    ),
}

# Number of random instances per instruction form; raise for deeper runs:
#   MAPACHESPIM_FUZZ_SCALE=20 python -m pytest tests/test_differential_*.py
FUZZ_SCALE = max(1, int(os.environ.get("MAPACHESPIM_FUZZ_SCALE", "1")))


def gnu_available(isa: str) -> bool:
    target = TARGETS[isa]
    return all(shutil.which(target.prefix + tool) for tool in ("as", "ld"))


def _linker_script(isa: str) -> str:
    layout = get_layout(isa)
    return f"""
SECTIONS {{
  . = 0x{layout.text_base:x};
  .text : {{ *(.text) }}
  . = 0x{layout.rodata_base:x};
  .rodata : {{ *(.rodata) }}
  . = 0x{layout.data_base:x};
  .data : {{ *(.data) }}
  . = 0x{layout.bss_base:x};
  .bss : {{ *(.bss) }}
  /* MapacheSPIM places other sections 64KB after .bss */
  . = 0x{layout.bss_base + 0x10000:x};
  .tohost : {{ *(.tohost) }}
}}
"""


class GnuError(Exception):
    """GNU as or ld rejected the input."""


def gnu_assemble(isa: str, source: str, section: str = ".text") -> bytes:
    """Assemble and link `source` with GNU tools; return a section's bytes."""
    target = TARGETS[isa]
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "prog.s").write_text(target.prologue + source + "\n")
        (tmpdir / "link.ld").write_text(_linker_script(isa))
        steps = [
            [target.prefix + "as", *target.as_flags, "prog.s", "-o", "prog.o"],
            [target.prefix + "ld", "-T", "link.ld", "prog.o", "-o", "prog", "-e", "0"],
        ]
        for cmd in steps:
            result = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
            if result.returncode != 0:
                raise GnuError(result.stderr.strip())
        with open(tmpdir / "prog", "rb") as f:
            found = ELFFile(f).get_section_by_name(section)
            return found.data() if found is not None else b""


def gnu_accepts(isa: str, source: str) -> bool:
    try:
        gnu_assemble(isa, source)
        return True
    except GnuError:
        return False


RISCV_NOP = (0x00000013).to_bytes(4, "little")


def trim_padding(gnu: bytes, ours: bytes) -> bytes:
    """Drop the padding GNU as adds at the end of a section to reach its
    alignment: zeros, or nop instructions in RISC-V code."""
    tail = gnu[len(ours) :]
    if len(gnu) > len(ours) and (
        not tail.strip(b"\0") or (len(tail) % 4 == 0 and tail == RISCV_NOP * (len(tail) // 4))
    ):
        return gnu[: len(ours)]
    return gnu


def ours_assemble(isa: str, source: str):  # -> AssemblyResult
    from mapachespim.toolchain import Assembler

    return Assembler(isa).assemble(source)


def ours_text(
    isa: str, source: str, section: str = ".text"
) -> Tuple[bytes, List[str], List[Tuple[int, int]]]:
    """Assemble with MapacheSPIM; return (section bytes, errors, debug_lines)."""
    from io import BytesIO

    result = ours_assemble(isa, source)
    if not result.success:
        return b"", result.errors, []
    elf = ELFFile(BytesIO(result.elf_bytes))
    found = elf.get_section_by_name(section)
    return (found.data() if found is not None else b""), [], result.debug_lines


def describe_mismatch(isa: str, source: str, ours: bytes, gnu: bytes, debug_lines) -> str:
    """Explain the first differing instruction, with its source line."""
    layout = get_layout(isa)
    order = "big" if not layout.is_little_endian else "little"
    lines = source.splitlines()
    for offset in range(0, max(len(ours), len(gnu)), 4):
        a, b = ours[offset : offset + 4], gnu[offset : offset + 4]
        if a != b:
            addr = layout.text_base + offset
            # The source line whose code starts at or before this address
            line_no: Optional[int] = None
            for line_addr, line in debug_lines:
                if line_addr <= addr:
                    line_no = line
            src = lines[line_no - 1].strip() if line_no and line_no <= len(lines) else "?"
            fmt = lambda w: f"{int.from_bytes(w, order):08x}" if len(w) == 4 else "(none)"  # noqa: E731
            return (
                f"first difference at 0x{addr:x} (line {line_no}: {src!r}): "
                f"ours {fmt(a)} vs GNU {fmt(b)}; lengths ours={len(ours)} GNU={len(gnu)}"
            )
    return "identical"
