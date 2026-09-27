"""
Access to the bundled example programs.

Wheels ship the repository's ``examples/`` directory as
``mapachespim/examples``, so examples are available after a plain
``pip install``. In a source checkout (including editable installs) the
repository's ``examples/`` directory is used instead.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# ISA directory name -> display name, in the order examples are listed
ISA_DIRS = {
    "riscv": "RISC-V 64-bit",
    "mips": "MIPS32",
    "arm": "ARM64",
    "x86_64": "x86-64",
}

SOURCE_SUFFIXES = (".s", ".S", ".asm")


@dataclass
class Example:
    """One example program."""

    isa: str
    """ISA directory name, e.g. 'riscv'."""

    name: str
    """Example directory name, e.g. 'fibonacci'."""

    binary: Path
    """Prebuilt ELF executable."""

    source: Optional[Path]
    """Assembly source file, if present."""

    description: str
    """One-line description taken from the source file's header comment."""

    @property
    def short_name(self) -> str:
        """Name accepted by the console's load command, e.g. 'riscv/fibonacci'."""
        return f"{self.isa}/{self.name}"


def examples_dir() -> Optional[Path]:
    """Directory containing the bundled examples, or None if unavailable."""
    package_dir = Path(__file__).resolve().parent
    for candidate in (package_dir / "examples", package_dir.parent / "examples"):
        if (candidate / "riscv").is_dir():
            return candidate
    return None


def _describe(source: Optional[Path]) -> str:
    """Pull a short description from the header comment of a source file."""
    if source is None:
        return ""
    try:
        lines = source.read_text(errors="replace").splitlines()[:6]
    except OSError:
        return ""
    for line in lines:
        text = line.strip().lstrip("#/;").strip()
        if not text or set(text) <= set("=-*"):
            continue
        # "hello_asm.s - Your First ..." / "RISC-V 64-bit Assembly: Recursive ..."
        for sep in (" - ", ": "):
            if sep in text:
                text = text.split(sep, 1)[1]
                break
        return text
    return ""


def _find_program(directory: Path) -> Optional[Example]:
    sources = sorted(p for p in directory.iterdir() if p.suffix in SOURCE_SUFFIXES)
    source = sources[0] if sources else None
    candidates = []
    if source is not None:
        candidates.append(directory / source.stem)
    candidates.append(directory / directory.name)
    binary = next((c for c in candidates if c.is_file()), None)
    if binary is None:
        return None
    return Example(
        isa=directory.parent.name,
        name=directory.name,
        binary=binary,
        source=source,
        description=_describe(source),
    )


def list_examples() -> List[Example]:
    """All bundled examples, grouped by ISA in ISA_DIRS order."""
    root = examples_dir()
    if root is None:
        return []
    result: List[Example] = []
    for isa in ISA_DIRS:
        isa_dir = root / isa
        if not isa_dir.is_dir():
            continue
        for directory in sorted(p for p in isa_dir.iterdir() if p.is_dir()):
            example = _find_program(directory)
            if example is not None:
                result.append(example)
    return result


def find_example(name: str) -> Optional[Path]:
    """
    Resolve an example name to a file in the bundled examples.

    Accepts short names ('riscv/fibonacci'), paths inside the examples tree
    ('riscv/fibonacci/fibonacci', 'riscv/fibonacci/fibonacci.s'), and the
    repository-relative paths used in the documentation
    ('examples/riscv/fibonacci/fibonacci').
    """
    root = examples_dir()
    if root is None:
        return None
    rel = name.strip().replace("\\", "/").strip("/")
    if rel.startswith("examples/"):
        rel = rel[len("examples/") :]
    if not rel:
        return None

    candidate = (root / rel).resolve()
    # Only files inside the examples tree are examples
    if root.resolve() not in candidate.parents:
        return None
    if candidate.is_file():
        return candidate
    if candidate.is_dir() and candidate.parent.name in ISA_DIRS:
        example = _find_program(candidate)
        if example is not None:
            return example.binary
    return None


def copy_examples(destination: Path) -> Path:
    """
    Copy the bundled examples to ``destination`` so they can be edited.

    Returns the destination path.

    Raises:
        FileNotFoundError: If the examples are not available.
        FileExistsError: If the destination already exists.
    """
    root = examples_dir()
    if root is None:
        raise FileNotFoundError("The bundled examples are not available in this installation")
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(f"{destination} already exists")
    shutil.copytree(
        root,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.o", "*.dis"),
    )
    return destination
