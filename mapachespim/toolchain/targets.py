"""
Assembler targets: how the ISA-independent assembler drives each ISA's encoder.

Every encoder module (riscv, mips, arm64, x86) provides the same two
functions::

    encode(text, address, labels, **options) -> bytes
    instruction_size(text, labels, address, **options) -> int

A :class:`Target` wraps an encoder and adds the ISA's GNU as behaviors that
the assembler needs: per-line encoder options, the nops used to pad code,
and hooks for ARM64 literal pools and x86 jump relaxation. A new Target is
made for each assembly, so targets may keep per-program state.

To add an ISA, write its encoder module and a Target subclass here, and add
it to ``TARGETS``.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any, Dict, List, Mapping, Set, Tuple, Type

from ..isa import ISASpec, get_spec
from . import arm64, mips, riscv, x86
from .directives import (
    ALIGN_DIRECTIVES,
    POOL_LABEL_PREFIX,
    DirectiveParser,
    LineType,
    ParsedLine,
    SectionData,
    emits_data,
)
from .expr import EncodeError


class Target:
    """Default behavior: a fixed-width ISA whose code padding is zero bytes."""

    isa_name: str
    encoder: ModuleType

    def __init__(self, parser: DirectiveParser) -> None:
        self.parser = parser

    @property
    def spec(self) -> ISASpec:
        return get_spec(self.isa_name)

    def prepare(self, sections: Dict[str, SectionData]) -> None:
        """Rewrite the parsed program before layout (e.g. add literal pools).

        Raises:
            EncodeError: For an error in the program.
        """

    def options(self, line: ParsedLine) -> Dict[str, Any]:
        """Extra keyword arguments for the encoder for this line."""
        return {}

    def encode(self, line: ParsedLine, address: int, labels: Mapping[str, int]) -> bytes:
        return self.encoder.encode(line.instruction, address, labels, **self.options(line))

    def size(self, line: ParsedLine, address: int, labels: Mapping[str, int]) -> int:
        return self.encoder.instruction_size(
            line.instruction, labels, address, **self.options(line)
        )

    def padding_before_instruction(self, address: int, after_data: bool) -> int:
        """Zero bytes GNU as puts before an instruction at ``address``."""
        return 0

    def is_explicit_fill(self, fill: int) -> bool:
        """Whether an alignment fill byte replaces the default code padding."""
        return True

    def code_padding(self, count: int, line: ParsedLine) -> bytes:
        """``count`` bytes of padding for an alignment directive in code."""
        return bytes(count)

    can_relax = False
    """True if instruction sizes can grow during layout (see :meth:`relax`)."""

    def relax(self, line: ParsedLine, address: int, labels: Mapping[str, int]) -> bool:
        """Grow the instruction at ``line`` if it cannot reach its target.

        Returns True if it grew.
        """
        return False


class RISCVTarget(Target):
    isa_name = "riscv64"
    encoder = riscv

    def code_padding(self, count: int, line: ParsedLine) -> bytes:
        # As GNU as's riscv_make_nops: a zero byte if odd, at most one
        # 2-byte c.nop, then 4-byte nops
        head = bytes(count % 2) + (b"\x01\x00" if count % 4 >= 2 else b"")
        return head + (0x00000013).to_bytes(4, "little") * (count // 4)


class MIPSTarget(Target):
    isa_name = "mips32"
    encoder = mips
    # The MIPS nop is all zeros, so the default padding is right

    def options(self, line: ParsedLine) -> Dict[str, Any]:
        return {"reorder": line.reorder}  # .set reorder / noreorder


class ARM64Target(Target):
    isa_name = "arm64"
    encoder = arm64

    def prepare(self, sections: Dict[str, SectionData]) -> None:
        if ".text" in sections:
            add_literal_pools(sections[".text"])

    def padding_before_instruction(self, address: int, after_data: bool) -> int:
        # GNU as aligns an instruction to 4 bytes when it directly follows
        # data (when switching from data to code; an alignment directive in
        # between counts as code)
        return -address % 4 if after_data else 0

    def code_padding(self, count: int, line: ParsedLine) -> bytes:
        return bytes(count % 4) + (0xD503201F).to_bytes(4, "little") * (count // 4)


class X86Target(Target):
    isa_name = "x86_64"
    encoder = x86
    can_relax = True

    def __init__(self, parser: DirectiveParser) -> None:
        super().__init__(parser)
        self._absolute_symbols: Set[str] = set()  # names of .equ constants
        self._long_jumps: Set[int] = set()  # jumps that need rel32
        self._align_after_data: Set[int] = set()  # see _alignments_after_data

    def prepare(self, sections: Dict[str, SectionData]) -> None:
        self._absolute_symbols = set(self.parser.constants) | set(self.parser.deferred_constants)
        self._align_after_data = _alignments_after_data(sections.get(".text"))

    def options(self, line: ParsedLine) -> Dict[str, Any]:
        return {
            "syntax": line.syntax,
            "absolute_symbols": self._absolute_symbols,
            "long_jump": id(line) in self._long_jumps,
        }

    def is_explicit_fill(self, fill: int) -> bool:
        # GNU as treats a fill of 0x90 (nop) like no fill: best nops
        return fill & 0xFF != 0x90

    def code_padding(self, count: int, line: ParsedLine) -> bytes:
        return x86.nop_padding(count, id(line) in self._align_after_data)

    def relax(self, line: ParsedLine, address: int, labels: Mapping[str, int]) -> bool:
        # Jumps start short (rel8) and grow to rel32 once, for good, when the
        # target is out of range (GNU's relaxation)
        text = line.instruction or ""
        if (
            id(line) in self._long_jumps
            or not x86.is_relaxable(text)
            or x86.short_jump_fits(text, address, labels)
        ):
            return False
        self._long_jumps.add(id(line))
        return True


def _alignments_after_data(section: Any) -> Set[int]:
    """Alignment directives in code whose last preceding item is data.

    GNU as pads x86 code with a one-byte nop first in that case, since the
    data might be an incomplete instruction.
    """
    found: Set[int] = set()
    after_data = False
    for line in section.lines if section else []:
        if line.line_type == LineType.INSTRUCTION and line.instruction:
            after_data = False
        elif line.line_type == LineType.DIRECTIVE:
            if line.directive in ALIGN_DIRECTIVES:
                if after_data:
                    found.add(id(line))
            elif emits_data(line):
                after_data = True
    return found


def add_literal_pools(section: SectionData) -> None:
    """Turn ARM64 'ldr x0, =value' into loads from a literal pool.

    As in GNU as, each load reads a pool entry placed at the next
    .ltorg/.pool directive or at the end of the section. Within a pool,
    equal values share one entry; 4-byte entries come first, then 8-byte
    entries, each group aligned to its size.

    Raises:
        EncodeError: If a literal load is invalid.
    """
    lines: List[ParsedLine] = []
    pool: Dict[Tuple[object, ...], Tuple[str, str, int]] = {}  # key -> (label, expr, size)
    counter = 0

    def dump(line_number: int) -> None:
        for size in (4, 8):
            entries = [(label, expr) for label, expr, sz in pool.values() if sz == size]
            if not entries:
                continue
            lines.append(
                ParsedLine(
                    line_number,
                    LineType.DIRECTIVE,
                    "",
                    directive="balign",
                    directive_args=[str(size), "0"],  # zeros, not nops
                )
            )
            for label, expr in entries:
                lines.append(
                    ParsedLine(
                        line_number,
                        LineType.DIRECTIVE,
                        "",
                        label=label,
                        directive="word" if size == 4 else "dword",
                        directive_args=[expr],
                    )
                )
        pool.clear()

    last_line = 0
    for line in section.lines:
        last_line = line.line_number
        if line.line_type == LineType.INSTRUCTION and line.instruction:
            found = arm64.literal_load(line.instruction)
            if found is not None:
                mnemonic, rt, expr = found
                try:
                    size = arm64.literal_size(mnemonic, rt)
                except EncodeError as e:
                    raise EncodeError(f"Line {line.line_number}: {e}")
                value = arm64.constant_value(expr)
                key: Tuple[object, ...] = (
                    ("value", value & ((1 << (8 * size)) - 1), size)
                    if value is not None
                    else ("expr", expr.replace(" ", ""), size)
                )
                if key not in pool:
                    counter += 1
                    pool[key] = (f"{POOL_LABEL_PREFIX}{counter}", expr, size)
                line.instruction = f"{mnemonic} {rt}, {pool[key][0]}"
        lines.append(line)
        if line.line_type == LineType.DIRECTIVE and line.directive in ("ltorg", "pool"):
            dump(line.line_number)
    dump(last_line)
    section.lines = lines


TARGETS: Dict[str, Type[Target]] = {
    cls.isa_name: cls for cls in (RISCVTarget, MIPSTarget, ARM64Target, X86Target)
}


def target_for(isa: str, parser: DirectiveParser) -> Target:
    """A new Target for an ISA (name or alias)."""
    spec = get_spec(isa)
    try:
        return TARGETS[spec.name](parser)
    except KeyError:
        raise ValueError(f"No assembler for {spec.display_name}")
