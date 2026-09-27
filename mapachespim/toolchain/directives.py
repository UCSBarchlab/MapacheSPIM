"""
Assembly directive parser for MapacheSPIM toolchain.

Parses GNU-as compatible assembly directives and organizes source
into sections for assembly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Literal, Optional, Tuple

from .expr import ExpressionError, UndefinedSymbol, evaluate


class LineType(Enum):
    """Type of assembly source line."""

    EMPTY = auto()
    COMMENT = auto()
    LABEL = auto()
    DIRECTIVE = auto()
    INSTRUCTION = auto()


@dataclass
class ParsedLine:
    """A parsed line of assembly source."""

    line_number: int
    """Original line number (1-based)."""

    line_type: LineType
    """Type of this line."""

    content: str
    """Original line content."""

    label: Optional[str] = None
    """Label defined on this line, if any."""

    directive: Optional[str] = None
    """Directive name (e.g., ".text", ".word")."""

    directive_args: List[str] = field(default_factory=list)
    """Arguments to the directive."""

    instruction: Optional[str] = None

    reorder: bool = True
    """MIPS: whether the assembler fills delay slots (.set reorder, the default)."""
    """Instruction mnemonic and operands."""


@dataclass
class SectionData:
    """Data accumulated for a section during parsing."""

    name: str
    """Section name (e.g., ".text")."""

    lines: List[ParsedLine] = field(default_factory=list)
    """Lines belonging to this section."""

    labels: Dict[str, int] = field(default_factory=dict)
    """Labels defined in this section (name -> offset)."""

    data: bytearray = field(default_factory=bytearray)
    """Accumulated data bytes."""

    current_offset: int = 0
    """Current offset within section."""

    fixups: List[Fixup] = field(default_factory=list)
    """Data values that refer to labels, filled in once addresses are known."""

    pending_labels: List[str] = field(default_factory=list)
    """Labels defined since the last data or instruction (MIPS auto-alignment
    moves these along with the data that follows them)."""


@dataclass
class Fixup:
    """A data value whose expression needs label addresses."""

    offset: int
    size: int
    expression: str
    line_number: int
    byteorder: Literal["little", "big"]


# Data directives: name -> size of each value in bytes
DATA_SIZES: Dict[str, int] = {
    "byte": 1,
    "half": 2, "short": 2, "2byte": 2, "hword": 2,
    "word": 4, "long": 4, "4byte": 4, "int": 4,
    "dword": 8, "quad": 8, "8byte": 8,
}  # fmt: skip

# The location counter '.', when it appears as a symbol in an expression
_DOT_RE = re.compile(r"(?<![\w.$])\.(?![\w.$])")

# Prefix of internal labels that stand in for '.' (not emitted as symbols)
DOT_LABEL_PREFIX = ".L.dot."


class DirectiveParser:
    """
    Parser for GNU-as compatible assembly directives.

    Supports:
    - Section directives: .text, .data, .rodata, .bss
    - Symbol directives: .globl, .global, .local
    - Data directives: .byte, .half, .word, .dword, .quad
    - String directives: .ascii, .asciz, .string
    - Alignment: .align, .balign, .p2align
    - Space: .space, .skip, .zero
    - Constants: .equ, .set
    - Architecture hints: .arch, .option
    """

    # Regex patterns
    LABEL_PATTERN = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*):(.*)$")
    DIRECTIVE_PATTERN = re.compile(r"^\s*\.(\w+)\s*(.*)$")
    # Hash comment: # at start, or # preceded by space and NOT followed by digit/minus (ARM immediate)
    # This handles both #42 and #-32 as ARM immediates, not comments
    HASH_COMMENT = re.compile(r"(^|\s)#(?!-?\d).*$")
    COMMENT_PATTERNS = [
        re.compile(r"//.*$"),  # C++ style
        re.compile(r";.*$"),  # Semicolon comments
    ]

    _ASSIGN_PATTERN = re.compile(r"^([A-Za-z_.$][\w.$]*)\s*=\s*(\S.*)$")

    # MIPS ".set" options that are accepted but have no effect here
    KNOWN_SET_OPTIONS = {
        "at", "noat", "macro", "nomacro", "push", "pop", "mips32", "mips32r2",
        "mips1", "mips2", "volatile", "novolatile", "move", "nomove",
    }  # fmt: skip

    # Valid ISA values for .isa directive
    VALID_ISAS = {"riscv64", "arm64", "x86_64", "mips32"}

    # Big-endian ISAs (default is little-endian)
    BIG_ENDIAN_ISAS = {"mips32"}

    # ISAs whose GNU assembler aligns .half/.word/.dword automatically
    AUTO_ALIGN_ISAS = {"mips32"}

    def __init__(self, isa: Optional[str] = None) -> None:
        """
        Args:
            isa: Target ISA, if known (e.g. from the assembler's --isa). It
                decides byte order and what .align means; an .isa directive
                in the source is used when this is not given.
        """
        self.target_isa = isa.lower().replace("-", "_") if isa else None
        self.sections: Dict[str, SectionData] = {}
        self.current_section: str = ".text"
        self.global_symbols: set = set()
        self.local_symbols: set = set()
        self.constants: Dict[str, int] = {}
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.isa: Optional[str] = None  # ISA from .isa directive
        # .equ/.set constants that refer to labels: name -> (expression, line)
        self.deferred_constants: Dict[str, Tuple[str, int]] = {}
        self.reorder = True  # MIPS .set reorder / .set noreorder
        self._dot_count = 0

        # Initialize default sections
        for name in [".text", ".data", ".rodata", ".bss"]:
            self.sections[name] = SectionData(name=name)

    @property
    def _effective_isa(self) -> Optional[str]:
        return self.target_isa or self.isa

    def _get_endianness(self) -> Literal["little", "big"]:
        """Return byte order for data directives based on ISA."""
        if self._effective_isa in self.BIG_ENDIAN_ISAS:
            return "big"
        return "little"

    def _alignment(self, directive: str, value: int) -> int:
        """Alignment in bytes for .align/.balign/.p2align with argument value.

        As in GNU as, .align takes a power of two on RISC-V, MIPS, and ARM,
        but a byte count on x86.
        """
        if directive == "balign" or (directive == "align" and self._effective_isa == "x86_64"):
            return value
        return 1 << value

    def _dot_label(self, section: SectionData) -> str:
        """Define an internal label at the current location, to stand for '.'."""
        self._dot_count += 1
        name = f"{DOT_LABEL_PREFIX}{self._dot_count}"
        section.labels[name] = section.current_offset
        return name

    def _constant(self, name: str) -> int:
        if name in self.constants:
            return self.constants[name]
        raise UndefinedSymbol(name)

    def data_bytes(
        self,
        directive: str,
        args: List[str],
        resolve: Callable[[str], int],
        offset: int = 0,
        fixups: Optional[List[Fixup]] = None,
        line_number: int = 0,
    ) -> Optional[bytes]:
        """
        Bytes produced by a data directive (.word, .asciz, .space, .align...).

        Values are evaluated with ``resolve``. If ``fixups`` is given, values
        that refer to undefined symbols are emitted as zeros and recorded
        there to be filled in later; otherwise UndefinedSymbol propagates.

        Returns:
            The bytes, or None if ``directive`` is not a data directive.

        Raises:
            ExpressionError: For invalid values.
        """
        byteorder = self._get_endianness()

        if directive in DATA_SIZES:
            size = DATA_SIZES[directive]
            out = bytearray()
            for arg in args:
                try:
                    value = evaluate(arg, resolve)
                except UndefinedSymbol:
                    if fixups is None:
                        raise
                    fixups.append(Fixup(offset + len(out), size, arg, line_number, byteorder))
                    value = 0
                out += (value & ((1 << (8 * size)) - 1)).to_bytes(size, byteorder)
            return bytes(out)

        if directive in ("ascii", "asciz", "string"):
            out = bytearray()
            for arg in args:
                out += self._parse_string_bytes(arg)
                if directive != "ascii":
                    out.append(0)
            return bytes(out)

        if directive in ("space", "skip", "zero"):
            if not args:
                raise ExpressionError(f".{directive} needs a size")
            size = evaluate(args[0], resolve)
            if size < 0:
                raise ExpressionError(f".{directive} size must not be negative")
            fill = evaluate(args[1], resolve) & 0xFF if len(args) > 1 else 0
            return bytes([fill]) * size

        if directive in ("align", "balign", "p2align"):
            if not args:
                raise ExpressionError(f".{directive} needs an alignment")
            alignment = self._alignment(directive, evaluate(args[0], resolve))
            if alignment <= 0 or alignment & (alignment - 1):
                raise ExpressionError(f"alignment {alignment} is not a power of 2")
            fill = evaluate(args[1], resolve) & 0xFF if len(args) > 1 and args[1] else 0
            return bytes([fill]) * ((alignment - offset % alignment) % alignment)

        return None

    def parse(self, source: str) -> Dict[str, SectionData]:
        """
        Parse assembly source into sections.

        Args:
            source: Assembly source code.

        Returns:
            Dictionary of section name -> SectionData.
        """
        lines = source.splitlines()

        for line_num, line in enumerate(lines, 1):
            try:
                parsed = self._parse_line(line_num, line)
                if parsed.line_type not in (LineType.EMPTY, LineType.COMMENT):
                    parsed.reorder = self.reorder
                    section = self.sections[self.current_section]
                    section.lines.append(parsed)

                    # Handle labels
                    if parsed.label:
                        if parsed.label in self.constants:
                            section.labels[parsed.label] = self.constants[parsed.label]
                        else:
                            section.labels[parsed.label] = section.current_offset
                            section.pending_labels.append(parsed.label)

                    # Process directive data
                    if parsed.directive:
                        self._process_directive(parsed, section)
                    elif parsed.line_type == LineType.INSTRUCTION:
                        section.pending_labels.clear()

            except Exception as e:
                self.errors.append(f"Line {line_num}: {e}")

        return self.sections

    def _parse_line(self, line_num: int, line: str) -> ParsedLine:
        """Parse a single line of assembly."""
        original = line

        # Strip hash comments (# at start or after space, but not ARM immediates like #42)
        line = self.HASH_COMMENT.sub(r"\1", line)
        # Strip other comment styles
        for pattern in self.COMMENT_PATTERNS:
            line = pattern.sub("", line)

        line = line.strip()

        # Empty line
        if not line:
            return ParsedLine(line_num, LineType.EMPTY, original)

        # Symbol assignment: "name = expression" (same as .set name, expression)
        assign = self._ASSIGN_PATTERN.match(line)
        if assign:
            return ParsedLine(
                line_num,
                LineType.DIRECTIVE,
                original,
                directive="set",
                directive_args=[assign.group(1), assign.group(2).strip()],
            )

        # Check for label
        label = None
        label_match = self.LABEL_PATTERN.match(line)
        if label_match:
            label = label_match.group(1)
            line = label_match.group(2).strip()

        # Empty after label
        if not line:
            return ParsedLine(line_num, LineType.LABEL, original, label=label)

        # Check for directive
        dir_match = self.DIRECTIVE_PATTERN.match(line)
        if dir_match:
            directive = dir_match.group(1).lower()
            args_str = dir_match.group(2).strip()
            args = self._parse_args(args_str) if args_str else []
            return ParsedLine(
                line_num,
                LineType.DIRECTIVE,
                original,
                label=label,
                directive=directive,
                directive_args=args,
            )

        # Must be an instruction
        return ParsedLine(line_num, LineType.INSTRUCTION, original, label=label, instruction=line)

    def _parse_args(self, args_str: str) -> List[str]:
        """Parse comma-separated directive arguments, respecting quotes."""
        args = []
        current = ""
        in_string = False
        string_char = None

        for char in args_str:
            if in_string:
                current += char
                if char == string_char:
                    in_string = False
            elif char in "\"'":
                in_string = True
                string_char = char
                current += char
            elif char == ",":
                if current.strip():
                    args.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            args.append(current.strip())

        return args

    def _process_directive(self, parsed: ParsedLine, section: SectionData) -> None:
        """Process a directive and update section data."""
        directive = parsed.directive
        args = parsed.directive_args

        # ISA directive - must specify target architecture
        if directive == "isa":
            if not args:
                self.errors.append(
                    f"Line {parsed.line_number}: .isa directive requires an argument "
                    f"(one of: {', '.join(sorted(self.VALID_ISAS))})"
                )
                return
            isa_value = args[0].lower().replace("-", "_")
            if isa_value not in self.VALID_ISAS:
                self.errors.append(
                    f"Line {parsed.line_number}: Invalid ISA '{args[0]}'. "
                    f"Valid options: {', '.join(sorted(self.VALID_ISAS))}"
                )
                return
            self.isa = isa_value
            return

        # Section directives
        if directive in ("text", "data", "rodata", "bss"):
            self.current_section = f".{directive}"
            return

        if directive == "section":
            if args:
                sect_name = args[0].strip('"')
                if not sect_name.startswith("."):
                    sect_name = f".{sect_name}"
                if sect_name not in self.sections:
                    self.sections[sect_name] = SectionData(name=sect_name)
                self.current_section = sect_name
            return

        # Symbol visibility
        if directive in ("globl", "global"):
            for arg in args:
                self.global_symbols.add(arg)
            return

        if directive == "local":
            for arg in args:
                self.local_symbols.add(arg)
            return

        # MIPS assembler options: ".set noreorder", ".set noat", ...
        if directive == "set" and len(args) == 1:
            option = args[0].lower()
            if option in ("reorder", "noreorder"):
                self.reorder = option == "reorder"
            elif option not in self.KNOWN_SET_OPTIONS:
                self.warnings.append(f"Line {parsed.line_number}: Unknown option .set {args[0]}")
            return

        # Constants
        if directive in ("equ", "set", "equiv"):
            if len(args) < 2:
                self.errors.append(
                    f"Line {parsed.line_number}: .{directive} needs a name and a value"
                )
                return
            self._define_constant(args[0], args[1], parsed.line_number, section)
            return

        # Data directives - these add bytes to current section

        # Like GNU as for MIPS, align .half/.word/.dword to their size, and
        # move labels that were waiting for this data along with it
        if (
            directive in DATA_SIZES
            and DATA_SIZES[directive] > 1
            and self._effective_isa in self.AUTO_ALIGN_ISAS
        ):
            size = DATA_SIZES[directive]
            padding = (size - section.current_offset % size) % size
            if padding:
                section.data.extend(b"\x00" * padding)
                section.current_offset += padding
                for label in section.pending_labels:
                    section.labels[label] = section.current_offset

        expr_args = [_DOT_RE.sub(lambda m: self._dot_label(section), a) for a in args]
        try:
            data = self.data_bytes(
                directive or "",
                expr_args,
                self._constant,
                offset=section.current_offset,
                fixups=section.fixups,
                line_number=parsed.line_number,
            )
        except ExpressionError as e:
            self.errors.append(f"Line {parsed.line_number}: .{directive}: {e}")
            return
        if data is not None:
            section.data.extend(data)
            section.current_offset += len(data)
            if data:
                section.pending_labels.clear()
            return

        # Architecture hints (ignored, but don't warn)
        if directive in ("arch", "option", "attribute", "file", "ident", "size", "type"):
            return

        # Unknown directive
        self.warnings.append(f"Line {parsed.line_number}: Unknown directive .{directive}")

    def _define_constant(
        self, name: str, expression: str, line_number: int, section: SectionData
    ) -> None:
        """Handle .equ/.set/'name = value'."""
        expression = _DOT_RE.sub(lambda m: self._dot_label(section), expression)
        try:
            self.constants[name] = evaluate(expression, self._constant)
        except UndefinedSymbol:
            # Refers to labels (e.g. "len = . - msg"); resolved after layout
            self.deferred_constants[name] = (expression, line_number)
        except ExpressionError as e:
            self.errors.append(f"Line {line_number}: {name}: {e}")

    def _evaluate_expr(self, expr: str) -> int:
        """Evaluate an expression using the constants defined so far."""
        return evaluate(expr, self._constant)

    _STRING_ESCAPES = {
        "n": 10, "t": 9, "r": 13, "\\": 92, '"': 34, "'": 39,
        "a": 7, "b": 8, "f": 12, "v": 11, "e": 27,
    }  # fmt: skip

    def _parse_string_bytes(self, s: str) -> bytes:
        """Bytes of a string literal, with GNU as escapes (\\n, \\x41, \\101, ...)."""
        s = s.strip()
        if len(s) < 2 or s[0] != '"' or s[-1] != '"':
            raise ExpressionError(f"expected a quoted string, got {s}")
        body = s[1:-1]
        out = bytearray()
        i = 0
        while i < len(body):
            ch = body[i]
            if ch != "\\" or i + 1 >= len(body):
                out += ch.encode("utf-8")
                i += 1
                continue
            nxt = body[i + 1]
            if nxt in "01234567":
                # Up to three octal digits
                j = i + 1
                while j < len(body) and j < i + 4 and body[j] in "01234567":
                    j += 1
                out.append(int(body[i + 1 : j], 8) & 0xFF)
                i = j
            elif nxt in "xX":
                j = i + 2
                while j < len(body) and body[j] in "0123456789abcdefABCDEF":
                    j += 1
                if j == i + 2:
                    raise ExpressionError("\\x used with no following hex digits")
                out.append(int(body[i + 2 : j], 16) & 0xFF)
                i = j
            else:
                out.append(self._STRING_ESCAPES.get(nxt, ord(nxt) & 0xFF))
                i += 2
        return bytes(out)

    def _parse_string(self, s: str) -> str:
        """Parse a string literal (as text, for compatibility)."""
        return self._parse_string_bytes(s).decode("latin-1")

    def get_instructions(self, section_name: str) -> List[Tuple[int, str, Optional[str]]]:
        """
        Get instruction lines from a section.

        Returns:
            List of (line_number, instruction_text, label_or_none)
        """
        if section_name not in self.sections:
            return []

        section = self.sections[section_name]
        instructions = []

        for line in section.lines:
            if line.line_type == LineType.INSTRUCTION and line.instruction:
                instructions.append((line.line_number, line.instruction, line.label))

        return instructions
