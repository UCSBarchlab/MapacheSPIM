"""
Assembly directive parser for MapacheSPIM toolchain.

Parses GNU-as compatible assembly directives and organizes source
into sections for assembly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Union


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
    LABEL_PATTERN = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_]*):(.*)$')
    DIRECTIVE_PATTERN = re.compile(r'^\s*\.(\w+)\s*(.*)$')
    # Hash comment: # at start, or # preceded by space and NOT followed by digit/minus (ARM immediate)
    # This handles both #42 and #-32 as ARM immediates, not comments
    HASH_COMMENT = re.compile(r'(^|\s)#(?!-?\d).*$')
    COMMENT_PATTERNS = [
        re.compile(r'//.*$'),  # C++ style
        re.compile(r';.*$'),   # Semicolon comments
    ]

    # Valid ISA values for .isa directive
    VALID_ISAS = {"riscv64", "arm64", "x86_64", "mips32"}

    def __init__(self) -> None:
        self.sections: Dict[str, SectionData] = {}
        self.current_section: str = ".text"
        self.global_symbols: set = set()
        self.local_symbols: set = set()
        self.constants: Dict[str, int] = {}
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.isa: Optional[str] = None  # ISA from .isa directive

        # Initialize default sections
        for name in [".text", ".data", ".rodata", ".bss"]:
            self.sections[name] = SectionData(name=name)

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
                    section = self.sections[self.current_section]
                    section.lines.append(parsed)

                    # Handle labels
                    if parsed.label:
                        if parsed.label in self.constants:
                            section.labels[parsed.label] = self.constants[parsed.label]
                        else:
                            section.labels[parsed.label] = section.current_offset

                    # Process directive data
                    if parsed.directive:
                        self._process_directive(parsed, section)

            except Exception as e:
                self.errors.append(f"Line {line_num}: {e}")

        return self.sections

    def _parse_line(self, line_num: int, line: str) -> ParsedLine:
        """Parse a single line of assembly."""
        original = line

        # Strip hash comments (# at start or after space, but not ARM immediates like #42)
        line = self.HASH_COMMENT.sub(r'\1', line)
        # Strip other comment styles
        for pattern in self.COMMENT_PATTERNS:
            line = pattern.sub('', line)

        line = line.strip()

        # Empty line
        if not line:
            return ParsedLine(line_num, LineType.EMPTY, original)

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
                line_num, LineType.DIRECTIVE, original,
                label=label, directive=directive, directive_args=args
            )

        # Must be an instruction
        return ParsedLine(
            line_num, LineType.INSTRUCTION, original,
            label=label, instruction=line
        )

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
            elif char in '"\'':
                in_string = True
                string_char = char
                current += char
            elif char == ',':
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
                if not sect_name.startswith('.'):
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

        # Constants
        if directive in ("equ", "set"):
            if len(args) >= 2:
                name = args[0]
                try:
                    value = self._evaluate_expr(args[1])
                    self.constants[name] = value
                except Exception:
                    pass
            return

        # Data directives - these add bytes to current section
        if directive == "byte":
            for arg in args:
                try:
                    value = self._evaluate_expr(arg)
                    section.data.append(value & 0xFF)
                    section.current_offset += 1
                except Exception:
                    section.data.append(0)
                    section.current_offset += 1
            return

        if directive in ("half", "short", "2byte"):
            for arg in args:
                try:
                    value = self._evaluate_expr(arg)
                    section.data.extend((value & 0xFFFF).to_bytes(2, 'little'))
                    section.current_offset += 2
                except Exception:
                    section.data.extend(b'\x00\x00')
                    section.current_offset += 2
            return

        if directive in ("word", "long", "4byte"):
            for arg in args:
                try:
                    value = self._evaluate_expr(arg)
                    section.data.extend((value & 0xFFFFFFFF).to_bytes(4, 'little'))
                    section.current_offset += 4
                except Exception:
                    section.data.extend(b'\x00\x00\x00\x00')
                    section.current_offset += 4
            return

        if directive in ("dword", "quad", "8byte"):
            for arg in args:
                try:
                    value = self._evaluate_expr(arg)
                    section.data.extend(value.to_bytes(8, 'little'))
                    section.current_offset += 8
                except Exception:
                    section.data.extend(b'\x00' * 8)
                    section.current_offset += 8
            return

        # String directives
        if directive == "ascii":
            for arg in args:
                s = self._parse_string(arg)
                section.data.extend(s.encode('utf-8'))
                section.current_offset += len(s)
            return

        if directive in ("asciz", "string"):
            for arg in args:
                s = self._parse_string(arg)
                section.data.extend(s.encode('utf-8'))
                section.data.append(0)  # Null terminator
                section.current_offset += len(s) + 1
            return

        # Alignment
        if directive == "align":
            if args:
                try:
                    # .align n aligns to 2^n bytes on some platforms
                    # or to n bytes on others. We use n bytes.
                    alignment = self._evaluate_expr(args[0])
                    if alignment > 0:
                        padding = (alignment - (section.current_offset % alignment)) % alignment
                        section.data.extend(b'\x00' * padding)
                        section.current_offset += padding
                except Exception:
                    pass
            return

        if directive == "balign":
            if args:
                try:
                    alignment = self._evaluate_expr(args[0])
                    if alignment > 0:
                        padding = (alignment - (section.current_offset % alignment)) % alignment
                        section.data.extend(b'\x00' * padding)
                        section.current_offset += padding
                except Exception:
                    pass
            return

        if directive == "p2align":
            if args:
                try:
                    power = self._evaluate_expr(args[0])
                    alignment = 1 << power
                    padding = (alignment - (section.current_offset % alignment)) % alignment
                    section.data.extend(b'\x00' * padding)
                    section.current_offset += padding
                except Exception:
                    pass
            return

        # Space/skip
        if directive in ("space", "skip", "zero"):
            if args:
                try:
                    size = self._evaluate_expr(args[0])
                    fill = 0
                    if len(args) > 1:
                        fill = self._evaluate_expr(args[1]) & 0xFF
                    section.data.extend(bytes([fill] * size))
                    section.current_offset += size
                except Exception:
                    pass
            return

        # Architecture hints (ignored, but don't warn)
        if directive in ("arch", "option", "attribute", "file", "ident", "size", "type"):
            return

        # Unknown directive
        self.warnings.append(f"Line {parsed.line_number}: Unknown directive .{directive}")

    def _evaluate_expr(self, expr: str) -> int:
        """Evaluate a simple expression."""
        expr = expr.strip()

        # Check for known constant
        if expr in self.constants:
            return self.constants[expr]

        # Hex
        if expr.startswith('0x') or expr.startswith('0X'):
            return int(expr, 16)

        # Binary
        if expr.startswith('0b') or expr.startswith('0B'):
            return int(expr, 2)

        # Octal
        if expr.startswith('0') and len(expr) > 1 and expr[1:].isdigit():
            return int(expr, 8)

        # Character literal
        if expr.startswith("'") and expr.endswith("'"):
            return ord(self._parse_string(expr))

        # Decimal
        try:
            return int(expr)
        except ValueError:
            pass

        # Simple arithmetic
        for op in ['+', '-', '*', '/', '<<', '>>', '|', '&', '^']:
            if op in expr:
                parts = expr.rsplit(op, 1)
                if len(parts) == 2:
                    left = self._evaluate_expr(parts[0])
                    right = self._evaluate_expr(parts[1])
                    if op == '+':
                        return left + right
                    if op == '-':
                        return left - right
                    if op == '*':
                        return left * right
                    if op == '/':
                        return left // right if right else 0
                    if op == '<<':
                        return left << right
                    if op == '>>':
                        return left >> right
                    if op == '|':
                        return left | right
                    if op == '&':
                        return left & right
                    if op == '^':
                        return left ^ right

        raise ValueError(f"Cannot evaluate: {expr}")

    def _parse_string(self, s: str) -> str:
        """Parse a string literal with escape sequences."""
        if not s:
            return ""

        # Remove quotes
        if (s.startswith('"') and s.endswith('"')) or \
           (s.startswith("'") and s.endswith("'")):
            s = s[1:-1]

        # Process escape sequences
        result = []
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                next_char = s[i + 1]
                if next_char == 'n':
                    result.append('\n')
                elif next_char == 't':
                    result.append('\t')
                elif next_char == 'r':
                    result.append('\r')
                elif next_char == '0':
                    result.append('\0')
                elif next_char == '\\':
                    result.append('\\')
                elif next_char == '"':
                    result.append('"')
                elif next_char == "'":
                    result.append("'")
                elif next_char == 'x' and i + 3 < len(s):
                    try:
                        value = int(s[i+2:i+4], 16)
                        result.append(chr(value))
                        i += 2
                    except ValueError:
                        result.append(next_char)
                else:
                    result.append(next_char)
                i += 2
            else:
                result.append(s[i])
                i += 1

        return ''.join(result)

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
