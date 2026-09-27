"""
Multi-architecture assembler with built-in, GNU as compatible encoders.

Assembles source code into machine code for RISC-V, ARM64, x86-64, and MIPS32.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Mapping, Optional, Tuple

from ..isa import get_spec
from .directives import (
    ALIGN_DIRECTIVES,
    INTERNAL_LABEL_PREFIXES,
    DirectiveParser,
    LineType,
    ParsedLine,
    SectionData,
    emits_data,
)
from .dwarf import DWARFv2Builder
from .elf_builder import STB_GLOBAL, STB_LOCAL, STT_FUNC, STT_NOTYPE, ELFBuilder, Section, Symbol
from .expr import EncodeError, ExpressionError, UndefinedSymbol, evaluate
from .targets import Target, target_for


def _lookup(values: Dict[str, int]) -> Callable[[str], int]:
    """Symbol resolver over a dict, raising UndefinedSymbol for unknown names."""

    def resolve(name: str) -> int:
        if name in values:
            return values[name]
        raise UndefinedSymbol(name)

    return resolve


class _RelaxView(Mapping[str, int]):
    """
    Label lookup during one x86 relaxation pass, the way GNU as sees it:
    labels already passed have their new address, labels ahead have their
    old address shifted by the growth so far (``stretch``).
    """

    def __init__(
        self,
        data_labels: Dict[str, int],
        old: Dict[str, int],
        new: Dict[str, int],
        stretch: int,
    ) -> None:
        self.data_labels, self.old, self.new, self.stretch = data_labels, old, new, stretch

    def __contains__(self, name: object) -> bool:
        return name in self.new or name in self.old or name in self.data_labels

    def __iter__(self) -> Iterator[str]:
        return iter({**self.data_labels, **self.old, **self.new})

    def __len__(self) -> int:
        return len({**self.data_labels, **self.old, **self.new})

    def __getitem__(self, name: str) -> int:
        if name in self.new:
            return self.new[name]
        if name in self.old:
            return self.old[name] + self.stretch
        return self.data_labels[name]


@dataclass
class AssemblyResult:
    """Result of assembly operation."""

    elf_bytes: bytes = b""
    """Generated ELF file."""

    symbols: Dict[str, int] = field(default_factory=dict)
    """Symbol table (name -> address)."""

    errors: List[str] = field(default_factory=list)
    """Assembly errors."""

    warnings: List[str] = field(default_factory=list)
    """Assembly warnings."""

    isa: str = ""
    """Target ISA."""

    entry_point: int = 0
    """Entry point address."""

    debug_lines: List[Tuple[int, int]] = field(default_factory=list)
    """Debug line info: list of (address, source_line_number)."""

    source_filename: str = ""
    """Source filename for debug info."""

    @property
    def success(self) -> bool:
        return len(self.errors) == 0 and len(self.elf_bytes) > 0


class Assembler:
    """
    Multi-architecture assembler.

    Each ISA has a pure-Python encoder (riscv.py, mips.py, arm64.py,
    x86.py) that produces the same bytes as GNU as, driven through a
    :class:`~mapachespim.toolchain.targets.Target`, plus a shared directive
    parser for GNU-as compatible source files. This class is the
    ISA-independent part: layout, label resolution, and ELF output.

    Example:
        >>> asm = Assembler("riscv64")
        >>> result = asm.assemble('''
        ... .text
        ... .globl _start
        ... _start:
        ...     li a0, 42
        ...     li a7, 93
        ...     ecall
        ... ''')
        >>> print(result.success)
        True
    """

    def __init__(self, isa: str):
        """
        Initialize assembler for a specific ISA.

        Args:
            isa: Target ISA (riscv64, arm64, x86_64, mips32)

        Raises:
            ValueError: If ISA is not supported.
        """
        self.spec = get_spec(isa)
        self.isa = self.spec.name
        self._layout = self.spec.layout
        # Replaced for each assemble() call; also used by the layout passes
        self._parser = DirectiveParser(isa=self.isa)
        self._target: Target = target_for(self.isa, self._parser)

    @staticmethod
    def _resolve_constants(
        pending: Dict[str, Tuple[str, int]],
        constants: Dict[str, int],
        labels: Dict[str, int],
    ) -> bool:
        """Evaluate pending constants whose symbols are now known.

        Resolved entries move from ``pending`` to ``constants``. Returns True
        if any were resolved.
        """
        resolved_any = False
        progress = True
        while progress and pending:
            progress = False
            for name, (expression, _line) in list(pending.items()):
                try:
                    constants[name] = evaluate(expression, _lookup({**constants, **labels}))
                except ExpressionError:
                    continue  # still waiting for a symbol (errors reported later)
                del pending[name]
                progress = resolved_any = True
        return resolved_any

    def _text_directive_bytes(
        self, line: ParsedLine, addr: int, base: int, labels: Dict[str, int], strict: bool
    ) -> bytes:
        """Bytes a data or alignment directive in .text produces at ``addr``.

        Alignment padding in code is made of nop instructions, as GNU as
        does.
        """
        values = {**labels, ".": addr}

        def resolve(name: str) -> int:
            if name in values:
                return values[name]
            if strict:
                raise UndefinedSymbol(name)
            return 0

        data = self._parser.data_bytes(
            line.directive or "", line.directive_args, resolve, offset=addr - base
        )
        if data is None:
            return b""
        is_align = line.directive in ALIGN_DIRECTIVES
        args = line.directive_args
        explicit_fill = len(args) > 1 and bool(args[1])
        if explicit_fill:
            explicit_fill = self._target.is_explicit_fill(evaluate(args[1], resolve))
        if not is_align or explicit_fill or not data:
            return data
        return self._target.code_padding(len(data), line)

    def _is_real_alignment(self, line: ParsedLine, labels: Dict[str, int]) -> bool:
        """Whether ``line`` aligns to more than 1 byte (even if it inserts
        no padding), which GNU as treats like code."""
        if line.line_type != LineType.DIRECTIVE or line.directive not in ALIGN_DIRECTIVES:
            return False
        try:
            value = evaluate(line.directive_args[0], _lookup(labels))
        except (ExpressionError, IndexError):
            return False
        return self._parser.alignment(line.directive or "", value) > 1

    def assemble(
        self,
        source: str,
        entry_symbol: str = "_start",
        debug: bool = False,
        source_filename: str = "",
    ) -> AssemblyResult:
        """
        Assemble source code into an ELF executable.

        Args:
            source: Assembly source code.
            entry_symbol: Entry point symbol name.
            debug: If True, generate DWARF debug information.
            source_filename: Source filename for debug info.

        Returns:
            AssemblyResult with ELF bytes and metadata.
        """
        result = AssemblyResult(isa=self.isa, source_filename=source_filename)

        # Parse source
        parser = DirectiveParser(isa=self.isa)
        self._parser = parser
        self._target = target_for(self.isa, parser)
        sections = parser.parse(source)
        try:
            self._target.prepare(sections)
        except EncodeError as e:
            result.errors.append(str(e))

        result.errors.extend(parser.errors)
        result.warnings.extend(parser.warnings)

        if result.errors:
            return result

        # Section base addresses
        section_bases = {
            ".text": self._layout.text_base,
            ".data": self._layout.data_base,
            ".rodata": self._layout.rodata_base,
            ".bss": self._layout.bss_base,
        }

        # Two-pass assembly for forward reference resolution
        #
        # Pass 1: Calculate label addresses without assembling
        # - For .text: count instructions to determine positions
        # - For other sections: use offsets from directive parsing
        all_labels: Dict[str, int] = {}

        # Calculate base addresses for non-standard sections
        # Place them after .bss
        next_custom_base = self._layout.bss_base + 0x10000  # 64KB after .bss

        # Collect labels from ALL sections (not just standard ones)
        for sect_name, sect_data in sections.items():
            if sect_name == ".text":
                continue  # Handle .text separately below

            # Get base address for this section
            if sect_name in section_bases:
                base = section_bases[sect_name]
            else:
                # Custom section - assign address and update for next
                section_bases[sect_name] = next_custom_base
                base = next_custom_base
                next_custom_base += max(len(sect_data.data), 0x1000)  # At least 4KB

            for label_name, offset in sect_data.labels.items():
                all_labels[label_name] = base + offset

        # .equ/.set constants can be used as instruction operands but are
        # not addresses, so they are kept out of the ELF symbol table.
        # Constants that refer to labels (e.g. "len = . - msg") are resolved
        # as soon as the labels they use have addresses.
        constants = dict(parser.constants)
        pending = dict(parser.deferred_constants)
        self._resolve_constants(pending, constants, all_labels)

        # Calculate .text section label positions, using the data labels and
        # constants for pseudo-instruction sizing
        text_section = sections.get(".text")
        if text_section:
            text_labels = self._calculate_text_labels(
                text_section, self._layout.text_base, {**constants, **all_labels}
            )
            all_labels.update(text_labels)
            if pending and self._resolve_constants(pending, constants, all_labels):
                # Constants that needed code labels may change code size
                text_labels = self._calculate_text_labels(
                    text_section, self._layout.text_base, {**constants, **all_labels}
                )
                all_labels.update(text_labels)
        for name, (expression, line_number) in pending.items():
            try:
                evaluate(expression, _lookup({**constants, **all_labels}))
            except ExpressionError as e:
                result.errors.append(f"Line {line_number}: {name}: {e}")

        # Pass 2: Assemble .text section with all labels known
        debug_lines: List[Tuple[int, int]] = []
        if text_section:
            code, code_labels, asm_errors, section_debug_lines = self._assemble_section(
                text_section, self._layout.text_base, {**constants, **all_labels}
            )
            result.errors.extend(asm_errors)
            debug_lines = section_debug_lines

            # Update labels with actual positions (may differ slightly for x86-64)
            for name, addr in code_labels.items():
                all_labels[name] = addr

            if not result.errors:
                text_section.data = bytearray(code)

        # Fill in data values that refer to labels (e.g. ".word array")
        symbol_values = {**constants, **all_labels}
        for sect_name, sect_data in sections.items():
            if sect_name == ".text":
                continue
            for fixup in sect_data.fixups:
                try:
                    value = evaluate(fixup.expression, _lookup(symbol_values))
                except ExpressionError as e:
                    result.errors.append(f"Line {fixup.line_number}: {e}")
                    continue
                mask = (1 << (8 * fixup.size)) - 1
                sect_data.data[fixup.offset : fixup.offset + fixup.size] = (value & mask).to_bytes(
                    fixup.size, fixup.byteorder
                )

        if result.errors:
            return result

        # Internal labels (standing in for '.' or numeric labels) are not real symbols
        all_labels = {
            k: v for k, v in all_labels.items() if not k.startswith(INTERNAL_LABEL_PREFIXES)
        }

        # Build ELF
        entry_addr = all_labels.get(entry_symbol, self._layout.text_base)
        result.entry_point = entry_addr

        builder = ELFBuilder(self.isa, entry=entry_addr)

        # Add sections (standard ones first, then any custom sections)
        ordered = [n for n in (".text", ".data", ".rodata", ".bss") if n in sections]
        ordered += [n for n in sections if n not in ordered]
        section_index: Dict[str, int] = {}  # ELF section header index
        for sect_name in ordered:
            sect_data = sections[sect_name]
            if sect_data.data or sect_name == ".text":
                base = section_bases.get(sect_name, self._layout.text_base)
                builder.add_section(
                    Section(name=sect_name, data=bytes(sect_data.data), address=base)
                )
                section_index[sect_name] = len(builder.sections)

        # Add symbols, each in the section that defines it
        for name, addr in all_labels.items():
            defined_in = next((n for n, d in sections.items() if name in d.labels), "")
            builder.add_symbol(
                Symbol(
                    name=name,
                    address=addr,
                    sym_type=STT_FUNC if name == entry_symbol else STT_NOTYPE,
                    binding=STB_GLOBAL if name in parser.global_symbols else STB_LOCAL,
                    section_index=section_index.get(defined_in, 0),
                )
            )

        result.symbols = all_labels
        result.debug_lines = debug_lines

        # Generate DWARF debug sections if requested
        if debug and debug_lines:
            # Calculate code range
            text_start = self._layout.text_base
            text_end = text_start + len(text_section.data) if text_section else text_start

            # Determine address size and instruction length
            addr_size = 8 if self._layout.is_64bit else 4
            min_instr_len = self.spec.min_instruction_size

            # Build DWARF sections
            dwarf = DWARFv2Builder(
                addr_size=addr_size, big_endian=not self._layout.is_little_endian
            )
            abbrev = dwarf.build_debug_abbrev()
            info = dwarf.build_debug_info(source_filename or "source.s", text_start, text_end)
            line = dwarf.build_debug_line(source_filename or "source.s", debug_lines, min_instr_len)

            builder.add_debug_sections(abbrev, info, line)

        result.elf_bytes = builder.build()

        return result

    def _calculate_text_labels(
        self,
        section: SectionData,
        base_addr: int,
        data_labels: Optional[Dict[str, int]] = None,
    ) -> Dict[str, int]:
        """
        Calculate label addresses in .text section.

        Pass 1 of two-pass assembly: determine where each label will be
        based on instruction count.

        Sizes come from the encoder itself, so pseudo-instructions and
        x86-64's variable-length jumps are laid out exactly as encoded.

        Args:
            section: The text section to process.
            base_addr: Base address for the section.
            data_labels: Optional dict of data section labels for pseudo-instruction sizing.

        Returns:
            Dictionary of label name -> address.
        """
        return self._calculate_builtin_text_labels(section, base_addr, data_labels or {})

    def _calculate_builtin_text_labels(
        self,
        section: SectionData,
        base_addr: int,
        data_labels: Dict[str, int],
    ) -> Dict[str, int]:
        """
        Calculate label addresses using the built-in encoder's own sizing.

        Only a few pseudo-instructions (li, la, constant operands) have
        value-dependent sizes, so this converges in a pass or two; the loop
        re-sizes with the labels found so far until they are stable.
        """
        labels: Dict[str, int] = {}
        for _ in range(100):
            known = {**data_labels, **labels}
            new_labels: Dict[str, int] = {}
            addr = base_addr
            grew = False
            stretch = 0  # growth so far this pass, as in GNU's relax_segment
            after_data = False  # see _instruction_padding
            for line in section.lines:
                if line.label:
                    new_labels[line.label] = addr
                    if line.label in labels:
                        stretch = addr - labels[line.label]
                if line.line_type == LineType.INSTRUCTION and line.instruction:
                    addr += self._target.padding_before_instruction(addr, after_data)
                    after_data = False
                    grown = self._target.can_relax and self._target.relax(
                        line, addr, _RelaxView(data_labels, labels, new_labels, stretch)
                    )
                    grew = grew or grown
                    size = self._target.size(line, addr, known)
                    if grown:
                        stretch += size - 2
                    addr += size
                elif line.line_type == LineType.DIRECTIVE:
                    try:
                        addr += len(
                            self._text_directive_bytes(line, addr, base_addr, known, strict=False)
                        )
                    except ExpressionError:
                        pass  # reported when the section is assembled
                    if emits_data(line):
                        after_data = True
                    elif self._is_real_alignment(line, known):
                        after_data = False
            if new_labels == labels and not grew:
                break
            labels = new_labels
        return labels

    def _assemble_section(
        self,
        section: SectionData,
        base_addr: int,
        labels: Dict[str, int],
    ) -> Tuple[bytes, Dict[str, int], List[str], List[Tuple[int, int]]]:
        """
        Assemble instructions in a section.

        Returns:
            (assembled_bytes, label_addresses, errors, debug_lines)
            where debug_lines is a list of (address, source_line_number) tuples.
        """
        code = bytearray()
        label_addrs: Dict[str, int] = {}
        errors: List[str] = []
        debug_lines: List[Tuple[int, int]] = []
        current_addr = base_addr
        after_data = False  # see _instruction_padding

        for line in section.lines:
            # Record label position
            if line.label:
                label_addrs[line.label] = current_addr

            # Data and alignment directives in code
            if line.line_type == LineType.DIRECTIVE:
                try:
                    data = self._text_directive_bytes(
                        line, current_addr, base_addr, labels, strict=True
                    )
                except ExpressionError as e:
                    errors.append(f"Line {line.line_number}: .{line.directive}: {e}")
                    continue
                code.extend(data)
                current_addr += len(data)
                if emits_data(line):
                    after_data = True
                elif self._is_real_alignment(line, labels):
                    after_data = False
                continue

            # Skip non-instructions
            if line.line_type != LineType.INSTRUCTION or not line.instruction:
                continue

            padding = self._target.padding_before_instruction(current_addr, after_data)
            after_data = False
            code.extend(bytes(padding))
            current_addr += padding

            # Record debug line info before assembling
            debug_lines.append((current_addr, line.line_number))

            try:
                encoding = self._target.encode(line, current_addr, labels)
            except EncodeError as e:
                errors.append(f"Line {line.line_number}: {e} - {line.instruction}")
                continue
            code.extend(encoding)
            current_addr += len(encoding)

        # Pass 1 must have predicted every label's address, or branch offsets
        # computed from those predictions would be wrong
        if not errors:
            for name, addr in label_addrs.items():
                if labels.get(name, addr) != addr:
                    errors.append(
                        f"Internal error: label '{name}' moved from 0x{labels[name]:x} "
                        f"to 0x{addr:x} between passes; please report this bug"
                    )

        return bytes(code), label_addrs, errors, debug_lines

    def assemble_instruction(self, instr: str, address: int = 0) -> bytes:
        """
        Assemble a single instruction.

        Args:
            instr: Instruction text (e.g., "addi x5, x0, 42")
            address: Address for PC-relative instructions.

        Returns:
            Assembled bytes.

        Raises:
            ValueError: If assembly fails.
        """
        try:
            return bytes(self._target.encoder.encode(instr, address, {}))
        except EncodeError as e:
            raise ValueError(f"Assembly error: {e}")
