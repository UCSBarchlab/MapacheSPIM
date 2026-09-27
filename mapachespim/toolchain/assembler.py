"""
Multi-architecture assembler with built-in, GNU as compatible encoders.

Assembles source code into machine code for RISC-V, ARM64, x86-64, and MIPS32.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Set, Tuple

from . import arm64, mips, riscv, x86
from .directives import (
    ALIGN_DIRECTIVES,
    BYTE_DIRECTIVES,
    DATA_SIZES,
    INTERNAL_LABEL_PREFIXES,
    POOL_LABEL_PREFIX,
    DirectiveParser,
    LineType,
    ParsedLine,
    SectionData,
)
from .dwarf import DWARFv2Builder
from .elf_builder import STB_GLOBAL, STB_LOCAL, STT_FUNC, STT_NOTYPE, ELFBuilder, Section, Symbol
from .expr import EncodeError, ExpressionError, UndefinedSymbol, evaluate
from .memory_map import get_layout


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
    x86.py) that produces the same bytes as GNU as, plus a shared directive
    parser for GNU-as compatible source files.

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

    # ISA configuration mapping
    ISA_CONFIG: Dict[str, Dict[str, Any]] = {
        "riscv64": {
            "instr_size": 4,
        },
        "riscv": {
            "instr_size": 4,
        },
        "arm64": {
            "instr_size": 4,
        },
        "aarch64": {
            "instr_size": 4,
        },
        "x86_64": {
            "instr_size": None,  # Variable length
        },
        "x86-64": {
            "instr_size": None,
        },
        "x64": {
            "instr_size": None,
        },
        "mips32": {
            "instr_size": 4,
        },
        "mips": {
            "instr_size": 4,
        },
    }

    def __init__(self, isa: str):
        """
        Initialize assembler for a specific ISA.

        Args:
            isa: Target ISA (riscv64, arm64, x86_64, mips32)

        Raises:
            ValueError: If ISA is not supported.
        """
        isa_lower = isa.lower().replace("-", "_")
        if isa_lower not in self.ISA_CONFIG:
            valid = sorted(set(k for k in self.ISA_CONFIG.keys() if "_" not in k))
            raise ValueError(f"Unknown ISA: {isa!r}. Valid: {', '.join(valid)}")

        self.isa = isa_lower
        self._config = self.ISA_CONFIG[isa_lower]
        self._layout = get_layout(isa_lower)
        # Replaced for each assemble() call; also used by the layout passes
        self._parser = DirectiveParser(isa=isa_lower)
        self._long_jumps: Set[int] = set()  # x86 jumps that need rel32
        self._align_after_data: Set[int] = set()  # x86 code alignment after data
        self._absolute_symbols: Set[str] = set()  # names of .equ constants

    @staticmethod
    def _add_literal_pools(section: SectionData) -> None:
        """Turn ARM64 'ldr x0, =value' into loads from a literal pool.

        As in GNU as, each load reads a pool entry placed at the next
        .ltorg/.pool directive or at the end of the section. Within a pool,
        equal values share one entry; 4-byte entries come first, then 8-byte
        entries, each group aligned to its size.
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

    @staticmethod
    def _alignments_after_data(section: Optional[SectionData]) -> Set[int]:
        """Alignment directives in code whose last preceding item is data.

        GNU as pads x86 code with a one-byte nop first in that case, since
        the data might be an incomplete instruction.
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
                elif Assembler._emits_data(line):
                    after_data = True
        return found

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
        if self._builtin_encoder is x86 and explicit_fill:
            # GNU as treats a fill of 0x90 (nop) like no fill: best nops
            explicit_fill = evaluate(args[1], resolve) & 0xFF != 0x90
        if not is_align or explicit_fill or not data:
            return data
        # Pad code with nops, as GNU as does (MIPS's nop is all zeros)
        if self._is_riscv:
            # As GNU as's riscv_make_nops: a zero byte if odd, at most one
            # 2-byte c.nop, then 4-byte nops
            head = bytes(len(data) % 2) + (b"\x01\x00" if len(data) % 4 >= 2 else b"")
            data = head + (0x00000013).to_bytes(4, "little") * (len(data) // 4)
        elif self._builtin_encoder is arm64:
            misaligned = len(data) % 4
            data = bytes(misaligned) + (0xD503201F).to_bytes(4, "little") * (len(data) // 4)
        elif self._builtin_encoder is x86:
            data = x86.nop_padding(len(data), id(line) in self._align_after_data)
        return data

    def _line_options(self, line: ParsedLine) -> Dict[str, Any]:
        """Per-line encoder options (MIPS: .set reorder / noreorder; x86-64:
        syntax, which symbols are constants, and jump size)."""
        if self.isa in ("mips32", "mips"):
            return {"reorder": line.reorder}
        if self._builtin_encoder is x86:
            return {
                "syntax": line.syntax,
                "absolute_symbols": self._absolute_symbols,
                "long_jump": id(line) in self._long_jumps,
            }
        return {}

    def _instruction_padding(self, addr: int, after_data: bool) -> int:
        """Zero bytes GNU as puts before an instruction at ``addr``.

        ARM64 aligns an instruction to 4 bytes when it directly follows data
        (GNU as does this when switching from data to code; an alignment
        directive in between counts as code).
        """
        return -addr % 4 if after_data and self._builtin_encoder is arm64 else 0

    @staticmethod
    def _emits_data(line: ParsedLine) -> bool:
        """Whether ``line`` is a data directive such as .byte or .fill."""
        directive = line.directive or ""
        return line.line_type == LineType.DIRECTIVE and (
            directive in DATA_SIZES or directive in BYTE_DIRECTIVES or directive == "value"
        )

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

    @property
    def _is_riscv(self) -> bool:
        return self.isa in ("riscv64", "riscv")

    @property
    def _builtin_encoder(self) -> ModuleType:
        """The pure-Python encoder module for this ISA."""
        if self._is_riscv:
            return riscv
        if self.isa in ("mips32", "mips"):
            return mips
        if self.isa in ("arm64", "aarch64"):
            return arm64
        return x86

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
        self._long_jumps = set()
        sections = parser.parse(source)
        self._absolute_symbols = set(parser.constants) | set(parser.deferred_constants)
        self._align_after_data = self._alignments_after_data(sections.get(".text"))
        if self.isa in ("arm64", "aarch64") and ".text" in sections:
            try:
                self._add_literal_pools(sections[".text"])
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
        for sect_name in ordered:
            if sect_name in sections:
                sect_data = sections[sect_name]
                if sect_data.data or sect_name == ".text":
                    base = section_bases.get(sect_name, self._layout.text_base)
                    builder.add_section(
                        Section(
                            name=sect_name,
                            data=bytes(sect_data.data),
                            address=base,
                        )
                    )

        # Add symbols
        for name, addr in all_labels.items():
            is_global = name in parser.global_symbols
            # Determine section index (simplified)
            section_idx = 1  # Assume .text is section 1
            for i, (sn, _) in enumerate(sections.items()):
                if sn == ".text":
                    section_idx = i + 1
                    break

            builder.add_symbol(
                Symbol(
                    name=name,
                    address=addr,
                    sym_type=STT_FUNC if name == entry_symbol else STT_NOTYPE,
                    binding=STB_GLOBAL if is_global else STB_LOCAL,
                    section_index=section_idx,
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
            min_instr_len = self._config.get("instr_size") or 1

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
                    addr += self._instruction_padding(addr, after_data)
                    after_data = False
                    # x86 jumps start short (rel8) and grow to rel32 once, for
                    # good, when the target is out of range (GNU's relaxation)
                    if (
                        self._builtin_encoder is x86
                        and id(line) not in self._long_jumps
                        and x86.is_relaxable(line.instruction)
                        and not x86.short_jump_fits(
                            line.instruction,
                            addr,
                            _RelaxView(data_labels, labels, new_labels, stretch),
                        )
                    ):
                        self._long_jumps.add(id(line))
                        grew = True
                        grown = True
                    else:
                        grown = False
                    size = self._builtin_encoder.instruction_size(
                        line.instruction, known, addr, **self._line_options(line)
                    )
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
                    if self._emits_data(line):
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
                if self._emits_data(line):
                    after_data = True
                elif self._is_real_alignment(line, labels):
                    after_data = False
                continue

            # Skip non-instructions
            if line.line_type != LineType.INSTRUCTION or not line.instruction:
                continue

            padding = self._instruction_padding(current_addr, after_data)
            after_data = False
            code.extend(bytes(padding))
            current_addr += padding

            # Record debug line info before assembling
            debug_lines.append((current_addr, line.line_number))

            instr = line.instruction

            try:
                encoding = self._builtin_encoder.encode(
                    instr, current_addr, labels, **self._line_options(line)
                )
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
            return bytes(self._builtin_encoder.encode(instr, address, {}))
        except EncodeError as e:
            raise ValueError(f"Assembly error: {e}")
