"""
Multi-architecture assembler using Keystone Engine.

Assembles source code into machine code for RISC-V, ARM64, x86-64, and MIPS32.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import keystone

    # Verify keystone actually works by trying to access a constant
    _ = keystone.KS_ARCH_X86
    KEYSTONE_AVAILABLE = True
    KEYSTONE_ERROR = None
except ImportError:
    # Simply not installed; the message raised later explains how to add it
    KEYSTONE_AVAILABLE = False
    KEYSTONE_ERROR = None
    keystone = None
except Exception as e:
    # Keystone installed but native library failed to load
    KEYSTONE_AVAILABLE = False
    KEYSTONE_ERROR = f"Keystone native library failed: {e}"
    keystone = None

from . import arm64, mips, riscv
from .directives import (
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


# Keystone architecture/mode constants
KS_ARCH_X86 = 4

KS_MODE_LITTLE_ENDIAN = 0
KS_MODE_64 = 0x8
KS_MODE_32 = 0x4


class Assembler:
    """
    Multi-architecture assembler.

    Uses Keystone Engine for instruction encoding and a custom
    directive parser for GNU-as compatible source files.

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
        # RISC-V is encoded by the built-in pure-Python encoder (riscv.py)
        "riscv64": {
            "arch": None,
            "mode": None,
            "instr_size": 4,
        },
        "riscv": {
            "arch": None,
            "mode": None,
            "instr_size": 4,
        },
        # ARM64 is encoded by the built-in pure-Python encoder (arm64.py)
        "arm64": {
            "arch": None,
            "mode": None,
            "instr_size": 4,
        },
        "aarch64": {
            "arch": None,
            "mode": None,
            "instr_size": 4,
        },
        "x86_64": {
            "arch": KS_ARCH_X86,
            "mode": KS_MODE_64,
            "instr_size": None,  # Variable length
        },
        "x86-64": {
            "arch": KS_ARCH_X86,
            "mode": KS_MODE_64,
            "instr_size": None,
        },
        "x64": {
            "arch": KS_ARCH_X86,
            "mode": KS_MODE_64,
            "instr_size": None,
        },
        # MIPS is encoded by the built-in pure-Python encoder (mips.py)
        "mips32": {
            "arch": None,
            "mode": None,
            "instr_size": 4,
        },
        "mips": {
            "arch": None,
            "mode": None,
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
            ImportError: If Keystone is not available.
        """
        isa_lower = isa.lower().replace("-", "_")
        if isa_lower not in self.ISA_CONFIG:
            valid = sorted(set(k for k in self.ISA_CONFIG.keys() if "_" not in k))
            raise ValueError(f"Unknown ISA: {isa!r}. Valid: {', '.join(valid)}")

        self.isa = isa_lower
        self._config = self.ISA_CONFIG[isa_lower]
        self._layout = get_layout(isa_lower)
        self._ks = None
        # Replaced for each assemble() call; also used by the layout passes
        self._parser = DirectiveParser(isa=isa_lower)

        # RISC-V and MIPS use built-in encoders; ARM64 and x86-64 need Keystone
        if self._config["arch"] is None:
            return

        if not KEYSTONE_AVAILABLE:
            if KEYSTONE_ERROR:
                msg = f"Assembling {isa} requires the Keystone Engine, which failed to load:\n"
                msg += f"  {KEYSTONE_ERROR}\n"
            else:
                msg = f"Assembling {isa} requires the Keystone Engine, which is not installed.\n"
            msg += "Install it with:  pip install 'mapachespim[keystone]'\n"
            msg += "(RISC-V and MIPS programs can be assembled without it.)"
            raise ImportError(msg)

        try:
            self._ks = keystone.Ks(self._config["arch"], self._config["mode"])
        except keystone.KsError as e:
            raise RuntimeError(f"Failed to initialize Keystone for {isa}: {e}")

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
                        directive_args=[str(size)],
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

    def _text_directive_bytes(
        self, line: ParsedLine, addr: int, base: int, labels: Dict[str, int], strict: bool
    ) -> bytes:
        """Bytes a data or alignment directive in .text produces at ``addr``.

        Alignment padding in RISC-V code is made of nop instructions, as GNU
        as does (MIPS's nop is all zeros, the default fill).
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
        is_align = line.directive in ("align", "balign", "p2align")
        explicit_fill = len(line.directive_args) > 1 and line.directive_args[1]
        if is_align and not explicit_fill and data and len(data) % 4 == 0 and self._is_riscv:
            data = (0x00000013).to_bytes(4, "little") * (len(data) // 4)
        return data

    def _line_options(self, line: ParsedLine) -> Dict[str, Any]:
        """Per-line encoder options (MIPS: .set reorder / noreorder)."""
        if self.isa in ("mips32", "mips"):
            return {"reorder": line.reorder}
        return {}

    @property
    def _is_riscv(self) -> bool:
        return self.isa in ("riscv64", "riscv")

    @property
    def _builtin_encoder(self) -> Optional[ModuleType]:
        """The pure-Python encoder module for this ISA, or None for Keystone ISAs."""
        if self._is_riscv:
            return riscv
        if self.isa in ("mips32", "mips"):
            return mips
        if self.isa in ("arm64", "aarch64"):
            return arm64
        return None

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
        sections = parser.parse(source)
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

        For fixed-size ISAs (RISC-V, ARM64, MIPS): 4 bytes per instruction.
        For variable-size ISAs (x86-64): use iterative assembly until stable.

        Args:
            section: The text section to process.
            base_addr: Base address for the section.
            data_labels: Optional dict of data section labels for pseudo-instruction sizing.

        Returns:
            Dictionary of label name -> address.
        """
        from .directives import LineType

        instr_size = self._config.get("instr_size", 4)

        # Variable-length ISA (x86-64) needs iterative approach
        if instr_size is None:
            return self._calculate_x86_text_labels_iterative(section, base_addr)

        if self._builtin_encoder is not None:
            return self._calculate_builtin_text_labels(section, base_addr, data_labels or {})

        # Fixed-size ISA: single pass with size estimation
        labels: Dict[str, int] = {}
        current_addr = base_addr

        for line in section.lines:
            # Record label position
            if line.label:
                labels[line.label] = current_addr

            # Skip non-instructions
            if line.line_type != LineType.INSTRUCTION or not line.instruction:
                continue

            # Check for pseudo-instructions that expand to multiple instructions
            size = self._estimate_fixed_instr_size(line.instruction, instr_size, data_labels)
            current_addr += size

        return labels

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
        for _ in range(8):
            known = {**data_labels, **labels}
            new_labels: Dict[str, int] = {}
            addr = base_addr
            for line in section.lines:
                if line.label:
                    new_labels[line.label] = addr
                if line.line_type == LineType.INSTRUCTION and line.instruction:
                    addr += self._builtin_encoder.instruction_size(
                        line.instruction, known, addr, **self._line_options(line)
                    )
                elif line.line_type == LineType.DIRECTIVE:
                    try:
                        addr += len(
                            self._text_directive_bytes(line, addr, base_addr, known, strict=False)
                        )
                    except ExpressionError:
                        pass  # reported when the section is assembled
            if new_labels == labels:
                break
            labels = new_labels
        return labels

    def _calculate_x86_text_labels_iterative(
        self,
        section: SectionData,
        base_addr: int,
        max_iterations: int = 5,
    ) -> Dict[str, int]:
        """
        Calculate x86-64 label addresses using iterative refinement.

        For variable-length instruction sets, instruction sizes can depend on
        label addresses (e.g., short vs near jumps). This method iterates
        until label addresses stabilize.

        Args:
            section: The text section to process.
            base_addr: Base address for the section.
            max_iterations: Maximum iterations before giving up.

        Returns:
            Dictionary of label name -> address.
        """
        from .directives import LineType

        labels: Dict[str, int] = {}

        for _ in range(max_iterations):
            new_labels: Dict[str, int] = {}
            current_addr = base_addr

            for line in section.lines:
                # Record label at current position
                if line.label:
                    new_labels[line.label] = current_addr

                # Skip non-instructions
                if line.line_type != LineType.INSTRUCTION or not line.instruction:
                    continue

                # Get actual instruction size by assembling
                size = self._get_x86_actual_size(line.instruction, current_addr, labels)
                current_addr += size

            # Check for convergence
            if new_labels == labels:
                return new_labels

            labels = new_labels

        # Return best effort if max iterations reached
        return labels

    def _get_x86_actual_size(
        self,
        instr: str,
        addr: int,
        labels: Dict[str, int],
    ) -> int:
        """
        Get actual x86-64 instruction size by assembling it.

        Args:
            instr: Instruction text (AT&T or Intel syntax).
            addr: Current address for PC-relative calculations.
            labels: Currently known label addresses.

        Returns:
            Instruction size in bytes.
        """
        # Convert to Intel syntax, resolving known labels
        converted = self._convert_x86_att_to_intel(instr, labels)

        # Try to assemble
        try:
            encoding, count = self._ks.asm(converted, addr)
            if encoding is not None and count > 0:
                return len(encoding)
        except keystone.KsError:
            pass

        # Assembly failed - likely unresolved forward reference
        # Try with a placeholder to get encoding size
        parts = converted.split(None, 1)
        mnemonic = parts[0].lower() if parts else ""

        # For branch/call instructions, use placeholder offset
        if mnemonic in (
            "jmp",
            "call",
            "je",
            "jne",
            "jz",
            "jnz",
            "jl",
            "jle",
            "jg",
            "jge",
            "ja",
            "jae",
            "jb",
            "jbe",
            "jo",
            "jno",
            "js",
            "jns",
            "jc",
            "jnc",
            "loop",
            "loope",
            "loopne",
        ):
            # Use a medium-range placeholder to get near (not short) encoding
            placeholder_addr = addr + 0x100
            placeholder_instr = f"{mnemonic} {placeholder_addr}"
            try:
                encoding, count = self._ks.asm(placeholder_instr, addr)
                if encoding is not None and count > 0:
                    return len(encoding)
            except keystone.KsError:
                pass

        # Final fallback: use existing estimation
        return self._estimate_x86_instr_size(instr)

    def _estimate_fixed_instr_size(
        self,
        instr: str,
        base_size: int,
        data_labels: Optional[Dict[str, int]] = None,
    ) -> int:
        """
        Estimate instruction size for fixed-size ISAs.

        Accounts for pseudo-instructions that expand to multiple instructions.

        Args:
            instr: The instruction text.
            base_size: Base instruction size (typically 4 bytes).
            data_labels: Optional dict of data section labels for address lookups.
        """
        parts = instr.split(None, 1)
        if not parts:
            return base_size

        mnemonic = parts[0].lower()

        if self._builtin_encoder is not None:
            return self._builtin_encoder.instruction_size(instr, data_labels or {})

        return base_size

    def _estimate_x86_instr_size(self, instr: str) -> int:
        """
        Estimate the size of an x86-64 instruction.

        This is a conservative estimate for pass 1.
        Pass 2 will use actual assembled sizes.
        """
        parts = instr.split(None, 1)
        if not parts:
            return 1

        mnemonic = parts[0].lower().rstrip("bwlq")
        operands = parts[1] if len(parts) > 1 else ""

        # Single/two-byte instructions
        if mnemonic == "nop":
            return 1
        if mnemonic == "ret":
            return 1
        if mnemonic in ("syscall", "hlt", "cld", "std", "cdqe", "cqo"):
            return 2

        # Near jumps/calls with label: 5 bytes (1 opcode + 4 offset)
        # But conditional jumps can be 2 bytes for short jumps, assume 6 for safety
        if mnemonic in ("jmp", "call"):
            return 5
        if mnemonic in (
            "je",
            "jne",
            "jz",
            "jnz",
            "jl",
            "jle",
            "jg",
            "jge",
            "ja",
            "jae",
            "jb",
            "jbe",
            "jo",
            "jno",
            "js",
            "jns",
            "jc",
            "jnc",
            "loop",
            "loope",
            "loopne",
        ):
            return 6  # 0F XX + 4-byte offset

        # RIP-relative addressing: 7 bytes
        # Format: symbol(%rip) or [rip + symbol]
        if "%rip" in operands or "rip" in operands.lower():
            # REX.W (1) + opcode (1-2) + ModR/M (1) + disp32 (4) = 7-8 bytes
            return 7

        # LEA with memory operand
        if mnemonic == "lea":
            if "%rip" in operands or "rip" in operands.lower():
                return 7
            return 4  # Base case

        # MOV with 64-bit immediate
        if mnemonic == "mov":
            # Check for 64-bit register destination with immediate
            if operands.startswith("$") or operands.startswith("%"):
                # AT&T: movq $imm, %reg or Intel mov reg, imm
                if any(
                    r in operands
                    for r in [
                        "%rax",
                        "%rbx",
                        "%rcx",
                        "%rdx",
                        "%rsi",
                        "%rdi",
                        "%rbp",
                        "%rsp",
                        "%r8",
                        "%r9",
                        "%r10",
                        "%r11",
                        "%r12",
                        "%r13",
                        "%r14",
                        "%r15",
                        "rax",
                        "rbx",
                        "rcx",
                        "rdx",
                    ]
                ):
                    # Could be 10 bytes for movabs
                    if "$" in operands:
                        return 10
                    return 7
            # Simple reg-reg or reg-mem: 2-4 bytes
            return 3

        # TEST, CMP with register: 2-3 bytes
        if mnemonic in ("test", "cmp"):
            if "(" not in operands and "[" not in operands:
                return 3

        # ADD, SUB, XOR, AND, OR with immediate or register: 3-7 bytes
        if mnemonic in ("add", "sub", "xor", "and", "or"):
            if "$" in operands or any(c.isdigit() for c in operands[:5]):
                return 7  # Could have 32-bit immediate
            return 3  # Register-register

        # Push/pop: 1-2 bytes
        if mnemonic in ("push", "pop"):
            return 2

        # Default for unknown instructions
        return 5

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

        for line in section.lines:
            # Record label position
            if line.label:
                label_addrs[line.label] = current_addr

            # Data and alignment directives in code (built-in encoders only)
            if line.line_type == LineType.DIRECTIVE and self._builtin_encoder is not None:
                try:
                    data = self._text_directive_bytes(
                        line, current_addr, base_addr, labels, strict=True
                    )
                except ExpressionError as e:
                    errors.append(f"Line {line.line_number}: .{line.directive}: {e}")
                    continue
                code.extend(data)
                current_addr += len(data)
                continue

            # Skip non-instructions
            if line.line_type != LineType.INSTRUCTION or not line.instruction:
                continue

            # Record debug line info before assembling
            debug_lines.append((current_addr, line.line_number))

            instr = line.instruction

            # RISC-V and MIPS: built-in encoders handle instructions and
            # pseudo-instructions directly
            encoder = self._builtin_encoder
            if encoder is not None:
                try:
                    encoding = encoder.encode(
                        instr, current_addr, labels, **self._line_options(line)
                    )
                except EncodeError as e:
                    errors.append(f"Line {line.line_number}: {e} - {line.instruction}")
                    continue
                code.extend(encoding)
                current_addr += len(encoding)
                continue

            # Convert AT&T to Intel syntax for x86-64
            if self.isa == "x86_64":
                instr = self._convert_x86_att_to_intel(instr, labels)

            # Assemble instruction
            try:
                encoding, count = self._ks.asm(instr, current_addr)
                if encoding is None or count == 0:
                    errors.append(
                        f"Line {line.line_number}: Failed to assemble: {line.instruction}"
                    )
                    continue

                code.extend(encoding)
                current_addr += len(encoding)

            except keystone.KsError as e:
                errors.append(f"Line {line.line_number}: {e} - {line.instruction}")

        # Pass 1 must have predicted every label's address, or branch offsets
        # computed from those predictions would be wrong
        if not errors and self.isa != "x86_64":
            for name, addr in label_addrs.items():
                if labels.get(name, addr) != addr:
                    errors.append(
                        f"Internal error: label '{name}' moved from 0x{labels[name]:x} "
                        f"to 0x{addr:x} between passes; please report this bug"
                    )

        return bytes(code), label_addrs, errors, debug_lines

    def _convert_x86_att_to_intel(
        self,
        instr: str,
        labels: Dict[str, int],
    ) -> str:
        """
        Convert x86 AT&T syntax to Intel syntax.

        Handles common patterns:
        - %reg -> reg (remove % prefix)
        - $imm -> imm (remove $ prefix)
        - op src, dst -> op dst, src (reverse operand order)
        - symbol(%rip) -> [rip + symbol] (RIP-relative addressing)
        """
        import re

        parts = instr.split(None, 1)
        if not parts:
            return instr

        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""

        # Check if already Intel syntax (no % or $)
        is_att_syntax = "%" in instr or "$" in instr

        # For Intel-syntax jump/call with symbol, resolve the symbol
        if not is_att_syntax:
            if mnemonic in (
                "jmp",
                "call",
                "je",
                "jne",
                "jz",
                "jnz",
                "jl",
                "jle",
                "jg",
                "jge",
                "ja",
                "jae",
                "jb",
                "jbe",
                "jo",
                "jno",
                "js",
                "jns",
                "jc",
                "jnc",
                "loop",
                "loope",
                "loopne",
            ):
                symbol = operands.strip()
                if symbol in labels:
                    return f"{mnemonic} {labels[symbol]}"
            return instr

        # Handle special AT&T mnemonics
        # movslq = move sign-extend long to quad (Intel: movsxd)
        if mnemonic == "movslq":
            mnemonic = "movsxd"
        # cltq = sign-extend eax to rax (Intel: cdqe)
        elif mnemonic == "cltq":
            return "cdqe"
        # cqto = sign-extend rax to rdx:rax (Intel: cqo)
        elif mnemonic == "cqto":
            return "cqo"

        # Remove size suffixes (b, w, l, q)
        if mnemonic.endswith(("b", "w", "l", "q")) and len(mnemonic) > 2:
            base = mnemonic[:-1]
            if base in (
                "mov",
                "add",
                "sub",
                "xor",
                "and",
                "or",
                "cmp",
                "test",
                "lea",
                "push",
                "pop",
                "call",
                "ret",
                "jmp",
                "dec",
                "inc",
                "neg",
                "not",
                "mul",
                "imul",
                "div",
                "idiv",
                "shl",
                "shr",
                "sar",
                "sal",
                "rol",
                "ror",
                "rcl",
                "rcr",
            ):
                mnemonic = base

        # Handle no-operand instructions
        if not operands:
            return mnemonic

        # Split operands
        op_list = []
        depth = 0
        current = ""
        for c in operands:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "," and depth == 0:
                op_list.append(current.strip())
                current = ""
                continue
            current += c
        if current.strip():
            op_list.append(current.strip())

        # Convert each operand
        converted = []
        for op in op_list:
            op = op.strip()

            # Handle RIP-relative: symbol(%rip) -> [rip + address]
            rip_match = re.match(r"(\w+)\s*\(\s*%rip\s*\)", op)
            if rip_match:
                symbol = rip_match.group(1)
                if symbol in labels:
                    addr = labels[symbol]
                    converted.append(f"[0x{addr:x}]")
                else:
                    # Symbol not found, use placeholder
                    converted.append(f"[rip + {symbol}]")
                continue

            # Handle memory operands with index and scale: offset(base, index, scale)
            # AT&T: (%r12, %rax, 4) -> Intel: [r12 + rax*4]
            # AT&T: 16(%rsp, %rax, 8) -> Intel: [rsp + rax*8 + 16]
            sib_match = re.match(r"(-?\d+)?\s*\(\s*%(\w+)\s*,\s*%(\w+)\s*,\s*(\d+)\s*\)", op)
            if sib_match:
                offset = sib_match.group(1)
                base = sib_match.group(2)
                index = sib_match.group(3)
                scale = sib_match.group(4)
                intel_op = f"[{base} + {index}*{scale}"
                if offset:
                    intel_op += f" + {offset}"
                intel_op += "]"
                converted.append(intel_op)
                continue

            # Handle memory operands: (%reg) -> [reg], offset(%reg) -> [reg + offset]
            mem_match = re.match(r"(-?\d+)?\s*\(\s*%(\w+)\s*\)", op)
            if mem_match:
                offset = mem_match.group(1)
                reg = mem_match.group(2)
                if offset:
                    converted.append(f"[{reg} + {offset}]")
                else:
                    converted.append(f"[{reg}]")
                continue

            # Handle immediate: $value -> value
            if op.startswith("$"):
                value = op[1:]
                # Check if it's a symbol
                if value in labels:
                    converted.append(str(labels[value]))
                else:
                    converted.append(value)
                continue

            # Handle register: %reg -> reg
            if op.startswith("%"):
                converted.append(op[1:])
                continue

            # Check if it's a bare symbol (for jump/call targets)
            if op in labels:
                converted.append(str(labels[op]))
                continue

            # Pass through as-is
            converted.append(op)

        # Reverse operand order for two-operand instructions (AT&T: src, dst -> Intel: dst, src)
        if len(converted) == 2 and mnemonic not in ("push", "pop", "call", "jmp", "syscall"):
            converted = converted[::-1]

        return f"{mnemonic} {', '.join(converted)}"

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
        if self._builtin_encoder is not None:
            try:
                return self._builtin_encoder.encode(instr, address, {})
            except EncodeError as e:
                raise ValueError(f"Assembly error: {e}")
        try:
            encoding, count = self._ks.asm(instr, address)
            if encoding is None or count == 0:
                raise ValueError(f"Failed to assemble: {instr}")
            return bytes(encoding)
        except keystone.KsError as e:
            raise ValueError(f"Assembly error: {e}")
