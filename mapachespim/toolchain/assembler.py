"""
Multi-architecture assembler using Keystone Engine.

Assembles source code into machine code for RISC-V, ARM64, x86-64, and MIPS32.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Dict, List, Optional, Tuple

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

from . import mips, riscv
from .directives import DirectiveParser, LineType, SectionData
from .dwarf import DWARFv2Builder
from .elf_builder import STB_GLOBAL, STB_LOCAL, STT_FUNC, STT_NOTYPE, ELFBuilder, Section, Symbol
from .expr import EncodeError
from .memory_map import get_layout


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
KS_ARCH_ARM64 = 2
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
        "arm64": {
            "arch": KS_ARCH_ARM64,
            "mode": KS_MODE_LITTLE_ENDIAN,
            "instr_size": 4,
        },
        "aarch64": {
            "arch": KS_ARCH_ARM64,
            "mode": KS_MODE_LITTLE_ENDIAN,
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
        parser = DirectiveParser()
        sections = parser.parse(source)

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

        # Calculate .text section label positions
        # Pass all_labels (which now contains data section labels) for pseudo-instruction sizing
        # .equ/.set constants can be used as instruction operands but are
        # not addresses, so they are kept out of the ELF symbol table
        constants = dict(parser.constants)

        text_section = sections.get(".text")
        if text_section:
            text_labels = self._calculate_text_labels(
                text_section, self._layout.text_base, {**constants, **all_labels}
            )
            all_labels.update(text_labels)

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

        if result.errors:
            return result

        # Build ELF
        entry_addr = all_labels.get(entry_symbol, self._layout.text_base)
        result.entry_point = entry_addr

        builder = ELFBuilder(self.isa, entry=entry_addr)

        # Add sections
        for sect_name in [".text", ".data", ".rodata", ".bss"]:
            if sect_name in sections:
                sect_data = sections[sect_name]
                if sect_data.data or sect_name == ".text":
                    base = section_bases.get(sect_name, self._layout.text_base)
                    builder.add_section(Section(
                        name=sect_name,
                        data=bytes(sect_data.data),
                        address=base,
                    ))

        # Add symbols
        for name, addr in all_labels.items():
            is_global = name in parser.global_symbols
            # Determine section index (simplified)
            section_idx = 1  # Assume .text is section 1
            for i, (sn, _) in enumerate(sections.items()):
                if sn == ".text":
                    section_idx = i + 1
                    break

            builder.add_symbol(Symbol(
                name=name,
                address=addr,
                sym_type=STT_FUNC if name == entry_symbol else STT_NOTYPE,
                binding=STB_GLOBAL if is_global else STB_LOCAL,
                section_index=section_idx,
            ))

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
                    addr += self._builtin_encoder.instruction_size(line.instruction, known, addr)
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
        if mnemonic in ('jmp', 'call', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle',
                        'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jo', 'jno',
                        'js', 'jns', 'jc', 'jnc', 'loop', 'loope', 'loopne'):
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

        # ARM64 pseudo-instructions that expand to multiple instructions
        if self.isa in ("arm64", "aarch64"):
            operands = parts[1] if len(parts) > 1 else ""
            # adr with symbol -> movz + movk sequence (typically 2 instrs for 32-bit addr)
            if mnemonic == "adr":
                # Check if it's using a symbol (not a numeric offset)
                ops = [o.strip() for o in operands.split(',')]
                if len(ops) == 2:
                    symbol = ops[1].strip()
                    # If it's not a number, it's a symbol that needs expansion
                    if not symbol.startswith('#') and not symbol.lstrip('-').isdigit():
                        return base_size * 2  # movz + movk
            # ldr x0, =symbol -> expands to adr -> movz + movk
            if mnemonic == "ldr" and "=" in operands:
                return base_size * 2

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

        mnemonic = parts[0].lower().rstrip('bwlq')
        operands = parts[1] if len(parts) > 1 else ""

        # Single/two-byte instructions
        if mnemonic == 'nop':
            return 1
        if mnemonic == 'ret':
            return 1
        if mnemonic in ('syscall', 'hlt', 'cld', 'std', 'cdqe', 'cqo'):
            return 2

        # Near jumps/calls with label: 5 bytes (1 opcode + 4 offset)
        # But conditional jumps can be 2 bytes for short jumps, assume 6 for safety
        if mnemonic in ('jmp', 'call'):
            return 5
        if mnemonic in ('je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
                        'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
                        'jc', 'jnc', 'loop', 'loope', 'loopne'):
            return 6  # 0F XX + 4-byte offset

        # RIP-relative addressing: 7 bytes
        # Format: symbol(%rip) or [rip + symbol]
        if '%rip' in operands or 'rip' in operands.lower():
            # REX.W (1) + opcode (1-2) + ModR/M (1) + disp32 (4) = 7-8 bytes
            return 7

        # LEA with memory operand
        if mnemonic == 'lea':
            if '%rip' in operands or 'rip' in operands.lower():
                return 7
            return 4  # Base case

        # MOV with 64-bit immediate
        if mnemonic == 'mov':
            # Check for 64-bit register destination with immediate
            if operands.startswith('$') or operands.startswith('%'):
                # AT&T: movq $imm, %reg or Intel mov reg, imm
                if any(r in operands for r in ['%rax', '%rbx', '%rcx', '%rdx',
                                                '%rsi', '%rdi', '%rbp', '%rsp',
                                                '%r8', '%r9', '%r10', '%r11',
                                                '%r12', '%r13', '%r14', '%r15',
                                                'rax', 'rbx', 'rcx', 'rdx']):
                    # Could be 10 bytes for movabs
                    if '$' in operands:
                        return 10
                    return 7
            # Simple reg-reg or reg-mem: 2-4 bytes
            return 3

        # TEST, CMP with register: 2-3 bytes
        if mnemonic in ('test', 'cmp'):
            if '(' not in operands and '[' not in operands:
                return 3

        # ADD, SUB, XOR, AND, OR with immediate or register: 3-7 bytes
        if mnemonic in ('add', 'sub', 'xor', 'and', 'or'):
            if '$' in operands or any(c.isdigit() for c in operands[:5]):
                return 7  # Could have 32-bit immediate
            return 3  # Register-register

        # Push/pop: 1-2 bytes
        if mnemonic in ('push', 'pop'):
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
                    encoding = encoder.encode(instr, current_addr, labels)
                except EncodeError as e:
                    errors.append(f"Line {line.line_number}: {e} - {line.instruction}")
                    continue
                code.extend(encoding)
                current_addr += len(encoding)
                continue

            # Expand pseudo-instructions for ARM64 and normalize syntax
            if self.isa in ("arm64", "aarch64"):
                instr = self._normalize_arm64_syntax(instr)
                instr = self._expand_arm64_pseudo(instr, current_addr, labels)

            # Convert AT&T to Intel syntax for x86-64
            if self.isa == "x86_64":
                instr = self._convert_x86_att_to_intel(instr, labels)

            # Assemble instruction
            try:
                encoding, count = self._ks.asm(instr, current_addr)
                if encoding is None or count == 0:
                    errors.append(f"Line {line.line_number}: Failed to assemble: {line.instruction}")
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

    def _normalize_arm64_syntax(self, instr: str) -> str:
        """
        Normalize ARM64 syntax for Keystone compatibility.

        Keystone doesn't accept # prefix on immediates, so we strip them.
        Example: mov x0, #42 -> mov x0, 42
        """
        import re
        # Match # followed by a number (decimal, hex, or negative)
        # But not at the start of the line (which would be a comment)
        # Pattern: comma or space, then #, then optional -, then number
        return re.sub(r'([\s,])#(-?(?:0x[0-9a-fA-F]+|\d+))', r'\1\2', instr)

    def _expand_arm64_pseudo(
        self,
        instr: str,
        addr: int,
        labels: Dict[str, int],
    ) -> str:
        """
        Expand ARM64 pseudo-instructions.

        Handles adr with far symbols by using adrp + add sequence.
        """
        parts = instr.split(None, 1)
        if not parts:
            return instr

        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""

        # Handle 'adr' with symbol - convert to movz + movk sequence for far addresses
        if mnemonic == "adr":
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                reg = ops[0]
                symbol = ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    # Use movz/movk sequence for 64-bit address
                    # movz loads the lowest 16 bits, movk adds higher bits
                    b0 = target & 0xFFFF
                    b1 = (target >> 16) & 0xFFFF
                    b2 = (target >> 32) & 0xFFFF
                    b3 = (target >> 48) & 0xFFFF

                    instrs = [f"movz {reg}, {b0}"]
                    if b1:
                        instrs.append(f"movk {reg}, {b1}, lsl 16")
                    if b2:
                        instrs.append(f"movk {reg}, {b2}, lsl 32")
                    if b3:
                        instrs.append(f"movk {reg}, {b3}, lsl 48")

                    return "; ".join(instrs)

        # Handle 'ldr' with = syntax (ldr x0, =symbol)
        if mnemonic == "ldr" and "=" in operands:
            ops = operands.split(",")
            if len(ops) == 2:
                reg = ops[0].strip()
                symbol = ops[1].strip().lstrip("=")
                if symbol in labels:
                    target = labels[symbol]
                    return self._expand_arm64_pseudo(f"adr {reg}, {symbol}", addr, labels)

        # Handle 'b' (unconditional branch) with symbol
        # Note: Keystone expects absolute target address for ARM64 branches
        if mnemonic == "b":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                return f"b 0x{target:x}"

        # Handle 'bl' (branch and link) with symbol
        if mnemonic == "bl":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                return f"bl 0x{target:x}"

        # Handle conditional branches (b.eq, b.ne, etc.)
        if mnemonic.startswith("b."):
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                return f"{mnemonic} 0x{target:x}"

        # Handle cbz/cbnz (compare and branch if zero/not zero)
        if mnemonic in ("cbz", "cbnz"):
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                reg, symbol = ops[0], ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    return f"{mnemonic} {reg}, 0x{target:x}"

        # Handle tbz/tbnz (test bit and branch if zero/not zero)
        if mnemonic in ("tbz", "tbnz"):
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 3:
                reg, bit, symbol = ops[0], ops[1], ops[2].strip()
                if symbol in labels:
                    target = labels[symbol]
                    return f"{mnemonic} {reg}, {bit}, 0x{target:x}"

        return instr

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
        is_att_syntax = '%' in instr or '$' in instr

        # For Intel-syntax jump/call with symbol, resolve the symbol
        if not is_att_syntax:
            if mnemonic in ('jmp', 'call', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle',
                            'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jo', 'jno',
                            'js', 'jns', 'jc', 'jnc', 'loop', 'loope', 'loopne'):
                symbol = operands.strip()
                if symbol in labels:
                    return f"{mnemonic} {labels[symbol]}"
            return instr

        # Handle special AT&T mnemonics
        # movslq = move sign-extend long to quad (Intel: movsxd)
        if mnemonic == 'movslq':
            mnemonic = 'movsxd'
        # cltq = sign-extend eax to rax (Intel: cdqe)
        elif mnemonic == 'cltq':
            return 'cdqe'
        # cqto = sign-extend rax to rdx:rax (Intel: cqo)
        elif mnemonic == 'cqto':
            return 'cqo'

        # Remove size suffixes (b, w, l, q)
        if mnemonic.endswith(('b', 'w', 'l', 'q')) and len(mnemonic) > 2:
            base = mnemonic[:-1]
            if base in ('mov', 'add', 'sub', 'xor', 'and', 'or', 'cmp', 'test',
                        'lea', 'push', 'pop', 'call', 'ret', 'jmp', 'dec', 'inc',
                        'neg', 'not', 'mul', 'imul', 'div', 'idiv', 'shl', 'shr',
                        'sar', 'sal', 'rol', 'ror', 'rcl', 'rcr'):
                mnemonic = base

        # Handle no-operand instructions
        if not operands:
            return mnemonic

        # Split operands
        op_list = []
        depth = 0
        current = ""
        for c in operands:
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            elif c == ',' and depth == 0:
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
            rip_match = re.match(r'(\w+)\s*\(\s*%rip\s*\)', op)
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
            sib_match = re.match(
                r'(-?\d+)?\s*\(\s*%(\w+)\s*,\s*%(\w+)\s*,\s*(\d+)\s*\)', op
            )
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
            mem_match = re.match(r'(-?\d+)?\s*\(\s*%(\w+)\s*\)', op)
            if mem_match:
                offset = mem_match.group(1)
                reg = mem_match.group(2)
                if offset:
                    converted.append(f"[{reg} + {offset}]")
                else:
                    converted.append(f"[{reg}]")
                continue

            # Handle immediate: $value -> value
            if op.startswith('$'):
                value = op[1:]
                # Check if it's a symbol
                if value in labels:
                    converted.append(str(labels[value]))
                else:
                    converted.append(value)
                continue

            # Handle register: %reg -> reg
            if op.startswith('%'):
                converted.append(op[1:])
                continue

            # Check if it's a bare symbol (for jump/call targets)
            if op in labels:
                converted.append(str(labels[op]))
                continue

            # Pass through as-is
            converted.append(op)

        # Reverse operand order for two-operand instructions (AT&T: src, dst -> Intel: dst, src)
        if len(converted) == 2 and mnemonic not in ('push', 'pop', 'call', 'jmp', 'syscall'):
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
