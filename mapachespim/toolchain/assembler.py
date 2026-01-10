"""
Multi-architecture assembler using Keystone Engine.

Assembles source code into machine code for RISC-V, ARM64, x86-64, and MIPS32.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import keystone
    # Verify keystone actually works by trying to access a constant
    _ = keystone.KS_ARCH_X86
    KEYSTONE_AVAILABLE = True
    KEYSTONE_ERROR = None
except ImportError as e:
    KEYSTONE_AVAILABLE = False
    KEYSTONE_ERROR = str(e)
    keystone = None
except Exception as e:
    # Keystone installed but native library failed to load
    KEYSTONE_AVAILABLE = False
    KEYSTONE_ERROR = f"Keystone native library failed: {e}"
    keystone = None

from .directives import DirectiveParser, LineType
from .elf_builder import ELFBuilder, Section, Symbol, STT_FUNC, STT_NOTYPE, STB_GLOBAL, STB_LOCAL
from .memory_map import get_layout, MemoryLayout


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

    @property
    def success(self) -> bool:
        return len(self.errors) == 0 and len(self.elf_bytes) > 0


# Keystone architecture/mode constants
KS_ARCH_ARM64 = 2
KS_ARCH_MIPS = 3
KS_ARCH_X86 = 4
KS_ARCH_RISCV = 10  # Added in recent Keystone

KS_MODE_LITTLE_ENDIAN = 0
KS_MODE_BIG_ENDIAN = 0x40000000
KS_MODE_64 = 0x8
KS_MODE_32 = 0x4
KS_MODE_RISCV64 = 0x8
KS_MODE_MIPS32 = 0x4


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
    ISA_CONFIG = {
        "riscv64": {
            "arch": KS_ARCH_RISCV,
            "mode": KS_MODE_RISCV64 | KS_MODE_LITTLE_ENDIAN,
            "instr_size": 4,
        },
        "riscv": {
            "arch": KS_ARCH_RISCV,
            "mode": KS_MODE_RISCV64 | KS_MODE_LITTLE_ENDIAN,
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
        "mips32": {
            "arch": KS_ARCH_MIPS,
            "mode": KS_MODE_MIPS32 | KS_MODE_BIG_ENDIAN,
            "instr_size": 4,
        },
        "mips": {
            "arch": KS_ARCH_MIPS,
            "mode": KS_MODE_MIPS32 | KS_MODE_BIG_ENDIAN,
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
        if not KEYSTONE_AVAILABLE:
            msg = "Keystone Engine not available.\n"
            if KEYSTONE_ERROR:
                msg += f"Error: {KEYSTONE_ERROR}\n\n"
            msg += "Install with: pip install keystone-engine\n\n"
            msg += "On Apple Silicon, you may need to install via Homebrew:\n"
            msg += "  brew install keystone\n"
            msg += "  pip install keystone-engine"
            raise ImportError(msg)

        isa_lower = isa.lower().replace("-", "_")
        if isa_lower not in self.ISA_CONFIG:
            valid = sorted(set(k for k in self.ISA_CONFIG.keys() if "_" not in k))
            raise ValueError(f"Unknown ISA: {isa!r}. Valid: {', '.join(valid)}")

        self.isa = isa_lower
        self._config = self.ISA_CONFIG[isa_lower]
        self._layout = get_layout(isa_lower)

        # Initialize Keystone
        try:
            self._ks = keystone.Ks(self._config["arch"], self._config["mode"])
        except keystone.KsError as e:
            raise RuntimeError(f"Failed to initialize Keystone for {isa}: {e}")

    def assemble(
        self,
        source: str,
        entry_symbol: str = "_start",
    ) -> AssemblyResult:
        """
        Assemble source code into an ELF executable.

        Args:
            source: Assembly source code.
            entry_symbol: Entry point symbol name.

        Returns:
            AssemblyResult with ELF bytes and metadata.
        """
        result = AssemblyResult(isa=self.isa)

        # Parse source
        parser = DirectiveParser()
        sections = parser.parse(source)

        result.errors.extend(parser.errors)
        result.warnings.extend(parser.warnings)

        if result.errors:
            return result

        # Collect all labels for forward reference resolution
        all_labels: Dict[str, int] = {}
        section_bases = {
            ".text": self._layout.text_base,
            ".data": self._layout.data_base,
            ".rodata": self._layout.rodata_base,
            ".bss": self._layout.bss_base,
        }

        # First pass: collect labels with estimated positions
        for sect_name, sect_data in sections.items():
            base = section_bases.get(sect_name, self._layout.text_base)
            for label_name, offset in sect_data.labels.items():
                all_labels[label_name] = base + offset

        # Second pass: assemble .text section
        text_section = sections.get(".text")
        if text_section:
            code, code_labels, asm_errors = self._assemble_section(
                text_section, self._layout.text_base, all_labels
            )
            result.errors.extend(asm_errors)

            # Update labels with actual positions
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
        result.elf_bytes = builder.build()

        return result

    def _assemble_section(
        self,
        section: "SectionData",
        base_addr: int,
        labels: Dict[str, int],
    ) -> Tuple[bytes, Dict[str, int], List[str]]:
        """
        Assemble instructions in a section.

        Returns:
            (assembled_bytes, label_addresses, errors)
        """
        from .directives import SectionData

        code = bytearray()
        label_addrs: Dict[str, int] = {}
        errors: List[str] = []
        current_addr = base_addr

        for line in section.lines:
            # Record label position
            if line.label:
                label_addrs[line.label] = current_addr

            # Skip non-instructions
            if line.line_type != LineType.INSTRUCTION or not line.instruction:
                continue

            instr = line.instruction

            # Expand pseudo-instructions for RISC-V
            if self.isa in ("riscv64", "riscv"):
                instr = self._expand_riscv_pseudo(instr, current_addr, labels)

            # Assemble instruction
            try:
                # For RISC-V, disable compressed instructions for predictable 4-byte encoding
                if self.isa in ("riscv64", "riscv"):
                    instr = f".option norvc\n{instr}"

                encoding, count = self._ks.asm(instr, current_addr)
                if encoding is None or count == 0:
                    errors.append(f"Line {line.line_number}: Failed to assemble: {line.instruction}")
                    continue

                code.extend(encoding)
                current_addr += len(encoding)

            except keystone.KsError as e:
                errors.append(f"Line {line.line_number}: {e} - {line.instruction}")

        return bytes(code), label_addrs, errors

    def _expand_riscv_pseudo(
        self,
        instr: str,
        addr: int,
        labels: Dict[str, int],
    ) -> str:
        """
        Expand RISC-V pseudo-instructions.

        Keystone handles most, but some need help.
        """
        parts = instr.split(None, 1)
        if not parts:
            return instr

        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""

        # Handle 'li' (load immediate) - Keystone may not handle large values
        if mnemonic == "li":
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                reg = ops[0]
                try:
                    # Try to parse the immediate
                    imm_str = ops[1].strip()
                    if imm_str in labels:
                        imm = labels[imm_str]
                    elif imm_str.startswith('0x'):
                        imm = int(imm_str, 16)
                    else:
                        imm = int(imm_str)

                    # If small enough, let Keystone handle it
                    if -2048 <= imm <= 2047:
                        return f"addi {reg}, x0, {imm}"

                    # Large immediate: use lui + addi
                    upper = (imm + 0x800) >> 12
                    lower = imm - (upper << 12)
                    if lower < -2048:
                        lower += 4096
                        upper -= 1

                    return f"lui {reg}, {upper}; addi {reg}, {reg}, {lower}"

                except (ValueError, KeyError):
                    pass  # Let Keystone try

        # Handle 'la' (load address)
        if mnemonic == "la":
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                reg = ops[0]
                symbol = ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    return self._expand_riscv_pseudo(f"li {reg}, {target}", addr, labels)

        # Handle 'call' pseudo
        if mnemonic == "call":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                offset = target - addr
                if -1048576 <= offset <= 1048575:
                    return f"jal ra, {offset}"
                # For far calls, use auipc + jalr
                upper = ((offset + 0x800) >> 12) & 0xFFFFF
                lower = offset - (upper << 12)
                return f"auipc ra, {upper}; jalr ra, ra, {lower}"

        return instr

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
            encoding, count = self._ks.asm(instr, address)
            if encoding is None or count == 0:
                raise ValueError(f"Failed to assemble: {instr}")
            return bytes(encoding)
        except keystone.KsError as e:
            raise ValueError(f"Assembly error: {e}")
