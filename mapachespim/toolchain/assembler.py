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
        text_section = sections.get(".text")
        if text_section:
            text_labels = self._calculate_text_labels(
                text_section, self._layout.text_base
            )
            all_labels.update(text_labels)

        # Pass 2: Assemble .text section with all labels known
        if text_section:
            code, code_labels, asm_errors = self._assemble_section(
                text_section, self._layout.text_base, all_labels
            )
            result.errors.extend(asm_errors)

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
        result.elf_bytes = builder.build()

        return result

    def _calculate_text_labels(
        self,
        section: "SectionData",
        base_addr: int,
    ) -> Dict[str, int]:
        """
        Calculate label addresses in .text section without assembling.

        Pass 1 of two-pass assembly: determine where each label will be
        based on instruction count.

        For fixed-size ISAs (RISC-V, ARM64, MIPS): 4 bytes per instruction.
        For variable-size ISAs (x86-64): estimate based on instruction type.

        Returns:
            Dictionary of label name -> address.
        """
        from .directives import LineType

        labels: Dict[str, int] = {}
        current_addr = base_addr
        instr_size = self._config.get("instr_size", 4)

        for line in section.lines:
            # Record label position
            if line.label:
                labels[line.label] = current_addr

            # Skip non-instructions
            if line.line_type != LineType.INSTRUCTION or not line.instruction:
                continue

            # Calculate instruction size
            if instr_size is not None:
                # Fixed-size ISA (RISC-V, ARM64, MIPS)
                # Check for pseudo-instructions that expand to multiple instructions
                size = self._estimate_fixed_instr_size(line.instruction, instr_size)
                current_addr += size
            else:
                # Variable-size ISA (x86-64)
                # Estimate based on instruction type
                current_addr += self._estimate_x86_instr_size(line.instruction)

        return labels

    def _estimate_fixed_instr_size(self, instr: str, base_size: int) -> int:
        """
        Estimate instruction size for fixed-size ISAs.

        Accounts for pseudo-instructions that expand to multiple instructions.
        """
        parts = instr.split(None, 1)
        if not parts:
            return base_size

        mnemonic = parts[0].lower()

        # MIPS pseudo-branches expand to 2 instructions (slt + branch)
        if self.isa in ("mips32", "mips"):
            if mnemonic in ("blt", "bge", "ble", "bgt"):
                return base_size * 2

        # RISC-V pseudo-instructions that might expand
        if self.isa in ("riscv64", "riscv"):
            # li with large immediate: lui + addi = 8 bytes
            if mnemonic == "li":
                operands = parts[1] if len(parts) > 1 else ""
                ops = [o.strip() for o in operands.split(',')]
                if len(ops) == 2:
                    try:
                        imm_str = ops[1].strip()
                        if imm_str.startswith('0x'):
                            imm = int(imm_str, 16)
                        else:
                            imm = int(imm_str)
                        if not (-2048 <= imm <= 2047):
                            return base_size * 2
                    except ValueError:
                        pass
            # la always expands to lui + addi
            if mnemonic == "la":
                return base_size * 2
            # call may expand to auipc + jalr for far calls
            if mnemonic == "call":
                return base_size * 2  # Conservative estimate

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

        # Single-byte instructions
        if mnemonic in ('nop', 'ret', 'syscall', 'hlt', 'cld', 'std'):
            return 1 if mnemonic == 'nop' else 2

        # Near jumps/calls with label: typically 5 bytes (1 opcode + 4 offset)
        if mnemonic in ('jmp', 'call', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle',
                        'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jo', 'jno',
                        'js', 'jns', 'jc', 'jnc'):
            return 5

        # Most other instructions: 3-7 bytes, use 5 as conservative estimate
        return 5

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

            # Expand pseudo-instructions for MIPS and normalize syntax
            if self.isa in ("mips32", "mips"):
                instr = self._normalize_mips_syntax(instr)
                instr = self._expand_mips_pseudo(instr, current_addr, labels)

            # Expand pseudo-instructions for ARM64 and normalize syntax
            if self.isa in ("arm64", "aarch64"):
                instr = self._normalize_arm64_syntax(instr)
                instr = self._expand_arm64_pseudo(instr, current_addr, labels)

            # Convert AT&T to Intel syntax for x86-64
            if self.isa == "x86_64":
                instr = self._convert_x86_att_to_intel(instr, labels)

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

        # Handle 'j' pseudo (jump without link)
        if mnemonic == "j":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                offset = target - addr
                return f"jal x0, {offset}"

        # Handle 'jal' with symbol (calculate offset)
        if mnemonic == "jal":
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                rd = ops[0]
                symbol = ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    return f"jal {rd}, {offset}"

        # Handle branch instructions with symbols
        branch_ops = ["beq", "bne", "blt", "bge", "bltu", "bgeu"]
        if mnemonic in branch_ops:
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 3:
                rs1, rs2, symbol = ops[0], ops[1], ops[2].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    return f"{mnemonic} {rs1}, {rs2}, {offset}"

        # Handle beqz/bnez pseudo-instructions (branch if zero/not zero)
        if mnemonic in ("beqz", "bnez"):
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                rs = ops[0]
                symbol = ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    real_mnemonic = "beq" if mnemonic == "beqz" else "bne"
                    return f"{real_mnemonic} {rs}, x0, {offset}"

        # Handle pseudo-branches that swap operands
        # ble rs1, rs2, label → bge rs2, rs1, label
        # bgt rs1, rs2, label → blt rs2, rs1, label
        # bleu rs1, rs2, label → bgeu rs2, rs1, label
        # bgtu rs1, rs2, label → bltu rs2, rs1, label
        swap_branches = {
            "ble": "bge",
            "bgt": "blt",
            "bleu": "bgeu",
            "bgtu": "bltu",
        }
        if mnemonic in swap_branches:
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 3:
                rs1, rs2, symbol = ops[0], ops[1], ops[2].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    real_mnemonic = swap_branches[mnemonic]
                    return f"{real_mnemonic} {rs2}, {rs1}, {offset}"

        # Handle blez/bgtz/bltz/bgez (single register branches)
        single_reg_branches = {
            "blez": ("bge", "x0"),   # blez rs, label → bge x0, rs, label
            "bgtz": ("blt", "x0"),   # bgtz rs, label → blt x0, rs, label
            "bltz": ("blt", None),   # bltz rs, label → blt rs, x0, label
            "bgez": ("bge", None),   # bgez rs, label → bge rs, x0, label
        }
        if mnemonic in single_reg_branches:
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                rs, symbol = ops[0], ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    real_mnemonic, first_reg = single_reg_branches[mnemonic]
                    if first_reg is not None:
                        return f"{real_mnemonic} {first_reg}, {rs}, {offset}"
                    else:
                        return f"{real_mnemonic} {rs}, x0, {offset}"

        return instr

    def _normalize_mips_syntax(self, instr: str) -> str:
        """
        Normalize MIPS syntax for Keystone compatibility.

        Keystone doesn't recognize $zero - convert to $0.
        """
        # Replace $zero with $0
        return instr.replace("$zero", "$0")

    def _expand_mips_pseudo(
        self,
        instr: str,
        addr: int,
        labels: Dict[str, int],
    ) -> str:
        """
        Expand MIPS pseudo-instructions.

        Handles la (load address) and li (load immediate).
        """
        parts = instr.split(None, 1)
        if not parts:
            return instr

        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""

        # Handle 'li' (load immediate)
        if mnemonic == "li":
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                reg = ops[0]
                try:
                    imm_str = ops[1].strip()
                    if imm_str in labels:
                        imm = labels[imm_str]
                    elif imm_str.startswith('0x'):
                        imm = int(imm_str, 16)
                    else:
                        imm = int(imm_str)

                    # Small immediate: use addiu with $0
                    if -32768 <= imm <= 32767:
                        return f"addiu {reg}, $0, {imm}"

                    # Large immediate: use lui + ori
                    upper = (imm >> 16) & 0xFFFF
                    lower = imm & 0xFFFF
                    if lower == 0:
                        return f"lui {reg}, {upper}"
                    return f"lui {reg}, {upper}; ori {reg}, {reg}, {lower}"

                except (ValueError, KeyError):
                    pass

        # Handle 'la' (load address)
        if mnemonic == "la":
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                reg = ops[0]
                symbol = ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    return self._expand_mips_pseudo(f"li {reg}, {target}", addr, labels)

        # Handle 'j' (unconditional jump) - MIPS uses absolute address
        if mnemonic == "j":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                # MIPS j uses 26-bit absolute address (shifted left 2)
                return f"j {target >> 2}"

        # Handle 'jal' (jump and link)
        if mnemonic == "jal":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                return f"jal {target >> 2}"

        # Handle branch instructions with symbols
        mips_branches = ["beq", "bne", "blez", "bgtz", "bltz", "bgez"]
        if mnemonic in mips_branches:
            ops = [o.strip() for o in operands.split(',')]
            # beq/bne: rs, rt, offset
            if mnemonic in ("beq", "bne") and len(ops) == 3:
                rs, rt, symbol = ops[0], ops[1], ops[2].strip()
                if symbol in labels:
                    target = labels[symbol]
                    # Keystone expects byte offset from current instruction
                    offset = target - addr
                    # Convert $zero to $0 for Keystone
                    rs = "$0" if rs == "$zero" else rs
                    rt = "$0" if rt == "$zero" else rt
                    return f"{mnemonic} {rs}, {rt}, {offset}"
            # blez/bgtz/bltz/bgez: rs, offset
            elif len(ops) == 2:
                rs, symbol = ops[0], ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    rs = "$0" if rs == "$zero" else rs
                    return f"{mnemonic} {rs}, {offset}"

        # Handle pseudo-branch instructions (blt, bge, ble, bgt)
        # These expand to: slt $at, rs, rt; beq/bne $at, $0, offset
        pseudo_branches = {
            "blt": ("slt", "bne"),   # blt rs, rt → slt $at, rs, rt; bne $at, $0
            "bge": ("slt", "beq"),   # bge rs, rt → slt $at, rs, rt; beq $at, $0
            "ble": ("slt", "beq", True),  # ble rs, rt → slt $at, rt, rs; beq $at, $0 (swap)
            "bgt": ("slt", "bne", True),  # bgt rs, rt → slt $at, rt, rs; bne $at, $0 (swap)
        }
        if mnemonic in pseudo_branches:
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 3:
                rs, rt, symbol = ops[0], ops[1], ops[2].strip()
                if symbol in labels:
                    target = labels[symbol]
                    config = pseudo_branches[mnemonic]
                    slt_op = config[0]
                    branch_op = config[1]
                    swap = len(config) > 2 and config[2]

                    # Normalize register names
                    rs = "$0" if rs == "$zero" else rs
                    rt = "$0" if rt == "$zero" else rt

                    # Build the slt instruction
                    if swap:
                        slt_instr = f"{slt_op} $1, {rt}, {rs}"  # $1 is $at
                    else:
                        slt_instr = f"{slt_op} $1, {rs}, {rt}"

                    # Branch offset is from the branch instruction (addr + 4)
                    offset = target - (addr + 4)
                    branch_instr = f"{branch_op} $1, $0, {offset}"

                    return f"{slt_instr}; {branch_instr}"

        return instr

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
        if mnemonic == "b":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                offset = target - addr
                return f"b {offset}"

        # Handle 'bl' (branch and link) with symbol
        if mnemonic == "bl":
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                offset = target - addr
                return f"bl {offset}"

        # Handle conditional branches (b.eq, b.ne, etc.)
        if mnemonic.startswith("b."):
            symbol = operands.strip()
            if symbol in labels:
                target = labels[symbol]
                offset = target - addr
                return f"{mnemonic} {offset}"

        # Handle cbz/cbnz (compare and branch if zero/not zero)
        if mnemonic in ("cbz", "cbnz"):
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 2:
                reg, symbol = ops[0], ops[1].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    return f"{mnemonic} {reg}, {offset}"

        # Handle tbz/tbnz (test bit and branch if zero/not zero)
        if mnemonic in ("tbz", "tbnz"):
            ops = [o.strip() for o in operands.split(',')]
            if len(ops) == 3:
                reg, bit, symbol = ops[0], ops[1], ops[2].strip()
                if symbol in labels:
                    target = labels[symbol]
                    offset = target - addr
                    return f"{mnemonic} {reg}, {bit}, {offset}"

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
        try:
            encoding, count = self._ks.asm(instr, address)
            if encoding is None or count == 0:
                raise ValueError(f"Failed to assemble: {instr}")
            return bytes(encoding)
        except keystone.KsError as e:
            raise ValueError(f"Assembly error: {e}")
