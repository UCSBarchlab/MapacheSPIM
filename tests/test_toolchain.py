"""Tests for the MapacheSPIM toolchain (Keystone-based assembler)."""

import pytest
from mapachespim.toolchain import assemble, AssemblyResult
from mapachespim.toolchain.assembler import Assembler, KEYSTONE_AVAILABLE
from mapachespim.toolchain.directives import DirectiveParser, LineType


# Skip all tests if Keystone not available
pytestmark = pytest.mark.skipif(
    not KEYSTONE_AVAILABLE,
    reason="Keystone engine not available"
)


class TestDirectiveParser:
    """Tests for the directive parser."""

    def test_parse_empty(self):
        parser = DirectiveParser()
        sections = parser.parse("")
        assert ".text" in sections
        assert len(sections[".text"].lines) == 0

    def test_parse_label(self):
        parser = DirectiveParser()
        sections = parser.parse("_start:")
        assert "_start" in sections[".text"].labels

    def test_parse_instruction(self):
        parser = DirectiveParser()
        sections = parser.parse("nop")
        lines = sections[".text"].lines
        assert len(lines) == 1
        assert lines[0].line_type == LineType.INSTRUCTION
        assert lines[0].instruction == "nop"

    def test_parse_hash_comment(self):
        parser = DirectiveParser()
        sections = parser.parse("# this is a comment")
        assert len(sections[".text"].lines) == 0

    def test_parse_inline_hash_comment(self):
        parser = DirectiveParser()
        sections = parser.parse("nop  # inline comment")
        lines = sections[".text"].lines
        assert len(lines) == 1
        assert lines[0].instruction == "nop"

    def test_arm_immediate_not_comment(self):
        """Test that ARM-style #immediate is not treated as comment."""
        parser = DirectiveParser()
        sections = parser.parse("mov x0, #42")
        lines = sections[".text"].lines
        assert len(lines) == 1
        assert lines[0].instruction == "mov x0, #42"

    def test_parse_section_directive(self):
        parser = DirectiveParser()
        sections = parser.parse(".data\n.word 42")
        assert ".data" in sections
        assert len(sections[".data"].data) == 4

    def test_parse_globl_directive(self):
        parser = DirectiveParser()
        parser.parse(".globl _start\n_start:")
        assert "_start" in parser.global_symbols


class TestAssembler:
    """Tests for the assembler."""

    def test_riscv64_simple(self):
        result = assemble("nop", isa="riscv64")
        assert result.success
        assert len(result.elf_bytes) > 0

    def test_riscv64_full_program(self):
        source = """
        .text
        .globl _start
        _start:
            li a0, 42
            li a7, 93
            ecall
        """
        result = assemble(source, isa="riscv64")
        assert result.success
        assert "_start" in result.symbols
        assert result.entry_point == result.symbols["_start"]

    def test_arm64_simple(self):
        result = assemble("nop", isa="arm64")
        assert result.success

    def test_arm64_immediates(self):
        source = """
        .text
        .globl _start
        _start:
            mov x0, #42
            mov x8, #93
            svc #0
        """
        result = assemble(source, isa="arm64")
        assert result.success
        assert len(result.errors) == 0

    def test_x86_64_simple(self):
        result = assemble("nop", isa="x86_64")
        assert result.success

    def test_x86_64_full_program(self):
        source = """
        .text
        .globl _start
        _start:
            mov rax, 60
            mov rdi, 42
            syscall
        """
        result = assemble(source, isa="x86_64")
        assert result.success

    def test_mips32_simple(self):
        result = assemble("nop", isa="mips32")
        assert result.success

    def test_mips32_full_program(self):
        source = """
        .text
        .globl _start
        _start:
            li $v0, 10
            li $a0, 42
            syscall
        """
        result = assemble(source, isa="mips32")
        assert result.success

    def test_invalid_isa(self):
        with pytest.raises(ValueError, match="Unknown ISA"):
            Assembler("invalid_isa")

    def test_assembly_error_reported(self):
        result = assemble("invalid_instruction_xyz", isa="riscv64")
        assert not result.success
        assert len(result.errors) > 0

    def test_data_section(self):
        source = """
        .data
        message: .asciz "Hello"
        .text
        .globl _start
        _start:
            nop
        """
        result = assemble(source, isa="riscv64")
        assert result.success
        assert "message" in result.symbols

    def test_all_isas(self):
        """Test that all 4 ISAs can assemble a simple program."""
        for isa in ["riscv64", "arm64", "x86_64", "mips32"]:
            result = assemble("nop", isa=isa)
            assert result.success, f"{isa} failed to assemble 'nop'"


class TestAssemblyResult:
    """Tests for AssemblyResult class."""

    def test_success_property(self):
        result = AssemblyResult(elf_bytes=b"\x00", errors=[])
        assert result.success

    def test_failure_with_errors(self):
        result = AssemblyResult(elf_bytes=b"", errors=["some error"])
        assert not result.success

    def test_failure_with_empty_bytes(self):
        result = AssemblyResult(elf_bytes=b"", errors=[])
        assert not result.success
