"""Tests for ISA specification via --isa flag and .isa directive."""

import pytest
from pathlib import Path

from mapachespim.toolchain import assemble, assemble_file, AssemblyResult
from mapachespim.toolchain.directives import DirectiveParser



class TestISADirective:
    """Tests for .isa directive in source files."""

    def test_isa_directive_riscv64(self):
        """Test .isa riscv64 directive."""
        source = """
        .isa riscv64
        .text
        .globl _start
        _start:
            nop
        """
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa == "riscv64"
        assert len(parser.errors) == 0

    def test_isa_directive_arm64(self):
        """Test .isa arm64 directive."""
        source = """
        .isa arm64
        .text
        _start:
            nop
        """
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa == "arm64"

    def test_isa_directive_x86_64(self):
        """Test .isa x86_64 directive."""
        source = """
        .isa x86_64
        .text
        _start:
            nop
        """
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa == "x86_64"

    def test_isa_directive_mips32(self):
        """Test .isa mips32 directive."""
        source = """
        .isa mips32
        .text
        _start:
            nop
        """
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa == "mips32"

    def test_isa_directive_with_hyphen(self):
        """Test .isa directive accepts x86-64 with hyphen."""
        source = """
        .isa x86-64
        .text
        _start:
            nop
        """
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa == "x86_64"

    def test_isa_directive_invalid_isa(self):
        """Test .isa directive with invalid ISA produces error."""
        source = """
        .isa invalid_arch
        .text
        _start:
            nop
        """
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa is None
        assert len(parser.errors) == 1
        assert "Invalid ISA" in parser.errors[0]
        assert "invalid_arch" in parser.errors[0]

    def test_isa_directive_missing_argument(self):
        """Test .isa directive without argument produces error."""
        source = """
        .isa
        .text
        _start:
            nop
        """
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa is None
        assert len(parser.errors) == 1
        assert "requires an argument" in parser.errors[0]


def _source(tmp_path, text, name="program.s"):
    """Write assembly source to a file and return its path."""
    path = tmp_path / name
    path.write_text(text)
    return path


class TestAssembleFile:
    """Tests for assemble_file with ISA specification."""

    def test_explicit_isa_flag(self, tmp_path):
        """Test that explicit ISA flag works."""
        result = assemble_file(_source(tmp_path, ".text\n_start: nop\n"), isa="riscv64")
        assert result.success
        assert result.isa == "riscv64"

    def test_isa_directive_in_file(self, tmp_path):
        """Test that .isa directive in file is detected."""
        result = assemble_file(_source(tmp_path, ".isa arm64\n.text\n_start: nop\n"))
        assert result.success
        assert result.isa == "arm64"

    def test_explicit_isa_overrides_directive(self, tmp_path):
        """Test that --isa flag overrides .isa directive in file."""
        # File says arm64, but the explicit flag should win
        path = _source(tmp_path, ".isa arm64\n.text\n_start: nop\n")
        result = assemble_file(path, isa="riscv64")
        assert result.success
        assert result.isa == "riscv64"

    def test_missing_isa_produces_error(self, tmp_path):
        """Test that missing ISA produces helpful error."""
        result = assemble_file(_source(tmp_path, ".text\n_start: nop\n"))
        assert not result.success
        assert len(result.errors) == 1
        assert "ISA not specified" in result.errors[0]
        assert "--isa" in result.errors[0]
        assert ".isa" in result.errors[0]

    def test_isa_directive_at_top_of_file(self, tmp_path):
        """Test that .isa directive works when at top (after comments)."""
        source = "# This is a comment\n// Another comment\n.isa mips32\n.text\n_start: nop\n"
        result = assemble_file(_source(tmp_path, source))
        assert result.success
        assert result.isa == "mips32"

    def test_all_isas_with_flag(self, tmp_path):
        """Test that all ISAs work with explicit flag."""
        for isa in ["riscv64", "arm64", "x86_64", "mips32"]:
            path = _source(tmp_path, ".text\n_start: nop\n", f"{isa}.s")
            result = assemble_file(path, isa=isa)
            assert result.success, f"Failed for ISA: {isa}"
            assert result.isa == isa

    def test_all_isas_with_directive(self, tmp_path):
        """Test that all ISAs work with .isa directive."""
        for isa in ["riscv64", "arm64", "x86_64", "mips32"]:
            path = _source(tmp_path, f".isa {isa}\n.text\n_start: nop\n", f"{isa}.s")
            result = assemble_file(path)
            assert result.success, f"Failed for ISA: {isa}"
            assert result.isa == isa


class TestDirectAssemble:
    """Tests for assemble() function with explicit ISA."""

    def test_explicit_isa_required(self):
        """Test that assemble() requires explicit ISA parameter."""
        # This should work - ISA is explicitly provided
        result = assemble("nop", isa="riscv64")
        assert result.success

    def test_all_isas_assemble_nop(self):
        """Test that all ISAs can assemble 'nop' instruction."""
        for isa in ["riscv64", "arm64", "x86_64", "mips32"]:
            result = assemble("nop", isa=isa)
            assert result.success, f"Failed for {isa}: {result.errors}"
