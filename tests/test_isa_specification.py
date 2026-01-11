"""Tests for ISA specification via --isa flag and .isa directive."""

import pytest
import tempfile
from pathlib import Path

from mapachespim.toolchain import assemble, assemble_file, AssemblyResult
from mapachespim.toolchain.assembler import KEYSTONE_AVAILABLE
from mapachespim.toolchain.directives import DirectiveParser


# Skip all tests if Keystone not available
pytestmark = pytest.mark.skipif(
    not KEYSTONE_AVAILABLE,
    reason="Keystone engine not available"
)


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


class TestAssembleFile:
    """Tests for assemble_file with ISA specification."""

    def test_explicit_isa_flag(self):
        """Test that explicit ISA flag works."""
        with tempfile.NamedTemporaryFile(suffix=".s", delete=False, mode='w') as f:
            f.write(".text\n_start: nop\n")
            f.flush()

            result = assemble_file(f.name, isa="riscv64")
            assert result.success
            assert result.isa == "riscv64"

            Path(f.name).unlink()

    def test_isa_directive_in_file(self):
        """Test that .isa directive in file is detected."""
        with tempfile.NamedTemporaryFile(suffix=".s", delete=False, mode='w') as f:
            f.write(".isa arm64\n.text\n_start: nop\n")
            f.flush()

            result = assemble_file(f.name)  # No explicit ISA
            assert result.success
            assert result.isa == "arm64"

            Path(f.name).unlink()

    def test_explicit_isa_overrides_directive(self):
        """Test that --isa flag overrides .isa directive in file."""
        with tempfile.NamedTemporaryFile(suffix=".s", delete=False, mode='w') as f:
            # File says arm64, but we'll pass riscv64
            f.write(".isa arm64\n.text\n_start: nop\n")
            f.flush()

            # Explicit flag should override
            result = assemble_file(f.name, isa="riscv64")
            assert result.success
            assert result.isa == "riscv64"

            Path(f.name).unlink()

    def test_missing_isa_produces_error(self):
        """Test that missing ISA produces helpful error."""
        with tempfile.NamedTemporaryFile(suffix=".s", delete=False, mode='w') as f:
            f.write(".text\n_start: nop\n")
            f.flush()

            result = assemble_file(f.name)  # No ISA specified anywhere
            assert not result.success
            assert len(result.errors) == 1
            assert "ISA not specified" in result.errors[0]
            assert "--isa" in result.errors[0]
            assert ".isa" in result.errors[0]

            Path(f.name).unlink()

    def test_isa_directive_at_top_of_file(self):
        """Test that .isa directive works when at top (after comments)."""
        with tempfile.NamedTemporaryFile(suffix=".s", delete=False, mode='w') as f:
            f.write("# This is a comment\n")
            f.write("// Another comment\n")
            f.write(".isa mips32\n")
            f.write(".text\n_start: nop\n")
            f.flush()

            result = assemble_file(f.name)
            assert result.success
            assert result.isa == "mips32"

            Path(f.name).unlink()

    def test_all_isas_with_flag(self):
        """Test that all ISAs work with explicit flag."""
        for isa in ["riscv64", "arm64", "x86_64", "mips32"]:
            with tempfile.NamedTemporaryFile(suffix=".s", delete=False, mode='w') as f:
                f.write(".text\n_start: nop\n")
                f.flush()

                result = assemble_file(f.name, isa=isa)
                assert result.success, f"Failed for ISA: {isa}"
                assert result.isa == isa

                Path(f.name).unlink()

    def test_all_isas_with_directive(self):
        """Test that all ISAs work with .isa directive."""
        for isa in ["riscv64", "arm64", "x86_64", "mips32"]:
            with tempfile.NamedTemporaryFile(suffix=".s", delete=False, mode='w') as f:
                f.write(f".isa {isa}\n.text\n_start: nop\n")
                f.flush()

                result = assemble_file(f.name)
                assert result.success, f"Failed for ISA: {isa}"
                assert result.isa == isa

                Path(f.name).unlink()


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
