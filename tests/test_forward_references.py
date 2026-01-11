"""Tests for forward reference handling in the assembler."""

import pytest

from mapachespim.toolchain import assemble
from mapachespim.toolchain.assembler import KEYSTONE_AVAILABLE


# Skip all tests if Keystone not available
pytestmark = pytest.mark.skipif(
    not KEYSTONE_AVAILABLE,
    reason="Keystone engine not available"
)


class TestRISCVForwardReferences:
    """Tests for forward references in RISC-V assembly."""

    def test_jal_forward_reference(self):
        """Test jal to forward-defined label."""
        source = """
        .text
        .globl _start
        _start:
            jal ra, helper
            li a7, 93
            ecall

        helper:
            li a0, 42
            ret
        """
        result = assemble(source, isa="riscv64")
        assert result.success
        assert "helper" in result.symbols
        assert result.symbols["helper"] > result.symbols["_start"]

    def test_beqz_forward_reference(self):
        """Test beqz to forward-defined label."""
        source = """
        .text
        _start:
            li t0, 0
            beqz t0, skip
            li a0, 1
        skip:
            li a0, 0
        """
        result = assemble(source, isa="riscv64")
        assert result.success
        assert "skip" in result.symbols

    def test_j_forward_reference(self):
        """Test j (unconditional jump) to forward-defined label."""
        source = """
        .text
        _start:
            j done
            li a0, 1
        done:
            li a0, 0
        """
        result = assemble(source, isa="riscv64")
        assert result.success
        assert "done" in result.symbols

    def test_multiple_forward_references(self):
        """Test multiple forward references in same program."""
        source = """
        .text
        .globl _start
        _start:
            beqz t0, case_zero
            beqz t1, case_one
            j case_default
        case_zero:
            li a0, 0
            j done
        case_one:
            li a0, 1
            j done
        case_default:
            li a0, 99
        done:
            nop
        """
        result = assemble(source, isa="riscv64")
        assert result.success
        assert all(label in result.symbols for label in
                   ["case_zero", "case_one", "case_default", "done"])


class TestARM64ForwardReferences:
    """Tests for forward references in ARM64 assembly."""

    def test_bl_forward_reference(self):
        """Test bl (branch and link) to forward-defined label."""
        source = """
        .text
        .globl _start
        _start:
            bl helper
            mov x8, 93
            svc 0

        helper:
            mov x0, 42
            ret
        """
        result = assemble(source, isa="arm64")
        assert result.success
        assert "helper" in result.symbols

    def test_b_forward_reference(self):
        """Test b (unconditional branch) to forward-defined label."""
        source = """
        .text
        _start:
            b done
            mov x0, 1
        done:
            mov x0, 0
        """
        result = assemble(source, isa="arm64")
        assert result.success
        assert "done" in result.symbols

    def test_cbz_forward_reference(self):
        """Test cbz (compare and branch if zero) to forward-defined label."""
        source = """
        .text
        _start:
            mov x0, 0
            cbz x0, skip
            mov x1, 1
        skip:
            mov x1, 0
        """
        result = assemble(source, isa="arm64")
        assert result.success
        assert "skip" in result.symbols


class TestMIPSForwardReferences:
    """Tests for forward references in MIPS assembly."""

    def test_jal_forward_reference(self):
        """Test jal to forward-defined label."""
        source = """
        .text
        .globl _start
        _start:
            jal helper
            li $v0, 10
            syscall

        helper:
            li $a0, 42
            jr $ra
        """
        result = assemble(source, isa="mips32")
        assert result.success
        assert "helper" in result.symbols

    def test_beq_forward_reference(self):
        """Test beq to forward-defined label."""
        source = """
        .text
        _start:
            li $t0, 0
            beq $t0, $zero, skip
            li $a0, 1
        skip:
            li $a0, 0
        """
        result = assemble(source, isa="mips32")
        assert result.success
        assert "skip" in result.symbols

    def test_j_forward_reference(self):
        """Test j to forward-defined label."""
        source = """
        .text
        _start:
            j done
            li $a0, 1
        done:
            li $a0, 0
        """
        result = assemble(source, isa="mips32")
        assert result.success
        assert "done" in result.symbols


class TestX86ForwardReferences:
    """Tests for forward references in x86-64 assembly."""

    def test_call_forward_reference(self):
        """Test call to forward-defined label."""
        source = """
        .text
        .globl _start
        _start:
            call helper
            mov rax, 60
            syscall

        helper:
            mov rax, 42
            ret
        """
        result = assemble(source, isa="x86_64")
        assert result.success
        assert "helper" in result.symbols

    def test_jmp_forward_reference(self):
        """Test jmp to forward-defined label."""
        source = """
        .text
        _start:
            jmp done
            mov rax, 1
        done:
            mov rax, 0
        """
        result = assemble(source, isa="x86_64")
        assert result.success
        assert "done" in result.symbols


class TestDataSectionReferences:
    """Tests for references to data section symbols."""

    def test_la_to_data_section(self):
        """Test la (load address) to data section symbol."""
        source = """
        .data
        message: .asciz "Hello"

        .text
        .globl _start
        _start:
            la a0, message
            li a7, 4
            ecall
        """
        result = assemble(source, isa="riscv64")
        assert result.success
        assert "message" in result.symbols
