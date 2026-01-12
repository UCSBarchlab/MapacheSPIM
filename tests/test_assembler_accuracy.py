#!/usr/bin/env python3
"""
Comprehensive tests for the MapacheSPIM assembler instruction size estimation.

These tests verify that the two-pass assembler correctly:
1. Estimates instruction sizes in Pass 1
2. Assembles to matching sizes in Pass 2
3. Resolves forward and backward references correctly
4. Handles pseudo-instruction expansion accurately

This test suite is designed to catch issues where estimated sizes differ from
actual assembled sizes, which would cause incorrect label addresses and broken
branch targets.
"""

import pytest
from typing import Dict, List, Tuple

from mapachespim.toolchain import assemble
from mapachespim.toolchain.assembler import Assembler, KEYSTONE_AVAILABLE
from mapachespim.toolchain.directives import DirectiveParser, LineType
from mapachespim.toolchain.memory_map import get_layout


# Skip all tests if Keystone not available
pytestmark = pytest.mark.skipif(
    not KEYSTONE_AVAILABLE,
    reason="Keystone engine not available"
)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def verify_label_accuracy(source: str, isa: str) -> List[str]:
    """
    Verify that all label addresses match between estimation and assembly.

    Compares Pass 1 (estimated) label addresses with Pass 2 (actual) addresses.

    Returns:
        List of error messages (empty if all labels match)
    """
    assembler = Assembler(isa)
    parser = DirectiveParser()
    sections = parser.parse(source)

    layout = get_layout(isa)
    text_section = sections.get(".text")
    if not text_section:
        return ["No .text section found"]

    # Pass 1: Get estimated label positions
    estimated_labels = assembler._calculate_text_labels(text_section, layout.text_base)

    # Pass 2: Assemble and get actual positions
    result = assemble(source, isa=isa)
    if not result.success:
        return [f"Assembly failed: {result.errors}"]

    actual_labels = result.symbols

    # Compare
    errors = []
    for label, estimated in estimated_labels.items():
        if label in actual_labels:
            actual = actual_labels[label]
            if estimated != actual:
                diff = actual - estimated
                errors.append(
                    f"'{label}': estimated=0x{estimated:x}, actual=0x{actual:x}, "
                    f"diff={diff:+d} bytes"
                )

    return errors


def get_label_offsets(source: str, isa: str) -> Dict[str, Tuple[int, int, int]]:
    """
    Get estimated, actual, and difference for all labels.

    Returns:
        Dict mapping label name to (estimated, actual, difference)
    """
    assembler = Assembler(isa)
    parser = DirectiveParser()
    sections = parser.parse(source)

    layout = get_layout(isa)
    text_section = sections.get(".text")
    if not text_section:
        return {}

    estimated = assembler._calculate_text_labels(text_section, layout.text_base)

    result = assemble(source, isa=isa)
    if not result.success:
        return {}

    actual = result.symbols

    offsets = {}
    for label in estimated:
        if label in actual:
            diff = actual[label] - estimated[label]
            offsets[label] = (estimated[label], actual[label], diff)

    return offsets


# =============================================================================
# TEST CLASS: INSTRUCTION SIZE ESTIMATION
# =============================================================================

class TestInstructionSizeEstimation:
    """Tests that estimated instruction sizes match actual assembled sizes."""

    # -------------------------------------------------------------------------
    # RISC-V Tests
    # -------------------------------------------------------------------------

    def test_riscv_basic_instructions(self):
        """RISC-V basic instructions are 4 bytes each."""
        source = """
        .text
        start:
            nop
        after_nop:
            add x1, x2, x3
        after_add:
            sub x4, x5, x6
        end:
            nop
        """
        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_riscv_li_small_immediate(self):
        """RISC-V li with small immediate is 1 instruction (4 bytes)."""
        source = """
        .text
        start:
            li a0, 42
        after_li:
            nop
        """
        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_riscv_li_large_immediate(self):
        """RISC-V li with large immediate expands to lui+addi (8 bytes)."""
        source = """
        .text
        start:
            li a0, 0x12345678
        after_li:
            nop
        """
        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_riscv_la_pseudo(self):
        """RISC-V la always expands to auipc+addi (8 bytes)."""
        source = """
        .data
        value: .word 42

        .text
        start:
            la a0, value
        after_la:
            nop
        """
        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_riscv_call_pseudo(self):
        """RISC-V call may expand for far calls."""
        source = """
        .text
        start:
            call helper
        after_call:
            nop
        helper:
            ret
        """
        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    # -------------------------------------------------------------------------
    # ARM64 Tests
    # -------------------------------------------------------------------------

    def test_arm64_basic_instructions(self):
        """ARM64 basic instructions are 4 bytes each."""
        source = """
        .text
        start:
            nop
        after_nop:
            add x0, x1, x2
        after_add:
            sub x3, x4, x5
        end:
            nop
        """
        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_arm64_mov_immediate(self):
        """ARM64 mov with immediate is 4 bytes."""
        source = """
        .text
        start:
            mov x0, 42
        after_mov:
            nop
        """
        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_arm64_adr_with_symbol(self):
        """ARM64 adr with symbol may expand to movz+movk sequence."""
        source = """
        .data
        message: .asciz "Hello"

        .text
        start:
            adr x0, message
        after_adr:
            nop
        """
        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_arm64_branch_instructions(self):
        """ARM64 branch instructions are 4 bytes."""
        source = """
        .text
        start:
            b target
        after_b:
            bl target
        after_bl:
            nop
        target:
            ret
        """
        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_arm64_multiple_adr(self):
        """ARM64 multiple adr instructions - tests cumulative error."""
        source = """
        .data
        msg1: .asciz "Hello"
        msg2: .asciz "World"

        .text
        start:
            adr x0, msg1
        after_adr1:
            adr x1, msg2
        after_adr2:
            bl helper
        after_bl:
            nop
        helper:
            ret
        """
        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    # -------------------------------------------------------------------------
    # x86-64 Tests
    # -------------------------------------------------------------------------

    def test_x86_nop_instruction(self):
        """x86-64 nop is 1 byte."""
        source = """
        .text
        start:
            nop
        after_nop:
            nop
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_ret_instruction(self):
        """x86-64 ret is 1 byte."""
        source = """
        .text
        start:
            ret
        after_ret:
            nop
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_syscall_instruction(self):
        """x86-64 syscall is 2 bytes."""
        source = """
        .text
        start:
            syscall
        after_syscall:
            nop
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_jmp_instruction(self):
        """x86-64 jmp with near offset."""
        source = """
        .text
        start:
            jmp target
        after_jmp:
            nop
        target:
            ret
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_call_instruction(self):
        """x86-64 call with near offset."""
        source = """
        .text
        start:
            call helper
        after_call:
            ret
        helper:
            nop
            ret
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_conditional_jumps(self):
        """x86-64 conditional jumps."""
        source = """
        .text
        start:
            je target
        after_je:
            jne target
        after_jne:
            nop
        target:
            ret
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_mov_immediate_to_register(self):
        """x86-64 mov with immediate to 64-bit register."""
        source = """
        .text
        start:
            mov rax, 42
        after_mov:
            nop
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    @pytest.mark.skip(reason="Cross-section RIP-relative addressing not yet supported")
    def test_x86_rip_relative_lea(self):
        """x86-64 LEA with RIP-relative addressing (the known problem case)."""
        source = """
        .data
        msg: .asciz "Hello"

        .text
        start:
            lea rax, msg(%rip)
        after_lea:
            nop
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_mixed_sizes(self):
        """x86-64 mixed instruction sizes - tests cumulative error."""
        source = """
        .text
        start:
            nop
        after_nop:
            mov rax, 42
        after_mov:
            syscall
        after_syscall:
            ret
        after_ret:
            nop
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    # -------------------------------------------------------------------------
    # MIPS Tests
    # -------------------------------------------------------------------------

    def test_mips_basic_instructions(self):
        """MIPS basic instructions are 4 bytes each."""
        source = """
        .text
        start:
            nop
        after_nop:
            add $t0, $t1, $t2
        after_add:
            sub $t3, $t4, $t5
        end:
            nop
        """
        errors = verify_label_accuracy(source, "mips32")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_mips_li_small_immediate(self):
        """MIPS li with small immediate is 1 instruction (4 bytes)."""
        source = """
        .text
        start:
            li $a0, 42
        after_li:
            nop
        """
        errors = verify_label_accuracy(source, "mips32")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_mips_li_large_immediate(self):
        """MIPS li with large immediate expands to lui+ori (8 bytes)."""
        source = """
        .text
        start:
            li $a0, 0x12345678
        after_li:
            nop
        """
        errors = verify_label_accuracy(source, "mips32")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_mips_pseudo_branches(self):
        """MIPS pseudo-branches (blt, bge, etc.) expand to 2 instructions."""
        source = """
        .text
        start:
            blt $t0, $t1, target
        after_blt:
            nop
        target:
            nop
        """
        errors = verify_label_accuracy(source, "mips32")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)


# =============================================================================
# TEST CLASS: FORWARD REFERENCES
# =============================================================================

class TestForwardReferences:
    """Tests that forward references (branches to later labels) work correctly."""

    def test_riscv_forward_branch_chain(self):
        """RISC-V forward branch chain resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            beqz t0, step1
            j exit
        step1:
            beqz t1, step2
            j exit
        step2:
            beqz t2, step3
            j exit
        step3:
            li a0, 42
        exit:
            li a7, 93
            ecall
        """
        result = assemble(source, isa="riscv64")
        assert result.success, f"Assembly failed: {result.errors}"

        # Verify all labels exist and are at increasing addresses
        labels = ["_start", "step1", "step2", "step3", "exit"]
        addrs = [result.symbols[l] for l in labels]
        for i in range(len(addrs) - 1):
            assert addrs[i] < addrs[i+1], f"{labels[i]} should be before {labels[i+1]}"

        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_arm64_forward_branch_chain(self):
        """ARM64 forward branch chain resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            cbz x0, step1
            b exit
        step1:
            cbz x1, step2
            b exit
        step2:
            cbz x2, step3
            b exit
        step3:
            mov x0, 42
        exit:
            mov x8, 93
            svc 0
        """
        result = assemble(source, isa="arm64")
        assert result.success, f"Assembly failed: {result.errors}"

        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_forward_branch_chain(self):
        """x86-64 forward branch chain resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            test rax, rax
            je step1
            jmp exit
        step1:
            test rbx, rbx
            je step2
            jmp exit
        step2:
            test rcx, rcx
            je step3
            jmp exit
        step3:
            mov rax, 42
        exit:
            mov rax, 60
            syscall
        """
        result = assemble(source, isa="x86_64")
        assert result.success, f"Assembly failed: {result.errors}"

        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_mips_forward_branch_chain(self):
        """MIPS forward branch chain resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            beq $t0, $zero, step1
            j exit
        step1:
            beq $t1, $zero, step2
            j exit
        step2:
            beq $t2, $zero, step3
            j exit
        step3:
            li $a0, 42
        exit:
            li $v0, 10
            syscall
        """
        result = assemble(source, isa="mips32")
        assert result.success, f"Assembly failed: {result.errors}"

        errors = verify_label_accuracy(source, "mips32")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)


# =============================================================================
# TEST CLASS: BACKWARD REFERENCES
# =============================================================================

class TestBackwardReferences:
    """Tests that backward references (branches to earlier labels) work correctly."""

    def test_riscv_backward_loop(self):
        """RISC-V backward branch in loop resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            li t0, 5
        loop:
            addi t0, t0, -1
            bnez t0, loop
        done:
            li a7, 93
            ecall
        """
        result = assemble(source, isa="riscv64")
        assert result.success, f"Assembly failed: {result.errors}"

        assert result.symbols["_start"] < result.symbols["loop"]
        assert result.symbols["loop"] < result.symbols["done"]

        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_arm64_backward_loop(self):
        """ARM64 backward branch in loop resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            mov x0, 5
        loop:
            sub x0, x0, 1
            cbnz x0, loop
        done:
            mov x8, 93
            svc 0
        """
        result = assemble(source, isa="arm64")
        assert result.success, f"Assembly failed: {result.errors}"

        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_backward_loop(self):
        """x86-64 backward branch in loop resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            mov rcx, 5
        loop:
            dec rcx
            jnz loop
        done:
            mov rax, 60
            syscall
        """
        result = assemble(source, isa="x86_64")
        assert result.success, f"Assembly failed: {result.errors}"

        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_mips_backward_loop(self):
        """MIPS backward branch in loop resolves correctly."""
        source = """
        .text
        .globl _start
        _start:
            li $t0, 5
        loop:
            addi $t0, $t0, -1
            bne $t0, $zero, loop
        done:
            li $v0, 10
            syscall
        """
        result = assemble(source, isa="mips32")
        assert result.success, f"Assembly failed: {result.errors}"

        errors = verify_label_accuracy(source, "mips32")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)


# =============================================================================
# TEST CLASS: PSEUDO-INSTRUCTION EXPANSION
# =============================================================================

class TestPseudoInstructionExpansion:
    """Tests that pseudo-instructions expand to the correct number of bytes."""

    def test_riscv_pseudo_instruction_sizes(self):
        """Test RISC-V pseudo-instruction size estimation."""
        # Test li with small immediate (should be 4 bytes)
        source_small = """
        .text
        start:
            li a0, 5
        end:
            nop
        """
        result = assemble(source_small, isa="riscv64")
        assert result.success
        size = result.symbols["end"] - result.symbols["start"]
        assert size == 4, f"li small should be 4 bytes, got {size}"

        # Test li with large immediate (should be 8 bytes)
        source_large = """
        .text
        start:
            li a0, 0x12345678
        end:
            nop
        """
        result = assemble(source_large, isa="riscv64")
        assert result.success
        size = result.symbols["end"] - result.symbols["start"]
        assert size == 8, f"li large should be 8 bytes, got {size}"

    def test_mips_pseudo_branch_sizes(self):
        """Test MIPS pseudo-branch size estimation (blt, bge expand to 3 instrs with delay slot)."""
        for branch in ["blt", "bge", "ble", "bgt"]:
            source = f"""
            .text
            start:
                {branch} $t0, $t1, target
            middle:
                nop
            target:
                nop
            """
            result = assemble(source, isa="mips32")
            assert result.success, f"Failed to assemble {branch}"

            size = result.symbols["middle"] - result.symbols["start"]
            # Pseudo-branches: slt + bne + delay slot nop = 12 bytes
            assert size == 12, \
                f"'{branch}' should expand to 12 bytes (slt+branch+nop), got {size}"

    def test_arm64_adr_expansion(self):
        """Test ARM64 adr with symbol expands correctly."""
        source = """
        .data
        msg: .asciz "Hello"

        .text
        start:
            adr x0, msg
        end:
            nop
        """
        result = assemble(source, isa="arm64")
        assert result.success, f"Assembly failed: {result.errors}"

        # adr with far symbol should expand to movz + movk(s)
        size = result.symbols["end"] - result.symbols["start"]
        assert size >= 4, f"adr should be at least 4 bytes, got {size}"

        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)


# =============================================================================
# TEST CLASS: COMPLEX PROGRAMS (FIBONACCI-LIKE)
# =============================================================================

class TestComplexPrograms:
    """Tests with complex programs that mix forward/backward refs and pseudo-instructions."""

    def test_riscv_fibonacci_structure(self):
        """RISC-V Fibonacci-like program with mixed reference types."""
        source = """
        .text
        .globl _start
        _start:
            li a0, 7
            jal ra, fib
            j done

        fib:
            addi sp, sp, -16
            sd ra, 8(sp)
            sd a0, 0(sp)
            li t0, 1
            ble a0, t0, fib_base

            addi a0, a0, -1
            jal ra, fib
            mv t1, a0

            ld a0, 0(sp)
            addi a0, a0, -2
            jal ra, fib

            add a0, a0, t1
            j fib_ret

        fib_base:
            ld a0, 0(sp)

        fib_ret:
            ld ra, 8(sp)
            addi sp, sp, 16
            ret

        done:
            li a7, 93
            ecall
        """
        result = assemble(source, isa="riscv64")
        assert result.success, f"Assembly failed: {result.errors}"

        expected = ["_start", "fib", "fib_base", "fib_ret", "done"]
        for label in expected:
            assert label in result.symbols, f"Missing label: {label}"

        errors = verify_label_accuracy(source, "riscv64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_arm64_function_call_chain(self):
        """ARM64 with chained function calls."""
        source = """
        .text
        .globl _start
        _start:
            bl func_a
            mov x8, 93
            svc 0

        func_a:
            stp x29, x30, [sp, -16]!
            bl func_b
            ldp x29, x30, [sp], 16
            ret

        func_b:
            stp x29, x30, [sp, -16]!
            bl func_c
            ldp x29, x30, [sp], 16
            ret

        func_c:
            mov x0, 42
            ret
        """
        result = assemble(source, isa="arm64")
        assert result.success, f"Assembly failed: {result.errors}"

        expected = ["_start", "func_a", "func_b", "func_c"]
        for label in expected:
            assert label in result.symbols, f"Missing label: {label}"

        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)

    def test_x86_complex_control_flow(self):
        """x86-64 with complex control flow."""
        source = """
        .text
        .globl _start
        _start:
            mov rcx, 10

        outer:
            push rcx
            mov rcx, 5

        inner:
            test rcx, rcx
            je inner_done
            dec rcx
            jmp inner

        inner_done:
            pop rcx
            dec rcx
            jnz outer

        exit:
            mov rax, 60
            xor rdi, rdi
            syscall
        """
        result = assemble(source, isa="x86_64")
        assert result.success, f"Assembly failed: {result.errors}"

        expected = ["_start", "outer", "inner", "inner_done", "exit"]
        for label in expected:
            assert label in result.symbols, f"Missing label: {label}"

        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"Label mismatches:\n" + "\n".join(errors)


# =============================================================================
# TEST CLASS: REGRESSION TESTS FOR KNOWN ISSUES
# =============================================================================

class TestRegressions:
    """Regression tests for known issues."""

    def test_arm64_branch_after_adr(self):
        """
        ARM64: Branch after adr pseudo-instruction.

        If adr expands to multiple instructions but estimation is wrong,
        the branch target will be incorrect.
        """
        source = """
        .data
        msg: .asciz "Hello"

        .text
        _start:
            adr x0, msg
            bl done
            nop
            nop
        done:
            mov x8, 93
            svc 0
        """
        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"ARM64 branch after adr failed:\n" + "\n".join(errors)

    def test_arm64_multiple_adr_before_branch(self):
        """
        ARM64: Multiple adr instructions before branch.

        Cumulative error from multiple adr expansions.
        """
        source = """
        .data
        msg1: .asciz "Hello"
        msg2: .asciz "World"

        .text
        _start:
            adr x0, msg1
            adr x1, msg2
            bl target
            nop
        target:
            ret
        """
        errors = verify_label_accuracy(source, "arm64")
        assert not errors, f"ARM64 multiple adr failed:\n" + "\n".join(errors)

    @pytest.mark.skip(reason="Cross-section RIP-relative addressing not yet supported")
    def test_x86_rip_relative_before_call(self):
        """
        x86-64: RIP-relative LEA before call instruction.

        LEA with RIP-relative addressing is 7 bytes, not 5.
        """
        source = """
        .data
        msg: .asciz "Hello"

        .text
        _start:
            lea rax, msg(%rip)
            call helper
            ret
        helper:
            nop
            ret
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"x86-64 RIP-relative before call failed:\n" + "\n".join(errors)

    def test_x86_mixed_instruction_sizes(self):
        """
        x86-64: Mixed instruction sizes before branch.

        Variable-length instructions followed by a branch can cause
        incorrect offset calculation if sizes are wrong.
        """
        source = """
        .text
        _start:
            nop
            mov rax, 42
            push rax
            pop rbx
            syscall
            jmp target
        between:
            nop
            nop
        target:
            ret
        """
        errors = verify_label_accuracy(source, "x86_64")
        assert not errors, f"x86-64 mixed sizes failed:\n" + "\n".join(errors)

    def test_mips_pseudo_branch_target(self):
        """
        MIPS: Pseudo-branch (blt/bge) with forward target.

        Pseudo-branches expand to 2 instructions, so the target offset
        must account for this expansion.
        """
        source = """
        .text
        _start:
            li $t0, 5
            li $t1, 10
            blt $t0, $t1, less
            li $a0, 0
            j done
        less:
            li $a0, 1
        done:
            li $v0, 10
            syscall
        """
        result = assemble(source, isa="mips32")
        assert result.success, f"Assembly failed: {result.errors}"

        errors = verify_label_accuracy(source, "mips32")
        assert not errors, f"MIPS pseudo-branch failed:\n" + "\n".join(errors)


# =============================================================================
# TEST CLASS: DIAGNOSTIC OUTPUT
# =============================================================================

class TestDiagnosticReport:
    """Generate diagnostic reports to understand failures."""

    def test_generate_size_report(self):
        """Generate a report of size estimation accuracy for all ISAs."""
        # Programs with varied instruction types
        programs = {
            "riscv64": """
            .text
            start: nop
            l1: li a0, 5
            l2: li a0, 0x12345678
            l3: jal ra, start
            l4: beqz t0, start
            end: nop
            """,
            "arm64": """
            .data
            msg: .asciz "x"
            .text
            start: nop
            l1: mov x0, 5
            l2: adr x1, msg
            l3: bl start
            l4: cbz x0, start
            end: nop
            """,
            "x86_64": """
            .text
            start: nop
            l1: mov rax, 42
            l2: call start
            l3: je start
            l4: jmp start
            end: nop
            """,
            "mips32": """
            .text
            start: nop
            l1: li $a0, 5
            l2: li $a0, 0x12345678
            l3: jal start
            l4: beq $t0, $zero, start
            end: nop
            """,
        }

        all_errors = []
        for isa, source in programs.items():
            errors = verify_label_accuracy(source, isa)
            if errors:
                all_errors.append(f"\n{isa.upper()} size estimation errors:")
                for err in errors:
                    all_errors.append(f"  {err}")

        if all_errors:
            # This test intentionally fails to show all issues at once
            pytest.fail("\n".join(all_errors))


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
