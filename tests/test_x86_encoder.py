"""
Unit tests for the built-in x86-64 encoder that complement the GNU
differential tests (test_differential_x86.py), which need binutils.
"""

import unittest

from mapachespim.toolchain import assemble
from mapachespim.toolchain.x86 import X86EncodeError, encode

PC = 0x400000

# Encodings produced by GNU as (x86_64-linux-gnu-as --64)
GNU_ENCODINGS = [
    ("movq $60, %rax", "48c7c03c000000"),
    ("movl $42, %edi", "bf2a000000"),
    ("syscall", "0f05"),
    ("addq %rbx, %rax", "4801d8"),
    ("leaq 8(%rsp,%rcx,4), %rdx", "488d548c08"),
    ("movb %sil, (%r12)", "41883424"),
    ("pushq %r15", "4157"),
    ("popq %rbp", "5d"),
    ("imulq $1000, %rcx, %rdx", "4869d1e8030000"),
    ("shrl $3, %eax", "c1e803"),
    ("cmpb $0x7f, %al", "3c7f"),
    ("movabsq $0x123456789abcdef0, %r10", "49baf0debc9a78563412"),
    ("movzbl (%rdi), %eax", "0fb607"),
    ("movslq %ecx, %rax", "4863c1"),
    ("sete %al", "0f94c0"),
    ("cmovlq %rbx, %rax", "480f4cc3"),
    ("ret", "c3"),
    # GNU special cases
    ("xchg %rax, %rax", "90"),
    ("xchg %eax, %eax", "87c0"),
    ("sbbb $-129, %bpl", "4080dd7f"),  # truncated to 8 bits, like GNU
]


class TestKnownEncodings(unittest.TestCase):
    def test_matches_gnu(self):
        for text, expected in GNU_ENCODINGS:
            with self.subTest(text):
                self.assertEqual(encode(text, PC, {}).hex(), expected)

    def test_intel_syntax_matches_att(self):
        pairs = [
            ("mov rax, 60", "movq $60, %rax"),
            ("add rax, rbx", "addq %rbx, %rax"),
            ("lea rdx, [rsp + rcx*4 + 8]", "leaq 8(%rsp,%rcx,4), %rdx"),
            ("mov byte ptr [r12], sil", "movb %sil, (%r12)"),
            ("imul rdx, rcx, 1000", "imulq $1000, %rcx, %rdx"),
        ]
        for intel, att in pairs:
            with self.subTest(intel):
                self.assertEqual(encode(intel, PC, {}), encode(att, PC, {}))

    def test_suffix_with_bare_symbol_operand_is_att(self):
        # No '%' or '$', but the size suffix only exists in AT&T syntax;
        # a bare symbol is an absolute address, as in GNU as
        self.assertEqual(encode("imulq value", PC, {"value": 0x500000}).hex(), "48f72c2500005000")


class TestErrors(unittest.TestCase):
    def test_ambiguous_size_is_rejected(self):
        with self.assertRaisesRegex(X86EncodeError, "operand size"):
            encode("inc (%rax)", PC, {})

    def test_invalid_combinations(self):
        for text in ("movq (%rax), (%rbx)", "addq %rax, %ebx", "movb %ah, %sil"):
            with self.subTest(text), self.assertRaises(X86EncodeError):
                encode(text, PC, {})


def _text(source: str) -> bytes:
    result = assemble(source, isa="x86_64")
    assert result.success, result.errors
    return result.elf_bytes


class TestJumpRelaxation(unittest.TestCase):
    """Jumps start short (rel8) and only grow to rel32 when out of range."""

    def _program(self, pad: int) -> str:
        return f"""
        .globl _start
        _start:
            jmp target
            .fill {pad}, 1, 0x90
        target:
            ret
        """

    def test_boundary(self):
        from io import BytesIO

        from elftools.elf.elffile import ELFFile

        def text(pad):
            elf = ELFFile(BytesIO(_text(self._program(pad))))
            return elf.get_section_by_name(".text").data()

        self.assertEqual(text(127)[:2].hex(), "eb7f")  # furthest short jump
        self.assertEqual(text(128)[:5].hex(), "e980000000")  # needs rel32


if __name__ == "__main__":
    unittest.main()
