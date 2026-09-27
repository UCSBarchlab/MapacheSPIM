"""
Differential tests for data directives: .data built by MapacheSPIM must be
byte-identical to GNU as, for every ISA with a built-in assembler.

These caught several bugs: .align meaning n bytes instead of 2**n, MIPS data
in the wrong byte order when the ISA came from --isa, labels in .word
becoming 0, and "\\xff" in strings emitting two bytes.
"""

import pytest

from .gnu_reference import gnu_assemble, gnu_available, ours_text, trim_padding

ISAS = [isa for isa in ("riscv64", "mips32") if gnu_available(isa)]
pytestmark = pytest.mark.skipif(not ISAS, reason="GNU binutils not installed")

DATA_PROGRAM = r"""
.text
.globl _start
_start:
    nop
.data
bytes:   .byte 1, 2, 0xff, -1, 'A', 'z', 0b101, 010
.align 2
halves:  .half 1, -2, 0x1234, 65535
.align 3
words:   .word 1, -1, 0x12345678, 0xffffffff, 1+2<<3, (1+2)<<3, ~0, 17 % 5, -7 / 2
table:   .word bytes, halves, words, table+4, end - bytes
.align 3
quads:   .dword 0x123456789abcdef0, -2
strings: .ascii "abc"
len = . - strings
         .asciz "with\nescapes\t\\ \"quoted\" \x41\x7f\xff \101\60"
         .string "two", "strings"
.balign 8
space:   .space 5
         .space 3, 0xaa
.p2align 4
         .skip 2
# MIPS aligns this .word (and moves the label) automatically
lens:    .word len, SIZE * 2
.equ SIZE, 12
         .byte 3
end:     .word 0
"""


@pytest.mark.parametrize("isa", ISAS)
def test_data_section_matches_gnu(isa):
    ours, errors, _ = ours_text(isa, DATA_PROGRAM, ".data")
    assert not errors, errors
    gnu = trim_padding(gnu_assemble(isa, DATA_PROGRAM, ".data"), ours)
    assert ours == gnu, f"\nours {ours.hex()}\ngnu  {gnu.hex()}"


@pytest.mark.parametrize("isa", ISAS)
def test_code_alignment_matches_gnu(isa):
    source = """
.text
.globl _start
_start:
    nop
.align 4
aligned:
    nop
.balign 8
    nop
"""
    ours, errors, _ = ours_text(isa, source)
    assert not errors, errors
    gnu = trim_padding(gnu_assemble(isa, source), ours)
    assert ours == gnu, f"\nours {ours.hex()}\ngnu  {gnu.hex()}"
