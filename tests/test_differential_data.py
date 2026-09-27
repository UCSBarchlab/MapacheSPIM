"""
Differential tests for data directives: .data built by MapacheSPIM must be
byte-identical to GNU as, for every ISA with a built-in assembler.

These caught several bugs: .align meaning n bytes instead of 2**n, MIPS data
in the wrong byte order when the ISA came from --isa, labels in .word
becoming 0, and "\\xff" in strings emitting two bytes.
"""

import pytest

from .gnu_reference import gnu_assemble, gnu_available, ours_text, trim_padding

ISAS = [isa for isa in ("riscv64", "mips32", "arm64", "x86_64") if gnu_available(isa)]
pytestmark = pytest.mark.skipif(not ISAS, reason="GNU binutils not installed")

DATA_PROGRAM = r"""
.text
.globl _start
_start:
    nop
.data
bytes:   .byte 1, 2, 0xff, -1, 'A', 'z', 0b101, 010
{align4}
halves:  .short 1, -2, 0x1234, 65535
{align8}
words:   .word 1, -1, 0x12345678, 0xffffffff, 1+2<<3, (1+2)<<3, ~0, 17 % 5, -7 / 2
table:   .long bytes, halves, words, table+4, end - bytes
{align8}
quads:   .quad 0x123456789abcdef0, -2
strings: .ascii "abc"
len = . - strings
         .asciz "with\nescapes\t\\ \"quoted\" \x41\x7f\xff \101\60"
         .string "two", "strings"
.balign 8
space:   .space 5
         .space 3, 0xaa
.p2align 4
         .skip 2
fills:   .fill 3, 1, 0x1ff
         .fill 2, 3, 0x123456
         .fill 1, 8, -1
         .fill 1, 7, 0x11
# MIPS aligns this .long (and moves the label) automatically
lens:    .long len, SIZE * 2
.equ SIZE, 12
         .byte 3
end:     .long 0
"""


@pytest.mark.parametrize("isa", ISAS)
def test_data_section_matches_gnu(isa):
    # .align n means n bytes on x86 but 2**n bytes elsewhere
    x86 = isa == "x86_64"
    source = DATA_PROGRAM.replace("{align4}", ".align 4" if x86 else ".align 2")
    source = source.replace("{align8}", ".align 8" if x86 else ".align 3")
    ours, errors, _ = ours_text(isa, source, ".data")
    assert not errors, errors
    gnu = trim_padding(gnu_assemble(isa, source, ".data"), ours)
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
