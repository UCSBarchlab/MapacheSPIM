# Test fixture program for unit tests
# This program has a specific instruction sequence expected by the tests
#
# Memory layout (as expected by test_disasm_comprehensive.py):
#   0x80000000: addi t0, zero, 10   - li t0, 10
#   0x80000004: addi t1, zero, 20   - li t1, 20
#   0x80000008: add  t2, t0, t1     - add t2, t0, t1
#   0x8000000c: sub  s0, t2, t0     - sub s0, t2, t0
#   0x80000010: slli s1, t0, 2      - slli s1, t0, 2
#   0x80000014: addi a0, zero, 42   - li a0, 42
#   0x80000018: j    +4             - jump forward 4 bytes to 0x8000001c
#   0x8000001c: addi ra, zero, 93   - li ra, 93
#   0x80000020: ecall               - exit

    .text
    .globl _start

_start:
    addi    t0, zero, 10        # x5 = 10
    addi    t1, zero, 20        # x6 = 20
    add     t2, t0, t1          # x7 = 30
    sub     s0, t2, t0          # x8 = 20
    slli    s1, t0, 2           # x9 = 40
    addi    a0, zero, 42        # a0 = 42
    jal     zero, 4             # jump forward 4 bytes
    addi    ra, zero, 93        # ra = 93 (test marker)
    ecall                       # Exit (syscall 10 expected in a7)
