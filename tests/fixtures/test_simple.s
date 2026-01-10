# Test fixture program for unit tests
# This program has a specific instruction sequence expected by the tests
#
# Memory layout:
#   0x80000000: addi x5, x0, 10    - Sets t0 = 10
#   0x80000004: addi x6, x0, 20    - Sets t1 = 20
#   0x80000008: add  x7, x5, x6    - Sets t2 = t0 + t1 = 30
#   0x8000000c: sub  x8, x6, x5    - Sets s0 = t1 - t0 = 10
#   0x80000010: li   s0, 21        - Sets s0 = 21
#   0x80000014: j    .+8           - Jump to 0x8000001c (skip nop)
#   0x80000018: addi x0, x0, 0     - nop (should be skipped)
#   0x8000001c: sub  s0, s0, 1     - s0 = s0 - 1 = 20
#   0x80000020: li   ra, 93        - Sets ra = 93 (test marker)
#   0x80000024: li   a7, 10        - Syscall 10 = exit
#   0x80000028: ecall              - Exit program

    .text
    .globl _start

_start:
    addi    t0, zero, 10        # x5 = 10
    addi    t1, zero, 20        # x6 = 20
    add     t2, t0, t1          # x7 = 30
    sub     s0, t1, t0          # x8 = 10
    li      s0, 21              # s0 = 21
    jal     zero, 8             # Jump forward 8 bytes (skip nop)
    nop                         # This should be skipped
    addi    s0, s0, -1          # s0 = 20 (21 - 1)
    li      ra, 93              # ra = 93 (test marker)
    li      a7, 10              # syscall 10 = exit
    ecall                       # Exit
