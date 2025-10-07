# Simple RISC-V Test Program
# Purpose: Predictable instruction-by-instruction behavior for testing
#
# Expected behavior:
#   Step 1: addi x5, x0, 10    -> x5 = 10 (0xa)
#   Step 2: addi x6, x0, 20    -> x6 = 20 (0x14)
#   Step 3: add  x7, x5, x6    -> x7 = 30 (0x1e)
#   Step 4: sub  x8, x7, x5    -> x8 = 20 (0x14)
#   Step 5: slli x9, x5, 2     -> x9 = 40 (0x28)
#   Step 6: addi x10, x0, 42   -> x10 = 42 (0x2a) - exit code
#   Step 7: j done             -> jump to done
#   Step 8: addi x1, x0, 93    -> ecall exit
#   Step 9: ecall

.section .text
.globl _start

_start:
    # Step 1: Load immediate 10 into x5 (t0)
    addi x5, x0, 10         # x5 = 10

    # Step 2: Load immediate 20 into x6 (t1)
    addi x6, x0, 20         # x6 = 20

    # Step 3: Add x5 + x6 -> x7
    add  x7, x5, x6         # x7 = 30

    # Step 4: Subtract x7 - x5 -> x8
    sub  x8, x7, x5         # x8 = 20

    # Step 5: Shift x5 left by 2 -> x9
    slli x9, x5, 2          # x9 = 40

    # Step 6: Set return value
    addi x10, x0, 42        # a0 = 42 (return code)

    # Step 7: Jump to done
    j done

done:
    # Step 8-9: Exit via ecall
    addi x1, x0, 93         # syscall number for exit
    ecall
