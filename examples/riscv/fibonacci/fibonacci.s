# ============================================================================
# RISC-V 64-bit Assembly: Recursive Fibonacci Calculator
# ============================================================================
#
# This program demonstrates recursive function calls in RISC-V assembly.
# It calculates the nth Fibonacci number using recursion.
#
# Fibonacci sequence: F(0)=0, F(1)=1, F(n)=F(n-1)+F(n-2) for n>1
# Example: F(7) = 13 (sequence: 0,1,1,2,3,5,8,13,...)
#
# Learning objectives:
# - Recursive function implementation
# - Stack frame management (push/pop)
# - RISC-V calling convention (a0-a7, ra, sp)
# - Base case and recursive case handling
# - Register save/restore conventions
# ============================================================================
.isa riscv64


.section .data
    # Input value: calculate Fibonacci(7)
    fib_input:
        .word 7

    # Storage for result
    fib_result:
        .word 0

.section .bss
    # Stack space (4KB)
    .align 4
    _stack_bottom:
        .space 4096
    _stack_start:

.section .text
.globl _start

_start:
    # Initialize stack pointer (required for recursive calls)
    la      sp, _stack_start    # sp = top of stack

    # Load the input value
    la      t0, fib_input
    lw      a0, 0(t0)           # a0 = n (input argument)

    # Call fibonacci function
    jal     ra, fibonacci       # result will be in a0

    # Store the result
    la      t0, fib_result
    sw      a0, 0(t0)           # save result to memory

    # Exit program using HTIF (write to tohost)
    li      t0, 1               # exit code 1 (success)
    la      t1, tohost          # load address of tohost
    sd      t0, 0(t1)           # write to tohost to signal exit

exit_loop:
    # Infinite loop - emulator will detect tohost write and stop
    j       exit_loop

# ============================================================================
# Function: fibonacci
# Purpose: Recursively calculates the nth Fibonacci number
#
# Mathematical definition:
#   F(0) = 0
#   F(1) = 1
#   F(n) = F(n-1) + F(n-2) for n > 1
#
# RISC-V Calling Convention:
#   Arguments: a0 = n (which Fibonacci number to calculate)
#   Returns:   a0 = F(n) (the nth Fibonacci number)
#   Saved:     ra (return address), s0 (saved register)
#
# Stack frame layout (when needed):
#   sp+0:  saved s0 (saved register for intermediate results)
#   sp+8:  saved ra (return address)
#   sp+16: saved a0 (original n value)
#   Total: 24 bytes
# ============================================================================
fibonacci:
    # Base case 1: if n == 0, return 0
    beqz    a0, base_case_zero

    # Base case 2: if n == 1, return 1
    li      t0, 1
    beq     a0, t0, base_case_one

    # Recursive case: n > 1
    # We need to save registers and make recursive calls
    # Save ra (return address), s0 (for intermediate result), and a0 (n)
    addi    sp, sp, -24         # allocate stack frame
    sd      ra, 16(sp)          # save return address
    sd      s0, 8(sp)           # save s0 (we'll use it for temp storage)
    sd      a0, 0(sp)           # save n

    # First recursive call: fibonacci(n-1)
    addi    a0, a0, -1          # a0 = n - 1
    jal     ra, fibonacci       # call fibonacci(n-1)
    mv      s0, a0              # s0 = F(n-1) (save result)

    # Second recursive call: fibonacci(n-2)
    ld      a0, 0(sp)           # restore original n
    addi    a0, a0, -2          # a0 = n - 2
    jal     ra, fibonacci       # call fibonacci(n-2)

    # Add the two results: F(n) = F(n-1) + F(n-2)
    add     a0, s0, a0          # a0 = F(n-1) + F(n-2)

    # Restore saved registers and return
    ld      ra, 16(sp)          # restore return address
    ld      s0, 8(sp)           # restore s0
    addi    sp, sp, 24          # deallocate stack frame
    ret                         # return to caller

base_case_zero:
    # F(0) = 0
    li      a0, 0               # return 0
    ret

base_case_one:
    # F(1) = 1
    li      a0, 1               # return 1
    ret

# ============================================================================
# Execution trace for fibonacci(3):
#
# Call fibonacci(3):
#   Not base case, make recursive calls
#   Call fibonacci(2):
#     Not base case, make recursive calls
#     Call fibonacci(1): returns 1
#     Call fibonacci(0): returns 0
#     Return 1 + 0 = 1
#   Call fibonacci(1): returns 1
#   Return 1 + 1 = 2
#
# Therefore: F(3) = 2
# Similarly: F(7) = 13
# ============================================================================

# ============================================================================
# Expected Results:
# Input: n = 7
# Output: F(7) = 13
#
# Fibonacci sequence reference:
# F(0)=0, F(1)=1, F(2)=1, F(3)=2, F(4)=3, F(5)=5, F(6)=8, F(7)=13
# ============================================================================

# HTIF (Host-Target Interface) section for Sail emulator
.section .tohost,"aw",@progbits
.align 6
.globl tohost
tohost: .dword 0
.align 6
.globl fromhost
fromhost: .dword 0
