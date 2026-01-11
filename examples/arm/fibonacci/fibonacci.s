# ============================================================================
# ARM64 Assembly: Recursive Fibonacci Calculator
# ============================================================================
#
# This program demonstrates recursive function calls in ARM64 assembly.
# It calculates the nth Fibonacci number using recursion.
#
# Fibonacci sequence: F(0)=0, F(1)=1, F(n)=F(n-1)+F(n-2) for n>1
# Example: F(7) = 13 (sequence: 0,1,1,2,3,5,8,13,...)
#
# Learning objectives:
# - Recursive function implementation
# - Stack frame management (push/pop)
# - ARM64 calling convention (x0-x7, x30/LR, sp)
# - Base case and recursive case handling
# - Register save/restore conventions
# ============================================================================
.isa arm64


.section .data
    # Input value: calculate Fibonacci(7)
    fib_input:
        .word 7

    # Storage for result
    fib_result:
        .word 0

.section .text
.globl _start

_start:
    # Load the input value
    adr     x1, fib_input
    ldr     w0, [x1]            # x0 = n (input argument)

    # Call fibonacci function
    bl      fibonacci           # result will be in x0

    # Store the result
    adr     x1, fib_result
    str     w0, [x1]            # save result to memory

    # Print result
    mov     x8, #1              # syscall 1 = print_int
    svc     #0

    # Print newline
    mov     x0, #10
    mov     x8, #11             # syscall 11 = print_char
    svc     #0

    # Exit via syscall
    mov     x8, #10             # syscall 10 = exit
    svc     #0

# ============================================================================
# Function: fibonacci
# Purpose: Recursively calculates the nth Fibonacci number
#
# Mathematical definition:
#   F(0) = 0
#   F(1) = 1
#   F(n) = F(n-1) + F(n-2) for n > 1
#
# ARM64 Calling Convention:
#   Arguments: x0 = n (which Fibonacci number to calculate)
#   Returns:   x0 = F(n) (the nth Fibonacci number)
#   Saved:     x30/LR (link register), x19 (callee-saved register)
#
# Stack frame layout (when needed):
#   sp+0:  saved x0 (original n value)
#   sp+16: saved x19 and x30/LR
#   Total: 32 bytes (16-byte aligned)
# ============================================================================
fibonacci:
    # Base case 1: if n == 0, return 0
    cbz     x0, base_case_zero

    # Base case 2: if n == 1, return 1
    cmp     x0, #1
    b.eq    base_case_one

    # Recursive case: n > 1
    # We need to save registers and make recursive calls
    # Save x30/LR (return address), x19 (for intermediate result), and x0 (n)
    sub     sp, sp, #32         # allocate stack frame (32 bytes, 16-byte aligned)
    stp     x19, x30, [sp, #16] # save x19 and LR
    str     x0, [sp]            # save n

    # First recursive call: fibonacci(n-1)
    sub     x0, x0, #1          # x0 = n - 1
    bl      fibonacci           # call fibonacci(n-1)
    mov     x19, x0             # x19 = F(n-1) (save result)

    # Second recursive call: fibonacci(n-2)
    ldr     x0, [sp]            # restore original n
    sub     x0, x0, #2          # x0 = n - 2
    bl      fibonacci           # call fibonacci(n-2)

    # Add the two results: F(n) = F(n-1) + F(n-2)
    add     x0, x19, x0         # x0 = F(n-1) + F(n-2)

    # Restore saved registers and return
    ldp     x19, x30, [sp, #16] # restore x19 and LR
    add     sp, sp, #32         # deallocate stack frame
    ret                         # return to caller

base_case_zero:
    # F(0) = 0
    mov     x0, #0              # return 0
    ret

base_case_one:
    # F(1) = 1
    mov     x0, #1              # return 1
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

# ============================================================================
# ARM64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              ARM64
#   ------              -----
#   beqz a0, label      cbz  x0, label       (branch if zero)
#   beq  a0, t0, label  cmp + b.eq           (compare + branch)
#   jal  ra, func       bl   func            (function call)
#   sd   ra, 16(sp)     stp  x19, x30, [sp]  (store pair)
#   ld   ra, 16(sp)     ldp  x19, x30, [sp]  (load pair)
#   addi sp, sp, -24    sub  sp, sp, #32     (allocate stack)
#   ret                 ret                   (return)
#
# ============================================================================
# EXERCISES FOR STUDENTS
# ============================================================================
#
# 1. Change the input value and verify the result
# 2. Add code to count the total number of function calls
# 3. Implement an iterative (non-recursive) version
# 4. Modify to calculate factorial instead of Fibonacci
#
# ============================================================================
