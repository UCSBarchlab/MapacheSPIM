# ============================================================================
# x86-64 Assembly: Recursive Fibonacci Calculator
# ============================================================================
#
# This program demonstrates recursive function calls in x86-64 assembly.
# It calculates the nth Fibonacci number using recursion.
#
# Fibonacci sequence: F(0)=0, F(1)=1, F(n)=F(n-1)+F(n-2) for n>1
# Example: F(7) = 13 (sequence: 0,1,1,2,3,5,8,13,...)
#
# Learning objectives:
# - Recursive function implementation
# - Stack frame management (push/pop)
# - System V AMD64 calling convention (rdi, rsi, rdx, rcx, r8, r9)
# - Base case and recursive case handling
# - Callee-saved register preservation
# ============================================================================
.isa x86_64


.section .data
    # Input value: calculate Fibonacci(7)
    .globl fib_input
    fib_input:
        .long 7

    # Storage for result
    .globl fib_result
    fib_result:
        .long 0

.section .text
.globl _start

_start:
    # Load the input value
    lea     fib_input(%rip), %rax
    movl    (%rax), %edi            # edi = n (first argument)

    # Call fibonacci function
    call    fibonacci               # result will be in eax

    # Store the result
    lea     fib_result(%rip), %rcx
    movl    %eax, (%rcx)            # save result to memory

    # Print result
    movq    %rax, %rdi              # move result to rdi for print_int
    movq    $1, %rax                # syscall 1 = print_int
    syscall

    # Print newline
    movq    $10, %rdi
    movq    $11, %rax               # syscall 11 = print_char
    syscall

    # Exit via SPIM-compatible syscall
    mov     $10, %rax               # syscall 10 = exit
    syscall

# ============================================================================
# Function: fibonacci
# Purpose: Recursively calculates the nth Fibonacci number
#
# Mathematical definition:
#   F(0) = 0
#   F(1) = 1
#   F(n) = F(n-1) + F(n-2) for n > 1
#
# System V AMD64 Calling Convention:
#   Arguments: edi = n (which Fibonacci number to calculate)
#   Returns:   eax = F(n) (the nth Fibonacci number)
#   Callee-saved: rbx, rbp, r12-r15
#
# Stack frame layout (when needed):
#   rbp-8:  saved original n
#   rbp-16: saved F(n-1) result
#   (rbp points to saved rbp, return address above it)
# ============================================================================
fibonacci:
    # Base case 1: if n == 0, return 0
    testl   %edi, %edi
    jz      base_case_zero

    # Base case 2: if n == 1, return 1
    cmpl    $1, %edi
    je      base_case_one

    # Recursive case: n > 1
    # Set up stack frame
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx                    # save callee-saved register
    pushq   %r12                    # save another callee-saved register

    # Save n in r12 (callee-saved)
    movl    %edi, %r12d

    # First recursive call: fibonacci(n-1)
    subl    $1, %edi                # edi = n - 1
    call    fibonacci               # call fibonacci(n-1)
    movl    %eax, %ebx              # ebx = F(n-1) (save result)

    # Second recursive call: fibonacci(n-2)
    movl    %r12d, %edi             # restore original n
    subl    $2, %edi                # edi = n - 2
    call    fibonacci               # call fibonacci(n-2)

    # Add the two results: F(n) = F(n-1) + F(n-2)
    addl    %ebx, %eax              # eax = F(n-1) + F(n-2)

    # Restore saved registers and return
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

base_case_zero:
    # F(0) = 0
    xorl    %eax, %eax              # return 0
    ret

base_case_one:
    # F(1) = 1
    movl    $1, %eax                # return 1
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
# x86-64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              x86-64 (AT&T syntax)
#   ------              --------------------
#   beqz a0, label      testl %edi, %edi + jz   (test and jump if zero)
#   beq  a0, t0, label  cmpl $1, %edi + je      (compare + jump)
#   jal  ra, func       call func               (function call)
#   sd   ra, 16(sp)     pushq %rbp              (save to stack)
#   ld   ra, 16(sp)     popq %rbp               (restore from stack)
#   addi sp, sp, -24    (automatic via push)    (stack allocation)
#   ret                 ret                      (return)
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
