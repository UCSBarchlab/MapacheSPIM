# ============================================================================
# MIPS Assembly: Recursive Fibonacci Calculator
# ============================================================================
#
# This program demonstrates recursive function calls in MIPS assembly.
# It calculates the nth Fibonacci number using recursion.
#
# Fibonacci sequence: F(0)=0, F(1)=1, F(n)=F(n-1)+F(n-2) for n>1
# Example: F(7) = 13 (sequence: 0,1,1,2,3,5,8,13,...)
#
# Learning objectives:
# - Recursive function implementation
# - Stack frame management (push/pop)
# - MIPS calling convention ($a0-$a3, $v0-$v1, $ra)
# - Base case and recursive case handling
# - Callee-saved register preservation ($s0-$s7)
# ============================================================================
.isa mips32


.section .data
    # Input value: calculate Fibonacci(7)
    .globl fib_input
    fib_input:
        .word 7

    # Storage for result
    .globl fib_result
    fib_result:
        .word 0

.section .text
.globl _start

_start:
    # Load the input value
    la      $t0, fib_input
    lw      $a0, 0($t0)         # $a0 = n (first argument)

    # Call fibonacci function
    jal     fibonacci           # result will be in $v0

    # Store the result
    la      $t0, fib_result
    sw      $v0, 0($t0)         # save result to memory

    # Print result
    move    $a0, $v0            # move result to $a0 for print_int
    li      $v0, 1              # syscall 1 = print_int
    syscall

    # Print newline
    li      $a0, 10
    li      $v0, 11             # syscall 11 = print_char
    syscall

    # Exit via syscall
    li      $v0, 10             # syscall 10 = exit
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
# MIPS Calling Convention:
#   Arguments: $a0 = n (which Fibonacci number to calculate)
#   Returns:   $v0 = F(n) (the nth Fibonacci number)
#   Callee-saved: $s0-$s7, $ra
#
# Stack frame layout:
#   sp+8:  saved $s1 (F(n-1) result)
#   sp+4:  saved $s0 (original n)
#   sp+0:  saved $ra (return address)
# ============================================================================
fibonacci:
    # Base case 1: if n == 0, return 0
    beq     $a0, $zero, base_case_zero

    # Base case 2: if n == 1, return 1
    li      $t0, 1
    beq     $a0, $t0, base_case_one

    # Recursive case: n > 1
    # Set up stack frame - save $ra, $s0, $s1
    addi    $sp, $sp, -12       # allocate 12 bytes on stack
    sw      $ra, 0($sp)         # save return address
    sw      $s0, 4($sp)         # save $s0 (we'll use it for n)
    sw      $s1, 8($sp)         # save $s1 (we'll use it for F(n-1))

    # Save n in $s0 (callee-saved)
    move    $s0, $a0

    # First recursive call: fibonacci(n-1)
    addi    $a0, $s0, -1        # $a0 = n - 1
    jal     fibonacci           # call fibonacci(n-1)
    move    $s1, $v0            # $s1 = F(n-1) (save result)

    # Second recursive call: fibonacci(n-2)
    addi    $a0, $s0, -2        # $a0 = n - 2
    jal     fibonacci           # call fibonacci(n-2)

    # Add the two results: F(n) = F(n-1) + F(n-2)
    add     $v0, $s1, $v0       # $v0 = F(n-1) + F(n-2)

    # Restore saved registers and return
    lw      $ra, 0($sp)         # restore return address
    lw      $s0, 4($sp)         # restore $s0
    lw      $s1, 8($sp)         # restore $s1
    addi    $sp, $sp, 12        # deallocate stack frame
    jr      $ra                 # return

base_case_zero:
    # F(0) = 0
    li      $v0, 0              # return 0
    jr      $ra

base_case_one:
    # F(1) = 1
    li      $v0, 1              # return 1
    jr      $ra

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
# MIPS vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              MIPS
#   ------              ----
#   beqz a0, label      beq $a0, $zero, label  (branch if zero)
#   beq  a0, t0, label  beq $a0, $t0, label    (branch if equal)
#   jal  ra, func       jal func               (jump and link)
#   sd   ra, 16(sp)     sw  $ra, 0($sp)        (save to stack)
#   ld   ra, 16(sp)     lw  $ra, 0($sp)        (load from stack)
#   addi sp, sp, -24    addi $sp, $sp, -12     (stack allocation)
#   ret                 jr  $ra                 (return)
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
