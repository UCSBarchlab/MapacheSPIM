# ============================================================================
# RISC-V 64-bit Assembly: 3x3 Matrix Multiplication
# ============================================================================
#
# This program demonstrates matrix multiplication in RISC-V assembly.
# It multiplies two 3x3 matrices (A and B) and stores the result in matrix C.
#
# Algorithm: C[i][j] = sum(A[i][k] * B[k][j]) for k = 0 to 2
#
# Learning objectives:
# - Nested loops in assembly
# - Memory addressing with base+offset
# - Register allocation and management
# - RISC-V calling convention
# ============================================================================
.isa riscv64


.section .data
    # Matrix A (3x3) - stored in row-major order
    # [ 1  2  3 ]
    # [ 4  5  6 ]
    # [ 7  8  9 ]
    matrix_a:
        .word 1, 2, 3
        .word 4, 5, 6
        .word 7, 8, 9

    # Matrix B (3x3) - stored in row-major order
    # [ 9  8  7 ]
    # [ 6  5  4 ]
    # [ 3  2  1 ]
    matrix_b:
        .word 9, 8, 7
        .word 6, 5, 4
        .word 3, 2, 1

    # Result matrix C (3x3) - initialized to zeros
    matrix_c:
        .word 0, 0, 0
        .word 0, 0, 0
        .word 0, 0, 0

.section .text
.globl _start

_start:
    # Initialize stack pointer (required for function calls)
    la      sp, _stack_start    # sp = top of stack

    # Load base addresses of matrices into registers
    la      a0, matrix_a        # a0 = address of matrix A
    la      a1, matrix_b        # a1 = address of matrix B
    la      a2, matrix_c        # a2 = address of matrix C

    # Call matrix multiply function
    jal     ra, matrix_multiply

    # Exit program using HTIF (write to tohost)
    li      t0, 1               # exit code 1 (success)
    la      t1, tohost          # load address of tohost
    sd      t0, 0(t1)           # write to tohost to signal exit

exit_loop:
    # Infinite loop - emulator will detect tohost write and stop
    j       exit_loop

# ============================================================================
# Function: matrix_multiply
# Purpose: Multiplies two 3x3 matrices
# Arguments:
#   a0 = address of matrix A
#   a1 = address of matrix B
#   a2 = address of matrix C (result)
# Returns: nothing (result stored in matrix C)
# Registers used:
#   t0 = outer loop counter (i)
#   t1 = middle loop counter (j)
#   t2 = inner loop counter (k)
#   t3 = temporary for accumulator
#   t4 = temporary for A[i][k]
#   t5 = temporary for B[k][j]
#   t6 = temporary address calculations
# ============================================================================
matrix_multiply:
    # Save callee-saved registers (following RISC-V convention)
    addi    sp, sp, -32
    sd      s0, 0(sp)
    sd      s1, 8(sp)
    sd      s2, 16(sp)
    sd      ra, 24(sp)

    # Save matrix addresses in saved registers
    mv      s0, a0              # s0 = matrix A address
    mv      s1, a1              # s1 = matrix B address
    mv      s2, a2              # s2 = matrix C address

    # Initialize outer loop: i = 0
    li      t0, 0               # t0 = i (row index)

outer_loop:
    li      t6, 3
    bge     t0, t6, end_outer   # if i >= 3, exit outer loop

    # Initialize middle loop: j = 0
    li      t1, 0               # t1 = j (column index)

middle_loop:
    li      t6, 3
    bge     t1, t6, end_middle  # if j >= 3, exit middle loop

    # Initialize accumulator: C[i][j] = 0
    li      t3, 0               # t3 = accumulator for C[i][j]

    # Initialize inner loop: k = 0
    li      t2, 0               # t2 = k

inner_loop:
    li      t6, 3
    bge     t2, t6, end_inner   # if k >= 3, exit inner loop

    # Calculate address of A[i][k]
    # Address = base + (i * 3 + k) * 4
    li      t6, 3
    mul     t4, t0, t6          # t4 = i * 3
    add     t4, t4, t2          # t4 = i * 3 + k
    slli    t4, t4, 2           # t4 = (i * 3 + k) * 4 (word offset)
    add     t4, s0, t4          # t4 = address of A[i][k]
    lw      t4, 0(t4)           # t4 = A[i][k] value

    # Calculate address of B[k][j]
    # Address = base + (k * 3 + j) * 4
    li      t6, 3
    mul     t5, t2, t6          # t5 = k * 3
    add     t5, t5, t1          # t5 = k * 3 + j
    slli    t5, t5, 2           # t5 = (k * 3 + j) * 4 (word offset)
    add     t5, s1, t5          # t5 = address of B[k][j]
    lw      t5, 0(t5)           # t5 = B[k][j] value

    # Multiply and accumulate: C[i][j] += A[i][k] * B[k][j]
    mul     t6, t4, t5          # t6 = A[i][k] * B[k][j]
    add     t3, t3, t6          # accumulator += A[i][k] * B[k][j]

    # Increment inner loop counter
    addi    t2, t2, 1           # k++
    j       inner_loop

end_inner:
    # Store result: C[i][j] = accumulator
    # Address = base + (i * 3 + j) * 4
    li      t6, 3
    mul     t4, t0, t6          # t4 = i * 3
    add     t4, t4, t1          # t4 = i * 3 + j
    slli    t4, t4, 2           # t4 = (i * 3 + j) * 4 (word offset)
    add     t4, s2, t4          # t4 = address of C[i][j]
    sw      t3, 0(t4)           # C[i][j] = accumulator

    # Increment middle loop counter
    addi    t1, t1, 1           # j++
    j       middle_loop

end_middle:
    # Increment outer loop counter
    addi    t0, t0, 1           # i++
    j       outer_loop

end_outer:
    # Restore callee-saved registers
    ld      s0, 0(sp)
    ld      s1, 8(sp)
    ld      s2, 16(sp)
    ld      ra, 24(sp)
    addi    sp, sp, 32

    # Return to caller
    ret

# ============================================================================
# Expected Result Matrix C:
# C = A × B =
# [ 30   24   18 ]     (1*9+2*6+3*3=30,  1*8+2*5+3*2=24,  1*7+2*4+3*1=18)
# [ 84   69   54 ]     (4*9+5*6+6*3=84,  4*8+5*5+6*2=69,  4*7+5*4+6*1=54)
# [138  114   90 ]     (7*9+8*6+9*3=138, 7*8+8*5+9*2=114, 7*7+8*4+9*1=90)
# ============================================================================

# Stack space in .bss section
.section .bss
    .align 4
    _stack_bottom:
        .space 4096
    _stack_start:

# HTIF (Host-Target Interface) section for Sail emulator
.section .tohost,"aw",@progbits
.align 6
.globl tohost
tohost: .dword 0
.align 6
.globl fromhost
fromhost: .dword 0
