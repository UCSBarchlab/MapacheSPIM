# ============================================================================
# MIPS Assembly: 3x3 Matrix Multiplication
# ============================================================================
#
# This program demonstrates matrix multiplication in MIPS assembly.
# It multiplies two 3x3 matrices (A and B) and stores the result in matrix C.
#
# Algorithm: C[i][j] = sum(A[i][k] * B[k][j]) for k = 0 to 2
#
# Learning objectives:
# - Nested loops in assembly
# - Memory addressing with base+offset
# - Register allocation and management
# - MIPS calling convention
# ============================================================================

.section .data
    # Matrix A (3x3) - stored in row-major order
    .globl matrix_a
    # [ 1  2  3 ]
    # [ 4  5  6 ]
    # [ 7  8  9 ]
    matrix_a:
        .word 1, 2, 3
        .word 4, 5, 6
        .word 7, 8, 9

    # Matrix B (3x3) - stored in row-major order
    .globl matrix_b
    # [ 9  8  7 ]
    # [ 6  5  4 ]
    # [ 3  2  1 ]
    matrix_b:
        .word 9, 8, 7
        .word 6, 5, 4
        .word 3, 2, 1

    # Result matrix C (3x3) - initialized to zeros
    .globl matrix_c
    matrix_c:
        .word 0, 0, 0
        .word 0, 0, 0
        .word 0, 0, 0

.section .text
.globl _start

_start:
    # Load base addresses of matrices into registers
    la      $a0, matrix_a       # $a0 = address of matrix A
    la      $a1, matrix_b       # $a1 = address of matrix B
    la      $a2, matrix_c       # $a2 = address of matrix C

    # Call matrix multiply function
    jal     matrix_multiply

    # Exit program using syscall
    li      $v0, 10             # syscall 10 = exit
    syscall

# ============================================================================
# Function: matrix_multiply
# Purpose: Multiplies two 3x3 matrices
# Arguments:
#   $a0 = address of matrix A
#   $a1 = address of matrix B
#   $a2 = address of matrix C (result)
# Returns: nothing (result stored in matrix C)
# Registers used:
#   $s0 = outer loop counter (i)
#   $s1 = middle loop counter (j)
#   $s2 = inner loop counter (k)
#   $s3 = accumulator for C[i][j]
#   $s4 = matrix A address
#   $s5 = matrix B address
#   $s6 = matrix C address
#   $t0-$t4 = temporaries for calculations
# ============================================================================
matrix_multiply:
    # Save callee-saved registers
    addi    $sp, $sp, -32
    sw      $ra, 0($sp)
    sw      $s0, 4($sp)
    sw      $s1, 8($sp)
    sw      $s2, 12($sp)
    sw      $s3, 16($sp)
    sw      $s4, 20($sp)
    sw      $s5, 24($sp)
    sw      $s6, 28($sp)

    # Save matrix addresses in callee-saved registers
    move    $s4, $a0            # $s4 = matrix A address
    move    $s5, $a1            # $s5 = matrix B address
    move    $s6, $a2            # $s6 = matrix C address

    # Initialize outer loop: i = 0
    li      $s0, 0              # $s0 = i (row index)

outer_loop:
    li      $t0, 3
    bge     $s0, $t0, end_outer # if i >= 3, exit outer loop

    # Initialize middle loop: j = 0
    li      $s1, 0              # $s1 = j (column index)

middle_loop:
    li      $t0, 3
    bge     $s1, $t0, end_middle # if j >= 3, exit middle loop

    # Initialize accumulator: C[i][j] = 0
    li      $s3, 0              # $s3 = accumulator for C[i][j]

    # Initialize inner loop: k = 0
    li      $s2, 0              # $s2 = k

inner_loop:
    li      $t0, 3
    bge     $s2, $t0, end_inner # if k >= 3, exit inner loop

    # Calculate index of A[i][k]
    # Index = i * 3 + k
    li      $t1, 3
    mul     $t0, $s0, $t1       # $t0 = i * 3
    add     $t0, $t0, $s2       # $t0 = i * 3 + k

    # Load A[i][k] value
    sll     $t0, $t0, 2         # $t0 *= 4 (byte offset)
    add     $t0, $s4, $t0       # $t0 = address of A[i][k]
    lw      $t1, 0($t0)         # $t1 = A[i][k]

    # Calculate index of B[k][j]
    # Index = k * 3 + j
    li      $t3, 3
    mul     $t2, $s2, $t3       # $t2 = k * 3
    add     $t2, $t2, $s1       # $t2 = k * 3 + j

    # Load B[k][j] value
    sll     $t2, $t2, 2         # $t2 *= 4 (byte offset)
    add     $t2, $s5, $t2       # $t2 = address of B[k][j]
    lw      $t3, 0($t2)         # $t3 = B[k][j]

    # Multiply and accumulate: C[i][j] += A[i][k] * B[k][j]
    mul     $t4, $t1, $t3       # $t4 = A[i][k] * B[k][j]
    add     $s3, $s3, $t4       # accumulator += A[i][k] * B[k][j]

    # Increment inner loop counter
    addi    $s2, $s2, 1         # k++
    j       inner_loop

end_inner:
    # Calculate index of C[i][j]
    # Index = i * 3 + j
    li      $t1, 3
    mul     $t0, $s0, $t1       # $t0 = i * 3
    add     $t0, $t0, $s1       # $t0 = i * 3 + j

    # Store result: C[i][j] = accumulator
    sll     $t0, $t0, 2         # $t0 *= 4 (byte offset)
    add     $t0, $s6, $t0       # $t0 = address of C[i][j]
    sw      $s3, 0($t0)         # C[i][j] = accumulator

    # Increment middle loop counter
    addi    $s1, $s1, 1         # j++
    j       middle_loop

end_middle:
    # Increment outer loop counter
    addi    $s0, $s0, 1         # i++
    j       outer_loop

end_outer:
    # Restore callee-saved registers
    lw      $ra, 0($sp)
    lw      $s0, 4($sp)
    lw      $s1, 8($sp)
    lw      $s2, 12($sp)
    lw      $s3, 16($sp)
    lw      $s4, 20($sp)
    lw      $s5, 24($sp)
    lw      $s6, 28($sp)
    addi    $sp, $sp, 32

    # Return to caller
    jr      $ra

# ============================================================================
# Expected Result Matrix C:
# C = A * B =
# [ 30   24   18 ]     (1*9+2*6+3*3=30,  1*8+2*5+3*2=24,  1*7+2*4+3*1=18)
# [ 84   69   54 ]     (4*9+5*6+6*3=84,  4*8+5*5+6*2=69,  4*7+5*4+6*1=54)
# [138  114   90 ]     (7*9+8*6+9*3=138, 7*8+8*5+9*2=114, 7*7+8*4+9*1=90)
# ============================================================================

# ============================================================================
# MIPS vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              MIPS
#   ------              ----
#   mul  t4, t0, t6     mul  $t4, $t0, $t6      (multiply)
#   slli t4, t4, 2      sll  $t4, $t4, 2        (shift left logical)
#   lw   t4, 0(t4)      lw   $t4, 0($t4)        (load word)
#   sw   t3, 0(t4)      sw   $t3, 0($t4)        (store word)
#   bge  t0, t6, end    bge  $t0, $t6, end      (compare + branch)
#
# ============================================================================
# EXERCISES FOR STUDENTS
# ============================================================================
#
# 1. Modify the matrices A and B and verify the output
# 2. Add code to print matrices A and B before multiplication
# 3. Implement matrix addition instead of multiplication
# 4. Extend to handle 4x4 matrices
#
# ============================================================================
