# ============================================================================
# ARM64 Assembly: 3x3 Matrix Multiplication
# ============================================================================
#
# This program demonstrates matrix multiplication in ARM64 assembly.
# It multiplies two 3x3 matrices (A and B) and stores the result in matrix C.
#
# Algorithm: C[i][j] = sum(A[i][k] * B[k][j]) for k = 0 to 2
#
# Learning objectives:
# - Nested loops in assembly
# - Memory addressing with base+offset
# - Register allocation and management
# - ARM64 calling convention
# ============================================================================

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

    # Output messages
    msg_result: .asciz "Result matrix C:\n"
    msg_row:    .asciz "  "
    space:      .asciz " "
    newline:    .asciz "\n"

.section .text
.globl _start

_start:
    # Load base addresses of matrices into registers
    adr     x0, matrix_a        # x0 = address of matrix A
    adr     x1, matrix_b        # x1 = address of matrix B
    adr     x2, matrix_c        # x2 = address of matrix C

    # Call matrix multiply function
    bl      matrix_multiply

    # Print result header
    adr     x0, msg_result
    mov     x8, #4
    svc     #0

    # Print the result matrix
    bl      print_matrix

    # Exit program
    mov     x8, #10
    svc     #0

# ============================================================================
# Function: matrix_multiply
# Purpose: Multiplies two 3x3 matrices
# Arguments:
#   x0 = address of matrix A
#   x1 = address of matrix B
#   x2 = address of matrix C (result)
# Returns: nothing (result stored in matrix C)
# Registers used:
#   x9  = outer loop counter (i)
#   x10 = middle loop counter (j)
#   x11 = inner loop counter (k)
#   x12 = accumulator
#   x13 = temporary for A[i][k]
#   x14 = temporary for B[k][j]
#   x15 = temporary address calculations
# ============================================================================
matrix_multiply:
    # Save callee-saved registers
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp

    # Save matrix addresses in callee-saved registers
    mov     x19, x0             # x19 = matrix A address
    mov     x20, x1             # x20 = matrix B address
    mov     x21, x2             # x21 = matrix C address

    # Initialize outer loop: i = 0
    mov     x9, #0              # x9 = i (row index)

outer_loop:
    cmp     x9, #3
    b.ge    end_outer           # if i >= 3, exit outer loop

    # Initialize middle loop: j = 0
    mov     x10, #0             # x10 = j (column index)

middle_loop:
    cmp     x10, #3
    b.ge    end_middle          # if j >= 3, exit middle loop

    # Initialize accumulator: C[i][j] = 0
    mov     x12, #0             # x12 = accumulator for C[i][j]

    # Initialize inner loop: k = 0
    mov     x11, #0             # x11 = k

inner_loop:
    cmp     x11, #3
    b.ge    end_inner           # if k >= 3, exit inner loop

    # Calculate address of A[i][k]
    # Address = base + (i * 3 + k) * 4
    mov     x15, #3
    mul     x13, x9, x15        # x13 = i * 3
    add     x13, x13, x11       # x13 = i * 3 + k
    lsl     x13, x13, #2        # x13 = (i * 3 + k) * 4 (word offset)
    add     x13, x19, x13       # x13 = address of A[i][k]
    ldr     w13, [x13]          # x13 = A[i][k] value

    # Calculate address of B[k][j]
    # Address = base + (k * 3 + j) * 4
    mov     x15, #3
    mul     x14, x11, x15       # x14 = k * 3
    add     x14, x14, x10       # x14 = k * 3 + j
    lsl     x14, x14, #2        # x14 = (k * 3 + j) * 4 (word offset)
    add     x14, x20, x14       # x14 = address of B[k][j]
    ldr     w14, [x14]          # x14 = B[k][j] value

    # Multiply and accumulate: C[i][j] += A[i][k] * B[k][j]
    mul     x15, x13, x14       # x15 = A[i][k] * B[k][j]
    add     x12, x12, x15       # accumulator += A[i][k] * B[k][j]

    # Increment inner loop counter
    add     x11, x11, #1        # k++
    b       inner_loop

end_inner:
    # Store result: C[i][j] = accumulator
    # Address = base + (i * 3 + j) * 4
    mov     x15, #3
    mul     x13, x9, x15        # x13 = i * 3
    add     x13, x13, x10       # x13 = i * 3 + j
    lsl     x13, x13, #2        # x13 = (i * 3 + j) * 4 (word offset)
    add     x13, x21, x13       # x13 = address of C[i][j]
    str     w12, [x13]          # C[i][j] = accumulator

    # Increment middle loop counter
    add     x10, x10, #1        # j++
    b       middle_loop

end_middle:
    # Increment outer loop counter
    add     x9, x9, #1          # i++
    b       outer_loop

end_outer:
    # Restore callee-saved registers
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48

    # Return to caller
    ret

# ============================================================================
# Function: print_matrix
# Purpose: Prints the result matrix C
# ============================================================================
print_matrix:
    stp     x29, x30, [sp, #-32]!
    stp     x19, x20, [sp, #16]
    mov     x29, sp

    adr     x19, matrix_c       # x19 = matrix C address
    mov     x20, #0             # x20 = element counter (0-8)

print_row:
    cmp     x20, #9
    b.ge    print_done

    # Print row indent
    adr     x0, msg_row
    mov     x8, #4
    svc     #0

    # Print 3 elements
    mov     x9, #0              # column counter
print_col:
    cmp     x9, #3
    b.ge    print_newline

    # Load and print element
    ldr     w0, [x19, x20, lsl #2]
    mov     x8, #1
    svc     #0

    # Print space
    adr     x0, space
    mov     x8, #4
    svc     #0

    add     x20, x20, #1
    add     x9, x9, #1
    b       print_col

print_newline:
    adr     x0, newline
    mov     x8, #4
    svc     #0
    b       print_row

print_done:
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

# ============================================================================
# Expected Result Matrix C:
# C = A × B =
# [ 30   24   18 ]     (1*9+2*6+3*3=30,  1*8+2*5+3*2=24,  1*7+2*4+3*1=18)
# [ 84   69   54 ]     (4*9+5*6+6*3=84,  4*8+5*5+6*2=69,  4*7+5*4+6*1=54)
# [138  114   90 ]     (7*9+8*6+9*3=138, 7*8+8*5+9*2=114, 7*7+8*4+9*1=90)
# ============================================================================

# ============================================================================
# ARM64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              ARM64
#   ------              -----
#   mul  t4, t0, t6     mul  x13, x9, x15    (multiply)
#   slli t4, t4, 2      lsl  x13, x13, #2    (shift left)
#   lw   t4, 0(t4)      ldr  w13, [x13]      (load word)
#   sw   t3, 0(t4)      str  w12, [x13]      (store word)
#   bge  t0, t6, end    cmp + b.ge           (compare + branch)
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
