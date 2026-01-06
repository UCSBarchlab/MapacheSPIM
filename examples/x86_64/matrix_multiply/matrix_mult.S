# ============================================================================
# x86-64 Assembly: 3x3 Matrix Multiplication
# ============================================================================
#
# This program demonstrates matrix multiplication in x86-64 assembly.
# It multiplies two 3x3 matrices (A and B) and stores the result in matrix C.
#
# Algorithm: C[i][j] = sum(A[i][k] * B[k][j]) for k = 0 to 2
#
# Learning objectives:
# - Nested loops in assembly
# - Memory addressing with base+index*scale+offset
# - Register allocation and management
# - x86-64 calling convention
# ============================================================================

.section .data
    # Matrix A (3x3) - stored in row-major order
    .globl matrix_a
    # [ 1  2  3 ]
    # [ 4  5  6 ]
    # [ 7  8  9 ]
    matrix_a:
        .long 1, 2, 3
        .long 4, 5, 6
        .long 7, 8, 9

    # Matrix B (3x3) - stored in row-major order
    .globl matrix_b
    # [ 9  8  7 ]
    # [ 6  5  4 ]
    # [ 3  2  1 ]
    matrix_b:
        .long 9, 8, 7
        .long 6, 5, 4
        .long 3, 2, 1

    # Result matrix C (3x3) - initialized to zeros
    .globl matrix_c
    matrix_c:
        .long 0, 0, 0
        .long 0, 0, 0
        .long 0, 0, 0

.section .text
.globl _start

_start:
    # Load base addresses of matrices into registers
    lea     matrix_a(%rip), %rdi    # rdi = address of matrix A
    lea     matrix_b(%rip), %rsi    # rsi = address of matrix B
    lea     matrix_c(%rip), %rdx    # rdx = address of matrix C

    # Call matrix multiply function
    call    matrix_multiply

    # Exit program using SPIM-compatible syscall
    mov     $10, %rax               # syscall 10 = exit
    syscall

# ============================================================================
# Function: matrix_multiply
# Purpose: Multiplies two 3x3 matrices
# Arguments:
#   rdi = address of matrix A
#   rsi = address of matrix B
#   rdx = address of matrix C (result)
# Returns: nothing (result stored in matrix C)
# Registers used:
#   r8  = outer loop counter (i)
#   r9  = middle loop counter (j)
#   r10 = inner loop counter (k)
#   r11 = accumulator for C[i][j]
#   rax, rcx = temporaries for calculations
# ============================================================================
matrix_multiply:
    # Save callee-saved registers (following x86-64 ABI)
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15

    # Save matrix addresses in callee-saved registers
    mov     %rdi, %r12              # r12 = matrix A address
    mov     %rsi, %r13              # r13 = matrix B address
    mov     %rdx, %r14              # r14 = matrix C address

    # Initialize outer loop: i = 0
    xor     %r8d, %r8d              # r8 = i (row index)

outer_loop:
    cmp     $3, %r8d
    jge     end_outer               # if i >= 3, exit outer loop

    # Initialize middle loop: j = 0
    xor     %r9d, %r9d              # r9 = j (column index)

middle_loop:
    cmp     $3, %r9d
    jge     end_middle              # if j >= 3, exit middle loop

    # Initialize accumulator: C[i][j] = 0
    xor     %r11d, %r11d            # r11 = accumulator for C[i][j]

    # Initialize inner loop: k = 0
    xor     %r10d, %r10d            # r10 = k

inner_loop:
    cmp     $3, %r10d
    jge     end_inner               # if k >= 3, exit inner loop

    # Calculate index of A[i][k]
    # Index = i * 3 + k
    mov     %r8d, %eax              # eax = i
    imul    $3, %eax                # eax = i * 3
    add     %r10d, %eax             # eax = i * 3 + k

    # Load A[i][k] value
    movslq  %eax, %rax              # sign-extend to 64-bit
    mov     (%r12, %rax, 4), %ecx   # ecx = A[i][k] (4 bytes per element)

    # Calculate index of B[k][j]
    # Index = k * 3 + j
    mov     %r10d, %eax             # eax = k
    imul    $3, %eax                # eax = k * 3
    add     %r9d, %eax              # eax = k * 3 + j

    # Load B[k][j] value
    movslq  %eax, %rax              # sign-extend to 64-bit
    mov     (%r13, %rax, 4), %eax   # eax = B[k][j]

    # Multiply and accumulate: C[i][j] += A[i][k] * B[k][j]
    imul    %ecx, %eax              # eax = A[i][k] * B[k][j]
    add     %eax, %r11d             # accumulator += A[i][k] * B[k][j]

    # Increment inner loop counter
    inc     %r10d                   # k++
    jmp     inner_loop

end_inner:
    # Calculate index of C[i][j]
    # Index = i * 3 + j
    mov     %r8d, %eax              # eax = i
    imul    $3, %eax                # eax = i * 3
    add     %r9d, %eax              # eax = i * 3 + j

    # Store result: C[i][j] = accumulator
    movslq  %eax, %rax              # sign-extend to 64-bit
    mov     %r11d, (%r14, %rax, 4)  # C[i][j] = accumulator

    # Increment middle loop counter
    inc     %r9d                    # j++
    jmp     middle_loop

end_middle:
    # Increment outer loop counter
    inc     %r8d                    # i++
    jmp     outer_loop

end_outer:
    # Restore callee-saved registers
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx

    # Return to caller
    ret

# ============================================================================
# Expected Result Matrix C:
# C = A * B =
# [ 30   24   18 ]     (1*9+2*6+3*3=30,  1*8+2*5+3*2=24,  1*7+2*4+3*1=18)
# [ 84   69   54 ]     (4*9+5*6+6*3=84,  4*8+5*5+6*2=69,  4*7+5*4+6*1=54)
# [138  114   90 ]     (7*9+8*6+9*3=138, 7*8+8*5+9*2=114, 7*7+8*4+9*1=90)
# ============================================================================
