# ============================================================================
# array_stats.s - Array Processing with Loops
# ============================================================================
#
# This program demonstrates:
#   1. Defining arrays in the .data section
#   2. Looping through array elements
#   3. Memory access with lw (load word)
#   4. Tracking multiple values (sum, min, max)
#   5. Conditional branches (blt, bgt, beq)
#
# ============================================================================

    .data

# Our array of 8 integers
array:      .word   23, 7, 42, 15, 8, 31, 4, 19
array_len:  .word   8           # Number of elements

# Output messages
msg_array:  .asciz  "Array: "
msg_sum:    .asciz  "Sum: "
msg_min:    .asciz  "Min: "
msg_max:    .asciz  "Max: "
msg_count:  .asciz  "Count: "
space:      .asciz  " "
newline:    .asciz  "\n"

    .text
    .globl _start

# ============================================================================
# _start: Program Entry Point
# ============================================================================
_start:
    # First, print the array contents
    jal     ra, print_array

    # Calculate and print statistics
    jal     ra, calc_stats

    # Exit program
    li      a7, 10
    ecall

# ============================================================================
# print_array: Print all elements of the array
# ============================================================================
print_array:
    # Save return address (we'll call print functions)
    addi    sp, sp, -16
    sd      ra, 0(sp)
    sd      s0, 8(sp)

    # Print "Array: "
    la      a0, msg_array
    li      a7, 4
    ecall

    # Set up loop variables
    la      s0, array       # s0 = pointer to current element
    la      t0, array_len
    lw      t1, 0(t0)       # t1 = array length (counter)

print_loop:
    beqz    t1, print_done  # If counter == 0, we're done

    # Load and print current element
    lw      a0, 0(s0)       # Load word from memory at address s0
    li      a7, 1           # print_int syscall
    ecall

    # Print space separator
    la      a0, space
    li      a7, 4
    ecall

    # Move to next element
    addi    s0, s0, 4       # Move pointer forward by 4 bytes (size of word)
    addi    t1, t1, -1      # Decrement counter

    j       print_loop      # Continue loop

print_done:
    # Print newline
    la      a0, newline
    li      a7, 4
    ecall

    # Restore and return
    ld      ra, 0(sp)
    ld      s0, 8(sp)
    addi    sp, sp, 16
    ret

# ============================================================================
# calc_stats: Calculate sum, min, max and print results
# ============================================================================
calc_stats:
    # Save return address
    addi    sp, sp, -8
    sd      ra, 0(sp)

    # Initialize variables
    # t2 = sum (starts at 0)
    # t3 = min (starts at first element)
    # t4 = max (starts at first element)

    la      t0, array
    lw      t3, 0(t0)       # min = array[0]
    lw      t4, 0(t0)       # max = array[0]
    li      t2, 0           # sum = 0

    # Set up loop
    la      t0, array       # t0 = pointer to current element
    la      t5, array_len
    lw      t1, 0(t5)       # t1 = array length (counter)

stats_loop:
    beqz    t1, stats_done  # If counter == 0, we're done

    # Load current element
    lw      t5, 0(t0)       # t5 = current element

    # Add to sum
    add     t2, t2, t5      # sum += current

    # Check if current < min
    bge     t5, t3, check_max   # if current >= min, skip to max check
    mv      t3, t5              # min = current

check_max:
    # Check if current > max
    ble     t5, t4, next_elem   # if current <= max, skip
    mv      t4, t5              # max = current

next_elem:
    # Move to next element
    addi    t0, t0, 4       # pointer += 4
    addi    t1, t1, -1      # counter--
    j       stats_loop

stats_done:
    # Now print all the statistics
    # t2 = sum, t3 = min, t4 = max

    # Save our computed values (syscalls may clobber t registers)
    mv      s1, t2          # s1 = sum
    mv      s2, t3          # s2 = min
    mv      s3, t4          # s3 = max

    # Print Sum
    la      a0, msg_sum
    li      a7, 4
    ecall
    mv      a0, s1
    li      a7, 1
    ecall
    la      a0, newline
    li      a7, 4
    ecall

    # Print Min
    la      a0, msg_min
    li      a7, 4
    ecall
    mv      a0, s2
    li      a7, 1
    ecall
    la      a0, newline
    li      a7, 4
    ecall

    # Print Max
    la      a0, msg_max
    li      a7, 4
    ecall
    mv      a0, s3
    li      a7, 1
    ecall
    la      a0, newline
    li      a7, 4
    ecall

    # Print Count
    la      a0, msg_count
    li      a7, 4
    ecall
    la      t0, array_len
    lw      a0, 0(t0)
    li      a7, 1
    ecall
    la      a0, newline
    li      a7, 4
    ecall

    # Restore and return
    ld      ra, 0(sp)
    addi    sp, sp, 8
    ret

# ============================================================================
# SUMMARY OF NEW INSTRUCTIONS
# ============================================================================
#
#   lw   rd, offset(rs)  - Load Word: rd = memory[rs + offset]
#   sw   rs, offset(rd)  - Store Word: memory[rd + offset] = rs
#   sd   rs, offset(rd)  - Store Doubleword (64-bit)
#   ld   rd, offset(rs)  - Load Doubleword (64-bit)
#   beqz rs, label       - Branch if Equal to Zero
#   bge  rs1, rs2, label - Branch if Greater or Equal
#   ble  rs1, rs2, label - Branch if Less or Equal
#   blt  rs1, rs2, label - Branch if Less Than
#   mv   rd, rs          - Move (copy register)
#   j    label           - Jump unconditionally
#   jal  rd, label       - Jump and Link (function call)
#   ret                  - Return from function (alias for jalr x0, ra, 0)
#
# ============================================================================
# EXERCISES FOR STUDENTS
# ============================================================================
#
# 1. Add calculation of the average (sum / count)
# 2. Modify the array values and verify the output changes correctly
# 3. Add a function to find the index of the maximum element
# 4. Print the array in reverse order
#
# ============================================================================
