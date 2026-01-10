# ============================================================================
# array_stats.s - Array Processing with Loops
# ============================================================================
#
# This program demonstrates:
#   1. Defining arrays in the .data section
#   2. Looping through array elements
#   3. Memory access with lw and addressing modes
#   4. Tracking multiple values (sum, min, max)
#   5. Conditional jumps (blt, bgt, beq)
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
    jal     print_array

    # Calculate and print statistics
    jal     calc_stats

    # Exit program
    li      $v0, 10
    syscall

# ============================================================================
# print_array: Print all elements of the array
# ============================================================================
print_array:
    # Save return address (we'll call syscall)
    addi    $sp, $sp, -4
    sw      $ra, 0($sp)

    # Print "Array: "
    la      $a0, msg_array
    li      $v0, 4
    syscall

    # Set up loop variables
    la      $t0, array          # $t0 = pointer to current element
    la      $t1, array_len
    lw      $t1, 0($t1)         # $t1 = array length (counter)

print_loop:
    beq     $t1, $zero, print_done  # If counter == 0, we're done

    # Load and print current element
    lw      $a0, 0($t0)         # Load word from memory
    li      $v0, 1              # print_int syscall
    syscall

    # Print space separator
    la      $a0, space
    li      $v0, 4
    syscall

    # Move to next element
    addi    $t0, $t0, 4         # Move pointer forward by 4 bytes
    addi    $t1, $t1, -1        # Decrement counter

    j       print_loop          # Continue loop

print_done:
    # Print newline
    la      $a0, newline
    li      $v0, 4
    syscall

    # Restore and return
    lw      $ra, 0($sp)
    addi    $sp, $sp, 4
    jr      $ra

# ============================================================================
# calc_stats: Calculate sum, min, max and print results
# ============================================================================
calc_stats:
    # Save callee-saved registers
    addi    $sp, $sp, -20
    sw      $ra, 0($sp)
    sw      $s0, 4($sp)         # will hold sum
    sw      $s1, 8($sp)         # will hold min
    sw      $s2, 12($sp)        # will hold max
    sw      $s3, 16($sp)        # will hold counter

    # Initialize variables
    # $s0 = sum (starts at 0)
    # $s1 = min (starts at first element)
    # $s2 = max (starts at first element)

    la      $t0, array
    lw      $s1, 0($t0)         # min = array[0]
    lw      $s2, 0($t0)         # max = array[0]
    li      $s0, 0              # sum = 0

    # Set up loop
    la      $t0, array          # $t0 = pointer to current element
    la      $t1, array_len
    lw      $s3, 0($t1)         # $s3 = array length (counter)

stats_loop:
    beq     $s3, $zero, stats_done  # If counter == 0, we're done

    # Load current element
    lw      $t2, 0($t0)         # $t2 = current element

    # Add to sum
    add     $s0, $s0, $t2       # sum += current

    # Check if current < min
    bge     $t2, $s1, check_max # if current >= min, skip to max check
    move    $s1, $t2            # min = current

check_max:
    # Check if current > max
    ble     $t2, $s2, next_elem # if current <= max, skip
    move    $s2, $t2            # max = current

next_elem:
    # Move to next element
    addi    $t0, $t0, 4         # pointer += 4
    addi    $s3, $s3, -1        # counter--
    j       stats_loop

stats_done:
    # Now print all the statistics
    # $s0 = sum, $s1 = min, $s2 = max

    # Print Sum
    la      $a0, msg_sum
    li      $v0, 4
    syscall
    move    $a0, $s0
    li      $v0, 1
    syscall
    la      $a0, newline
    li      $v0, 4
    syscall

    # Print Min
    la      $a0, msg_min
    li      $v0, 4
    syscall
    move    $a0, $s1
    li      $v0, 1
    syscall
    la      $a0, newline
    li      $v0, 4
    syscall

    # Print Max
    la      $a0, msg_max
    li      $v0, 4
    syscall
    move    $a0, $s2
    li      $v0, 1
    syscall
    la      $a0, newline
    li      $v0, 4
    syscall

    # Print Count
    la      $a0, msg_count
    li      $v0, 4
    syscall
    la      $t0, array_len
    lw      $a0, 0($t0)
    li      $v0, 1
    syscall
    la      $a0, newline
    li      $v0, 4
    syscall

    # Restore and return
    lw      $ra, 0($sp)
    lw      $s0, 4($sp)
    lw      $s1, 8($sp)
    lw      $s2, 12($sp)
    lw      $s3, 16($sp)
    addi    $sp, $sp, 20
    jr      $ra

# ============================================================================
# SUMMARY OF NEW INSTRUCTIONS
# ============================================================================
#
#   lw   rd, offset(rs) - Load Word: rd = memory[rs + offset]
#   sw   rs, offset(rd) - Store Word: memory[rd + offset] = rs
#   add  rd, rs, rt     - Add: rd = rs + rt
#   addi rd, rs, imm    - Add Immediate: rd = rs + imm
#   beq  rs, rt, label  - Branch if Equal
#   blt  rs, rt, label  - Branch if Less Than (pseudo-instruction)
#   bgt  rs, rt, label  - Branch if Greater Than (pseudo-instruction)
#   bge  rs, rt, label  - Branch if Greater or Equal (pseudo-instruction)
#   ble  rs, rt, label  - Branch if Less or Equal (pseudo-instruction)
#   j    label          - Jump (unconditional)
#   jal  label          - Jump and Link (function call)
#   jr   $ra            - Jump Register (return)
#   move rd, rs         - Move: rd = rs (pseudo-instruction)
#
# ============================================================================
# MIPS vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              MIPS
#   ------              ----
#   lw   a0, 0(t0)      lw   $a0, 0($t0)       (load word)
#   beqz t1, done       beq  $t1, $zero, done  (branch if zero)
#   bge  t5, t3, skip   bge  $t5, $t3, skip    (branch if >=)
#   jal  ra, func       jal  func              (function call)
#   ret                 jr   $ra                (return)
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
