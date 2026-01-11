# ============================================================================
# array_stats.s - Array Processing with Loops
# ============================================================================
#
# This program demonstrates:
#   1. Defining arrays in the .data section
#   2. Looping through array elements
#   3. Memory access with ldr (load register)
#   4. Tracking multiple values (sum, min, max)
#   5. Conditional branches (b.lt, b.gt, b.eq)
#
# ============================================================================
.isa arm64


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
    bl      print_array

    # Calculate and print statistics
    bl      calc_stats

    # Exit program
    mov     x8, #10
    svc     #0

# ============================================================================
# print_array: Print all elements of the array
# ============================================================================
print_array:
    # Save return address and callee-saved registers
    stp     x29, x30, [sp, #-32]!   # Push frame pointer and link register
    stp     x19, x20, [sp, #16]     # Push callee-saved registers
    mov     x29, sp                  # Set frame pointer

    # Print "Array: "
    adr     x0, msg_array
    mov     x8, #4
    svc     #0

    # Set up loop variables
    adr     x19, array              # x19 = pointer to current element
    adr     x9, array_len
    ldr     w20, [x9]               # x20 = array length (counter)

print_loop:
    cbz     x20, print_done         # If counter == 0, we're done

    # Load and print current element
    ldr     w0, [x19]               # Load word from memory at address x19
    mov     x8, #1                  # print_int syscall
    svc     #0

    # Print space separator
    adr     x0, space
    mov     x8, #4
    svc     #0

    # Move to next element
    add     x19, x19, #4            # Move pointer forward by 4 bytes (size of word)
    sub     x20, x20, #1            # Decrement counter

    b       print_loop              # Continue loop

print_done:
    # Print newline
    adr     x0, newline
    mov     x8, #4
    svc     #0

    # Restore and return
    ldp     x19, x20, [sp, #16]     # Pop callee-saved registers
    ldp     x29, x30, [sp], #32     # Pop frame pointer and link register
    ret

# ============================================================================
# calc_stats: Calculate sum, min, max and print results
# ============================================================================
calc_stats:
    # Save return address and callee-saved registers
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp

    # Initialize variables
    # x21 = sum (starts at 0)
    # x22 = min (starts at first element)
    # x19 = max (starts at first element)

    adr     x9, array
    ldr     w22, [x9]               # min = array[0]
    ldr     w19, [x9]               # max = array[0]
    mov     x21, #0                 # sum = 0

    # Set up loop
    adr     x9, array               # x9 = pointer to current element
    adr     x10, array_len
    ldr     w20, [x10]              # x20 = array length (counter)

stats_loop:
    cbz     x20, stats_done         # If counter == 0, we're done

    # Load current element
    ldr     w10, [x9]               # x10 = current element

    # Add to sum
    add     x21, x21, x10           # sum += current

    # Check if current < min
    cmp     x10, x22
    b.ge    check_max               # if current >= min, skip to max check
    mov     x22, x10                # min = current

check_max:
    # Check if current > max
    cmp     x10, x19
    b.le    next_elem               # if current <= max, skip
    mov     x19, x10                # max = current

next_elem:
    # Move to next element
    add     x9, x9, #4              # pointer += 4
    sub     x20, x20, #1            # counter--
    b       stats_loop

stats_done:
    # Now print all the statistics
    # x21 = sum, x22 = min, x19 = max

    # Print Sum
    adr     x0, msg_sum
    mov     x8, #4
    svc     #0
    mov     x0, x21
    mov     x8, #1
    svc     #0
    adr     x0, newline
    mov     x8, #4
    svc     #0

    # Print Min
    adr     x0, msg_min
    mov     x8, #4
    svc     #0
    mov     x0, x22
    mov     x8, #1
    svc     #0
    adr     x0, newline
    mov     x8, #4
    svc     #0

    # Print Max
    adr     x0, msg_max
    mov     x8, #4
    svc     #0
    mov     x0, x19
    mov     x8, #1
    svc     #0
    adr     x0, newline
    mov     x8, #4
    svc     #0

    # Print Count
    adr     x0, msg_count
    mov     x8, #4
    svc     #0
    adr     x9, array_len
    ldr     w0, [x9]
    mov     x8, #1
    svc     #0
    adr     x0, newline
    mov     x8, #4
    svc     #0

    # Restore and return
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret

# ============================================================================
# SUMMARY OF NEW INSTRUCTIONS
# ============================================================================
#
#   ldr  wd, [xn]        - Load Word (32-bit): wd = memory[xn]
#   ldr  xd, [xn]        - Load Doubleword (64-bit): xd = memory[xn]
#   str  wd, [xn]        - Store Word: memory[xn] = wd
#   stp  xa, xb, [sp, #-N]! - Store Pair with pre-decrement (push)
#   ldp  xa, xb, [sp], #N   - Load Pair with post-increment (pop)
#   cbz  xn, label       - Compare and Branch if Zero
#   cmp  xn, xm          - Compare (sets condition flags)
#   b.eq, b.ne           - Branch if Equal / Not Equal
#   b.lt, b.le           - Branch if Less Than / Less or Equal
#   b.gt, b.ge           - Branch if Greater Than / Greater or Equal
#   bl   label           - Branch and Link (function call)
#   ret                  - Return from function
#
# ============================================================================
# ARM64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              ARM64
#   ------              -----
#   lw   a0, 0(t0)      ldr  w0, [x9]        (load word)
#   sd   ra, 0(sp)      stp  x29, x30, [sp]  (store to stack)
#   beqz t1, done       cbz  x20, done       (branch if zero)
#   bge  t5, t3, skip   cmp x10, x22 + b.ge  (compare + branch)
#   jal  ra, func       bl   func            (function call)
#   ret                 ret                  (return)
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
