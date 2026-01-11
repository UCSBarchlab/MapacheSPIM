# ============================================================================
# array_stats.s - Array Processing with Loops
# ============================================================================
#
# This program demonstrates:
#   1. Defining arrays in the .data section
#   2. Looping through array elements
#   3. Memory access with mov and addressing modes
#   4. Tracking multiple values (sum, min, max)
#   5. Conditional jumps (jl, jg, je)
#
# Note: This uses AT&T syntax (GNU assembler style)
# ============================================================================
.isa x86_64


    .data

# Our array of 8 integers
array:      .long   23, 7, 42, 15, 8, 31, 4, 19
array_len:  .long   8           # Number of elements

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
    call    print_array

    # Calculate and print statistics
    call    calc_stats

    # Exit program
    movq    $10, %rax
    syscall

# ============================================================================
# print_array: Print all elements of the array
# ============================================================================
print_array:
    # Save callee-saved registers
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %r12
    pushq   %r13

    # Print "Array: "
    leaq    msg_array(%rip), %rdi
    movq    $4, %rax
    syscall

    # Set up loop variables
    leaq    array(%rip), %r12       # r12 = pointer to current element
    leaq    array_len(%rip), %rax
    movl    (%rax), %r13d           # r13 = array length (counter)

print_loop:
    testq   %r13, %r13
    jz      print_done              # If counter == 0, we're done

    # Load and print current element
    movl    (%r12), %edi            # Load word from memory
    movq    $1, %rax                # print_int syscall
    syscall

    # Print space separator
    leaq    space(%rip), %rdi
    movq    $4, %rax
    syscall

    # Move to next element
    addq    $4, %r12                # Move pointer forward by 4 bytes
    decq    %r13                    # Decrement counter

    jmp     print_loop              # Continue loop

print_done:
    # Print newline
    leaq    newline(%rip), %rdi
    movq    $4, %rax
    syscall

    # Restore and return
    popq    %r13
    popq    %r12
    popq    %rbp
    ret

# ============================================================================
# calc_stats: Calculate sum, min, max and print results
# ============================================================================
calc_stats:
    # Save callee-saved registers
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %r12                    # will hold sum
    pushq   %r13                    # will hold min
    pushq   %r14                    # will hold max
    pushq   %r15                    # will hold counter

    # Initialize variables
    # r12 = sum (starts at 0)
    # r13 = min (starts at first element)
    # r14 = max (starts at first element)

    leaq    array(%rip), %rax
    movl    (%rax), %r13d           # min = array[0]
    movl    (%rax), %r14d           # max = array[0]
    xorq    %r12, %r12              # sum = 0

    # Set up loop
    leaq    array(%rip), %rcx       # rcx = pointer to current element
    leaq    array_len(%rip), %rax
    movl    (%rax), %r15d           # r15 = array length (counter)

stats_loop:
    testq   %r15, %r15
    jz      stats_done              # If counter == 0, we're done

    # Load current element
    movl    (%rcx), %edx            # edx = current element

    # Add to sum
    addq    %rdx, %r12              # sum += current

    # Check if current < min
    cmpq    %r13, %rdx
    jge     check_max               # if current >= min, skip to max check
    movq    %rdx, %r13              # min = current

check_max:
    # Check if current > max
    cmpq    %r14, %rdx
    jle     next_elem               # if current <= max, skip
    movq    %rdx, %r14              # max = current

next_elem:
    # Move to next element
    addq    $4, %rcx                # pointer += 4
    decq    %r15                    # counter--
    jmp     stats_loop

stats_done:
    # Now print all the statistics
    # r12 = sum, r13 = min, r14 = max

    # Print Sum
    leaq    msg_sum(%rip), %rdi
    movq    $4, %rax
    syscall
    movq    %r12, %rdi
    movq    $1, %rax
    syscall
    leaq    newline(%rip), %rdi
    movq    $4, %rax
    syscall

    # Print Min
    leaq    msg_min(%rip), %rdi
    movq    $4, %rax
    syscall
    movq    %r13, %rdi
    movq    $1, %rax
    syscall
    leaq    newline(%rip), %rdi
    movq    $4, %rax
    syscall

    # Print Max
    leaq    msg_max(%rip), %rdi
    movq    $4, %rax
    syscall
    movq    %r14, %rdi
    movq    $1, %rax
    syscall
    leaq    newline(%rip), %rdi
    movq    $4, %rax
    syscall

    # Print Count
    leaq    msg_count(%rip), %rdi
    movq    $4, %rax
    syscall
    leaq    array_len(%rip), %rax
    movl    (%rax), %edi
    movq    $1, %rax
    syscall
    leaq    newline(%rip), %rdi
    movq    $4, %rax
    syscall

    # Restore and return
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbp
    ret

# ============================================================================
# SUMMARY OF NEW INSTRUCTIONS
# ============================================================================
#
#   movl src, %ed     - Move Long (32-bit): ed = memory or register
#   movq src, %rd     - Move Quad (64-bit): rd = memory or register
#   addq %rs, %rd     - Add Quad: rd = rd + rs
#   cmpq %rs, %rd     - Compare: sets flags based on rd - rs
#   testq %rs, %rd    - Test: sets flags based on rd AND rs
#   je/jz label       - Jump if Equal/Zero
#   jne/jnz label     - Jump if Not Equal/Not Zero
#   jl label          - Jump if Less (signed)
#   jg label          - Jump if Greater (signed)
#   jle label         - Jump if Less or Equal
#   jge label         - Jump if Greater or Equal
#   incq %rd          - Increment: rd = rd + 1
#   decq %rd          - Decrement: rd = rd - 1
#   call label        - Call function (pushes return address)
#   ret               - Return from function
#
# ============================================================================
# x86-64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              x86-64 (AT&T syntax)
#   ------              --------------------
#   lw   a0, 0(t0)      movl (%rcx), %edx      (load word)
#   beqz t1, done       testq %r15, %r15 + jz  (test and jump if zero)
#   bge  t5, t3, skip   cmpq + jge             (compare + jump)
#   jal  ra, func       call func              (function call)
#   ret                 ret                     (return)
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
