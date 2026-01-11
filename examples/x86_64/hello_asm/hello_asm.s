# ============================================================================
# hello_asm.s - Your First x86-64 Assembly Program
# ============================================================================
#
# This program demonstrates the basics of x86-64 assembly:
#   1. Program structure (.data and .text sections)
#   2. Defining string constants
#   3. Using syscalls to print output
#   4. Basic register usage
#
# To run this program:
#   $ mapachespim
#   (mapachespim) load examples/x86_64/hello_asm/hello_asm
#   (mapachespim) run
#
# Note: This uses AT&T syntax (GNU assembler style)
# ============================================================================
.isa x86_64


# ----------------------------------------------------------------------------
# DATA SECTION
# ----------------------------------------------------------------------------
# The .data section is where we define our variables and constants.
# These are stored in memory and can be accessed by our code.

    .data

# Define string constants using .asciz (null-terminated strings)
# The label (e.g., "hello_msg") gives us a way to reference this memory address

hello_msg:      .asciz "Hello, Assembly!\n"
lucky_msg:      .asciz "Your lucky number is: "
newline:        .asciz "\n"
goodbye_msg:    .asciz "Goodbye!\n"

# ----------------------------------------------------------------------------
# TEXT SECTION
# ----------------------------------------------------------------------------
# The .text section contains our executable code.
# This is where the CPU will fetch and execute instructions.

    .text
    .globl _start       # Make _start visible to the linker

# ----------------------------------------------------------------------------
# _start: Program Entry Point
# ----------------------------------------------------------------------------
# Every program needs an entry point - this is where execution begins.
# By convention, we call it "_start".

_start:
    # ========================================================================
    # STEP 1: Print "Hello, Assembly!"
    # ========================================================================
    # To print a string, we use syscall #4 (print_string)
    # We need to:
    #   1. Put the string's address in register rdi
    #   2. Put the syscall number (4) in register rax
    #   3. Execute the syscall instruction

    leaq    hello_msg(%rip), %rdi   # lea = "Load Effective Address" - puts address into rdi
    movq    $4, %rax                # mov = "Move" - puts the value 4 into rax
    syscall                         # Make the syscall - this prints the string!

    # ========================================================================
    # STEP 2: Print "Your lucky number is: "
    # ========================================================================
    # Same pattern: load address, set syscall number, call

    leaq    lucky_msg(%rip), %rdi   # Load address of our message
    movq    $4, %rax                # Syscall 4 = print_string
    syscall                         # Print it!

    # ========================================================================
    # STEP 3: Calculate and print a number
    # ========================================================================
    # Let's do some math! We'll add 7 + 35 and print the result.
    # To print an integer, we use syscall #1 (print_int)

    movq    $7, %rcx                # Load 7 into register rcx
    movq    $35, %rdx               # Load 35 into register rdx
    addq    %rcx, %rdx              # rdx = rdx + rcx = 35 + 7 = 42
    movq    %rdx, %rdi              # Move result to rdi for syscall
                                    # We put the result in rdi because that's where
                                    # the print_int syscall expects to find it

    movq    $1, %rax                # Syscall 1 = print_int
    syscall                         # Print the number!

    # ========================================================================
    # STEP 4: Print a newline character
    # ========================================================================
    # After printing a number, we need to print a newline to move to the next line.
    # We use print_char (syscall #11) to print ASCII code 10 (newline)

    movq    $10, %rdi               # ASCII code 10 = newline character '\n'
    movq    $11, %rax               # Syscall 11 = print_char
    syscall                         # Print the newline!

    # ========================================================================
    # STEP 5: Print goodbye message
    # ========================================================================

    leaq    goodbye_msg(%rip), %rdi
    movq    $4, %rax
    syscall

    # ========================================================================
    # STEP 6: Exit the program
    # ========================================================================
    # Always end your program with the exit syscall!
    # Otherwise, the CPU will keep executing whatever is in memory next,
    # which will probably crash.

    movq    $10, %rax               # Syscall 10 = exit
    syscall                         # Goodbye!

# ============================================================================
# SUMMARY OF SYSCALLS USED
# ============================================================================
#
#   Syscall #1  (print_int):    Print integer in rdi
#   Syscall #4  (print_string): Print null-terminated string at address in rdi
#   Syscall #10 (exit):         Exit the program
#   Syscall #11 (print_char):   Print ASCII character in rdi
#
# ============================================================================
# SUMMARY OF INSTRUCTIONS USED
# ============================================================================
#
#   leaq src, %rd     - Load Effective Address: rd = address of src
#   movq $imm, %rd    - Move Immediate: rd = immediate value
#   movq %rs, %rd     - Move Register: rd = rs
#   addq %rs, %rd     - Add: rd = rd + rs
#   syscall           - System Call: invoke a syscall
#
# ============================================================================
# x86-64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              x86-64 (AT&T syntax)
#   ------              --------------------
#   la   a0, label      leaq label(%rip), %rdi  (load address)
#   li   a0, imm        movq $imm, %rdi         (load immediate)
#   add  a0, t0, t1     addq %rcx, %rdx         (add - note dest is last)
#   ecall               syscall                  (syscall)
#   a0-a7 (arguments)   rdi, rsi, rdx, rcx...   (arguments)
#   a7 (syscall num)    rax (syscall num)
#
# Note: AT&T syntax uses %register and $immediate prefixes
#       Source comes before destination (opposite of Intel syntax)
#
# ============================================================================
# EXERCISES FOR STUDENTS
# ============================================================================
#
# 1. Change the lucky number calculation to use different numbers
# 2. Add another message that prints your name
# 3. Try using subtraction (subq) instead of addition
# 4. Print multiple numbers on the same line separated by spaces
#
# ============================================================================
