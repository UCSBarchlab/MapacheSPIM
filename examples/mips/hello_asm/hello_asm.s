# ============================================================================
# hello_asm.s - Your First MIPS Assembly Program
# ============================================================================
#
# This program demonstrates the basics of MIPS assembly:
#   1. Program structure (.data and .text sections)
#   2. Defining string constants
#   3. Using syscalls to print output
#   4. Basic register usage
#
# To run this program:
#   $ mapachespim
#   (mapachespim) load examples/mips/hello_asm/hello_asm
#   (mapachespim) run
#
# ============================================================================
.isa mips32


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
    #   1. Put the string's address in register $a0
    #   2. Put the syscall number (4) in register $v0
    #   3. Execute the syscall instruction

    la      $a0, hello_msg  # la = "Load Address" - puts address of hello_msg into $a0
    li      $v0, 4          # li = "Load Immediate" - puts the value 4 into $v0
    syscall                 # Make the syscall - this prints the string!

    # ========================================================================
    # STEP 2: Print "Your lucky number is: "
    # ========================================================================
    # Same pattern: load address, set syscall number, call

    la      $a0, lucky_msg  # Load address of our message
    li      $v0, 4          # Syscall 4 = print_string
    syscall                 # Print it!

    # ========================================================================
    # STEP 3: Calculate and print a number
    # ========================================================================
    # Let's do some math! We'll add 7 + 35 and print the result.
    # To print an integer, we use syscall #1 (print_int)

    li      $t0, 7          # Load 7 into temporary register $t0
    li      $t1, 35         # Load 35 into temporary register $t1
    add     $a0, $t0, $t1   # $a0 = $t0 + $t1 = 7 + 35 = 42
                            # We put the result in $a0 because that's where
                            # the print_int syscall expects to find it

    li      $v0, 1          # Syscall 1 = print_int
    syscall                 # Print the number!

    # ========================================================================
    # STEP 4: Print a newline character
    # ========================================================================
    # After printing a number, we need to print a newline to move to the next line.
    # We could use print_string with our newline constant, or use print_char.
    # Let's use print_char (syscall #11) to print ASCII code 10 (newline)

    li      $a0, 10         # ASCII code 10 = newline character '\n'
    li      $v0, 11         # Syscall 11 = print_char
    syscall                 # Print the newline!

    # ========================================================================
    # STEP 5: Print goodbye message
    # ========================================================================

    la      $a0, goodbye_msg
    li      $v0, 4
    syscall

    # ========================================================================
    # STEP 6: Exit the program
    # ========================================================================
    # Always end your program with the exit syscall!
    # Otherwise, the CPU will keep executing whatever is in memory next,
    # which will probably crash.

    li      $v0, 10         # Syscall 10 = exit
    syscall                 # Goodbye!

# ============================================================================
# SUMMARY OF SYSCALLS USED
# ============================================================================
#
#   Syscall #1  (print_int):    Print integer in $a0
#   Syscall #4  (print_string): Print null-terminated string at address in $a0
#   Syscall #10 (exit):         Exit the program
#   Syscall #11 (print_char):   Print ASCII character in $a0
#
# ============================================================================
# SUMMARY OF INSTRUCTIONS USED
# ============================================================================
#
#   la   rd, label    - Load Address: rd = address of label
#   li   rd, imm      - Load Immediate: rd = immediate value
#   add  rd, rs, rt   - Add: rd = rs + rt
#   syscall           - System Call: invoke a syscall (number in $v0)
#
# ============================================================================
# MIPS vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              MIPS
#   ------              ----
#   a0-a7 (args)        $a0-$a3 (args)
#   a7 (syscall num)    $v0 (syscall num)
#   t0-t6 (temps)       $t0-$t9 (temps)
#   ecall               syscall
#
# ============================================================================
# EXERCISES FOR STUDENTS
# ============================================================================
#
# 1. Change the lucky number calculation to use different numbers
# 2. Add another message that prints your name
# 3. Try using subtraction (sub) instead of addition
# 4. Print multiple numbers on the same line separated by spaces
#
# ============================================================================
