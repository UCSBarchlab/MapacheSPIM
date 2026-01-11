# ============================================================================
# hello_asm.s - Your First ARM64 Assembly Program
# ============================================================================
#
# This program demonstrates the basics of ARM64 (AArch64) assembly:
#   1. Program structure (.data and .text sections)
#   2. Defining string constants
#   3. Using syscalls to print output
#   4. Basic register usage
#
# To run this program:
#   $ mapachespim
#   (mapachespim) load examples/arm/hello_asm/hello_asm
#   (mapachespim) run
#
# ============================================================================
.isa arm64


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
    #   1. Put the string's address in register x0
    #   2. Put the syscall number (4) in register x8
    #   3. Execute the svc #0 instruction

    adr     x0, hello_msg   # adr = "Address" - puts address of hello_msg into x0
    mov     x8, #4          # mov = "Move" - puts the value 4 into x8
    svc     #0              # Supervisor Call - this prints the string!

    # ========================================================================
    # STEP 2: Print "Your lucky number is: "
    # ========================================================================
    # Same pattern: load address, set syscall number, call

    adr     x0, lucky_msg   # Load address of our message
    mov     x8, #4          # Syscall 4 = print_string
    svc     #0              # Print it!

    # ========================================================================
    # STEP 3: Calculate and print a number
    # ========================================================================
    # Let's do some math! We'll add 7 + 35 and print the result.
    # To print an integer, we use syscall #1 (print_int)

    mov     x1, #7          # Load 7 into register x1
    mov     x2, #35         # Load 35 into register x2
    add     x0, x1, x2      # x0 = x1 + x2 = 7 + 35 = 42
                            # We put the result in x0 because that's where
                            # the print_int syscall expects to find it

    mov     x8, #1          # Syscall 1 = print_int
    svc     #0              # Print the number!

    # ========================================================================
    # STEP 4: Print a newline character
    # ========================================================================
    # After printing a number, we need to print a newline to move to the next line.
    # We use print_char (syscall #11) to print ASCII code 10 (newline)

    mov     x0, #10         # ASCII code 10 = newline character '\n'
    mov     x8, #11         # Syscall 11 = print_char
    svc     #0              # Print the newline!

    # ========================================================================
    # STEP 5: Print goodbye message
    # ========================================================================

    adr     x0, goodbye_msg
    mov     x8, #4
    svc     #0

    # ========================================================================
    # STEP 6: Exit the program
    # ========================================================================
    # Always end your program with the exit syscall!
    # Otherwise, the CPU will keep executing whatever is in memory next,
    # which will probably crash.

    mov     x8, #10         # Syscall 10 = exit
    svc     #0              # Goodbye!

# ============================================================================
# SUMMARY OF SYSCALLS USED
# ============================================================================
#
#   Syscall #1  (print_int):    Print integer in x0
#   Syscall #4  (print_string): Print null-terminated string at address in x0
#   Syscall #10 (exit):         Exit the program
#   Syscall #11 (print_char):   Print ASCII character in x0
#
# ============================================================================
# SUMMARY OF INSTRUCTIONS USED
# ============================================================================
#
#   adr  xd, label    - Address: xd = address of label (PC-relative)
#   mov  xd, #imm     - Move Immediate: xd = immediate value
#   add  xd, xn, xm   - Add: xd = xn + xm
#   svc  #0           - Supervisor Call: invoke a syscall
#
# ============================================================================
# ARM64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              ARM64
#   ------              -----
#   la   a0, label      adr  x0, label    (load address)
#   li   a0, imm        mov  x0, #imm     (load immediate)
#   add  a0, t0, t1     add  x0, x1, x2   (addition)
#   ecall               svc  #0           (syscall)
#   a0-a7 (arguments)   x0-x7 (arguments)
#   a7 (syscall num)    x8 (syscall num)
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
