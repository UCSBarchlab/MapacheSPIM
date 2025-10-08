# Hello World - Simple I/O Test Program
# Tests print_string syscall (4)

.section .data
msg:    .string "Hello, World!\n"

.section .text
.globl _start

_start:
    # Print "Hello, World!\n"
    la a0, msg          # Load address of string
    li a7, 4            # Syscall 4 = print_string
    ecall

    # Exit
    li a7, 10           # Syscall 10 = exit
    ecall
