# Hello World test fixture
# Prints "Hello, World!\n" and exits

    .data
msg:    .asciz "Hello, World!\n"

    .text
    .globl _start

_start:
    la      a0, msg             # Load address of message
    li      a7, 4               # Syscall 4 = print_string
    ecall                       # Print the message

    li      a7, 10              # Syscall 10 = exit
    ecall                       # Exit
