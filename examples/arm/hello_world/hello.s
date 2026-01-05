// Hello World - Simple I/O Test Program (ARM64)
// Tests print_string syscall (4)

.section .data
msg:    .asciz "Hello, World!\n"

.section .text
.globl _start

_start:
    // Print "Hello, World!\n"
    adr x0, msg             // Load address of string
    mov x8, #4              // Syscall 4 = print_string
    svc #0

    // Exit
    mov x8, #10             // Syscall 10 = exit
    svc #0
