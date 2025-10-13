.global _start
.text

_start:
    // Simple ARM test program
    // Load some values into registers
    mov x0, #42
    mov x1, #100
    add x2, x0, x1

    // Exit via syscall (exit code in x0)
    mov x0, #0
    mov x8, #93    // exit syscall number for ARM64
    svc #0
