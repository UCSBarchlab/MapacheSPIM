# Simple x86-64 Test Program
# Purpose: Predictable instruction-by-instruction behavior for testing
#
# Expected behavior:
#   Step 1: mov rax, 10      -> rax = 10 (0xa)
#   Step 2: mov rcx, 20      -> rcx = 20 (0x14)
#   Step 3: add rax, rcx     -> rax = 30 (0x1e)
#   Step 4: mov rdx, rax     -> rdx = 30
#   Step 5: sub rdx, 10      -> rdx = 20 (0x14)
#   Step 6: shl rax, 1       -> rax = 60 (0x3c)
#   Step 7: mov rdi, 42      -> rdi = 42 (exit code)
#   Step 8: mov rax, 10      -> rax = 10 (syscall 10 = exit)
#   Step 9: syscall          -> exit

.section .text
.globl _start

_start:
    # Step 1: Load immediate 10 into rax
    mov $10, %rax           # rax = 10

    # Step 2: Load immediate 20 into rcx
    mov $20, %rcx           # rcx = 20

    # Step 3: Add rcx to rax
    add %rcx, %rax          # rax = 30

    # Step 4: Copy rax to rdx
    mov %rax, %rdx          # rdx = 30

    # Step 5: Subtract 10 from rdx
    sub $10, %rdx           # rdx = 20

    # Step 6: Shift rax left by 1
    shl $1, %rax            # rax = 60

    # Step 7: Set exit code in rdi
    mov $42, %rdi           # rdi = 42 (exit code)

    # Step 8-9: Exit via syscall
    mov $10, %rax           # syscall number 10 = exit (SPIM-compatible)
    syscall
