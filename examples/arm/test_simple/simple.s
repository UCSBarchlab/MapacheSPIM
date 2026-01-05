// Simple ARM64 Test Program
// Purpose: Predictable instruction-by-instruction behavior for testing
//
// Expected behavior:
//   Step 1: mov x5, #10        -> x5 = 10 (0xa)
//   Step 2: mov x6, #20        -> x6 = 20 (0x14)
//   Step 3: add x7, x5, x6     -> x7 = 30 (0x1e)
//   Step 4: sub x8, x7, x5     -> x8 = 20 (0x14)
//   Step 5: lsl x9, x5, #2     -> x9 = 40 (0x28)
//   Step 6: mov x0, #42        -> x0 = 42 (0x2a) - exit code
//   Step 7: b done             -> branch to done
//   Step 8: mov x8, #93        -> syscall exit
//   Step 9: svc #0

.section .text
.globl _start

_start:
    // Step 1: Load immediate 10 into x5
    mov x5, #10             // x5 = 10

    // Step 2: Load immediate 20 into x6
    mov x6, #20             // x6 = 20

    // Step 3: Add x5 + x6 -> x7
    add x7, x5, x6          // x7 = 30

    // Step 4: Subtract x7 - x5 -> x8
    sub x8, x7, x5          // x8 = 20

    // Step 5: Shift x5 left by 2 -> x9
    lsl x9, x5, #2          // x9 = 40

    // Step 6: Set return value
    mov x0, #42             // x0 = 42 (return code)

    // Step 7: Branch to done
    b done

done:
    // Step 8-9: Exit via svc (supervisor call)
    mov x8, #93             // syscall number for exit
    svc #0
