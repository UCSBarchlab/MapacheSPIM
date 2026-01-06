// ============================================================================
// ARM64 Assembly: Recursive Fibonacci Calculator
// ============================================================================
//
// This program demonstrates recursive function calls in ARM64 assembly.
// It calculates the nth Fibonacci number using recursion.
//
// Fibonacci sequence: F(0)=0, F(1)=1, F(n)=F(n-1)+F(n-2) for n>1
// Example: F(7) = 13 (sequence: 0,1,1,2,3,5,8,13,...)
//
// Learning objectives:
// - Recursive function implementation
// - Stack frame management (push/pop)
// - ARM64 calling convention (x0-x7, x30/LR, sp)
// - Base case and recursive case handling
// - Register save/restore conventions
// ============================================================================

.section .data
    // Input value: calculate Fibonacci(7)
    fib_input:
        .word 7

    // Storage for result
    fib_result:
        .word 0

.section .text
.globl _start

_start:
    // Initialize stack pointer (usually done by OS, but we'll set it explicitly)
    adr     x1, _stack_start    // x1 = address of stack
    mov     sp, x1              // sp = top of stack

    // Load the input value
    adr     x1, fib_input
    ldr     w0, [x1]            // x0 = n (input argument)

    // Call fibonacci function
    bl      fibonacci           // result will be in x0

    // Store the result
    adr     x1, fib_result
    str     w0, [x1]            // save result to memory

    // Exit via syscall
    mov     x8, #93             // syscall number for exit
    svc     #0

exit_loop:
    // Infinite loop - just in case
    b       exit_loop

// ============================================================================
// Function: fibonacci
// Purpose: Recursively calculates the nth Fibonacci number
//
// Mathematical definition:
//   F(0) = 0
//   F(1) = 1
//   F(n) = F(n-1) + F(n-2) for n > 1
//
// ARM64 Calling Convention:
//   Arguments: x0 = n (which Fibonacci number to calculate)
//   Returns:   x0 = F(n) (the nth Fibonacci number)
//   Saved:     x30/LR (link register), x19 (saved register)
//
// Stack frame layout (when needed):
//   sp+0:  saved x19 (saved register for intermediate results)
//   sp+8:  saved x30/LR (return address)
//   sp+16: saved x0 (original n value)
//   Total: 24 bytes (aligned to 16)
// ============================================================================
fibonacci:
    // Base case 1: if n == 0, return 0
    cbz     x0, base_case_zero

    // Base case 2: if n == 1, return 1
    cmp     x0, #1
    beq     base_case_one

    // Recursive case: n > 1
    // We need to save registers and make recursive calls
    // Save x30/LR (return address), x19 (for intermediate result), and x0 (n)
    sub     sp, sp, #32         // allocate stack frame (32 bytes, 16-byte aligned)
    stp     x19, x30, [sp, #16] // save x19 and LR
    str     x0, [sp]            // save n

    // First recursive call: fibonacci(n-1)
    sub     x0, x0, #1          // x0 = n - 1
    bl      fibonacci           // call fibonacci(n-1)
    mov     x19, x0             // x19 = F(n-1) (save result)

    // Second recursive call: fibonacci(n-2)
    ldr     x0, [sp]            // restore original n
    sub     x0, x0, #2          // x0 = n - 2
    bl      fibonacci           // call fibonacci(n-2)

    // Add the two results: F(n) = F(n-1) + F(n-2)
    add     x0, x19, x0         // x0 = F(n-1) + F(n-2)

    // Restore saved registers and return
    ldp     x19, x30, [sp, #16] // restore x19 and LR
    add     sp, sp, #32         // deallocate stack frame
    ret                         // return to caller

base_case_zero:
    // F(0) = 0
    mov     x0, #0              // return 0
    ret

base_case_one:
    // F(1) = 1
    mov     x0, #1              // return 1
    ret

// ============================================================================
// Execution trace for fibonacci(3):
//
// Call fibonacci(3):
//   Not base case, make recursive calls
//   Call fibonacci(2):
//     Not base case, make recursive calls
//     Call fibonacci(1): returns 1
//     Call fibonacci(0): returns 0
//     Return 1 + 0 = 1
//   Call fibonacci(1): returns 1
//   Return 1 + 1 = 2
//
// Therefore: F(3) = 2
// Similarly: F(7) = 13
// ============================================================================

// ============================================================================
// Expected Results:
// Input: n = 7
// Output: F(7) = 13
//
// Fibonacci sequence reference:
// F(0)=0, F(1)=1, F(2)=1, F(3)=2, F(4)=3, F(5)=5, F(6)=8, F(7)=13
// ============================================================================

// Stack definition (8KB stack)
.section .bss
.align 4
_stack:
    .space 8192
_stack_start:
