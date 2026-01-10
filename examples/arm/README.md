# ARM64 Assembly Examples for MapacheSPIM

Educational ARM64 (AArch64) assembly examples designed to teach computer architecture concepts using the Unicorn Engine emulator.

## Prerequisites

### ARM64 Toolchain

You need an ARM64 cross-compilation toolchain to build these examples:

**macOS (Homebrew):**
```bash
brew install aarch64-elf-gcc
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
# Then build with: make PREFIX=aarch64-linux-gnu-
```

**Alternative toolchains:**
- ARM GNU Toolchain: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads
- LLVM/Clang with ARM support

## Building Examples

### Build All Examples
```bash
make
```

### Build Individual Examples
```bash
make hello_asm        # Basic I/O and syscalls
make guess_game       # Interactive number guessing
make fibonacci        # Recursive Fibonacci
make array_stats      # Array processing
make matrix_multiply  # Matrix multiplication
```

### Clean Build Artifacts
```bash
make clean
```

## Running Examples

```bash
# Start MapacheSPIM
mapachespim

# Load and run an example
(mapachespim) load examples/arm/fibonacci/fibonacci
(mapachespim) run
```

## Examples Overview

### 1. Hello Assembly (`hello_asm/hello_asm.s`)
**Difficulty:** Beginner

**Learning Objectives:**
- Basic ARM64 instruction syntax
- String output with syscalls
- Simple arithmetic operations
- Program structure and exit

### 2. Guess Game (`guess_game/guess_game.s`)
**Difficulty:** Beginner+

**Learning Objectives:**
- User input with read_int syscall
- Conditional branching (cbz, cmp, beq, blt, bgt)
- Loop structures
- Interactive programs

### 3. Fibonacci (`fibonacci/fibonacci.s`)
**Difficulty:** Intermediate

**Learning Objectives:**
- Recursive function calls
- Stack frame management
- ARM64 calling convention
- Register save/restore with stp/ldp

**ARM64 Calling Convention:**
- x0-x7: Argument/result registers
- x8: Syscall number register
- x9-x15: Temporary registers
- x19-x28: Callee-saved registers
- x29: Frame pointer (FP)
- x30: Link register (LR) - return address
- sp: Stack pointer (16-byte aligned)

### 4. Array Statistics (`array_stats/array_stats.s`)
**Difficulty:** Intermediate

**Learning Objectives:**
- Array traversal in memory
- Load/store instructions (ldr/str)
- Calculating sum, min, max, average
- Working with data sections

### 5. Matrix Multiply (`matrix_multiply/matrix_mult.s`)
**Difficulty:** Advanced

**Learning Objectives:**
- Nested loop structures
- 2D array indexing
- Memory layout for matrices
- Complex pointer arithmetic

## ARM64 Assembly Quick Reference

### Register Names
- **x0-x30**: 64-bit general-purpose registers
- **w0-w30**: 32-bit versions (lower half of x registers)
- **sp**: Stack pointer
- **pc**: Program counter (not directly accessible)

### Common Instructions
```assembly
mov  x0, #42          // Move immediate 42 to x0
add  x2, x0, x1       // x2 = x0 + x1
sub  x2, x0, x1       // x2 = x0 - x1
lsl  x2, x0, #2       // x2 = x0 << 2 (multiply by 4)
ldr  x0, [x1]         // Load from address in x1 to x0
str  x0, [x1]         // Store x0 to address in x1
adr  x0, label        // Load PC-relative address of label
b    label            // Unconditional branch
bl   function         // Branch with link (call function)
ret                   // Return (branch to x30/LR)
cbz  x0, label        // Branch if x0 is zero
cmp  x0, #1           // Compare x0 with 1
beq  label            // Branch if equal
svc  #0               // Supervisor call (syscall)
```

### Stack Operations
```assembly
// Save two registers (16-byte aligned)
stp  x19, x30, [sp, #-16]!

// Restore two registers
ldp  x19, x30, [sp], #16

// Allocate stack space
sub  sp, sp, #32

// Deallocate stack space
add  sp, sp, #32
```

### Function Call Example
```assembly
my_function:
    // Prologue: save registers
    stp  x29, x30, [sp, #-16]!  // Save FP and LR
    mov  x29, sp                 // Set up frame pointer

    // Function body
    // ... your code ...

    // Epilogue: restore and return
    ldp  x29, x30, [sp], #16    // Restore FP and LR
    ret                          // Return to caller
```

## Syscalls

MapacheSPIM uses SPIM-compatible syscalls:

| # | Name | Arguments | Description |
|---|------|-----------|-------------|
| 1 | print_int | x0 = integer | Print integer |
| 4 | print_string | x0 = address | Print null-terminated string |
| 5 | read_int | | Read integer into x0 |
| 10 | exit | | Exit program |
| 11 | print_char | x0 = char | Print ASCII character |

**Syscall Convention:** Place syscall number in x8, arguments in x0-x2, then execute `svc #0`.

## Differences from RISC-V

If you're familiar with RISC-V assembly:

| Concept | RISC-V | ARM64 |
|---------|--------|-------|
| Syscall | `ecall` | `svc #0` |
| Return | `ret` (pseudo-instr) | `ret` |
| Call | `call label` | `bl label` |
| Jump | `j label` | `b label` |
| Load immediate | `li rd, imm` | `mov xd, #imm` |
| Shift left | `slli rd, rs, n` | `lsl xd, xs, #n` |
| Return address | `ra` (x1) | `x30` (LR) |
| Syscall number | `a7` (x17) | `x8` |

## Linker Script

The `linker.ld` file defines the memory layout:
- **Base address**: 0x80000000
- **Memory size**: 64MB RAM
- **Sections**: `.text`, `.rodata`, `.data`, `.bss`
- **Stack**: 1MB at end of RAM

## Resources

- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [ARM Assembly Language](https://developer.arm.com/documentation/den0024/latest)
- [MapacheSPIM Documentation](../../docs/)
- [Examples Guide](../README.md)

## Troubleshooting

### Toolchain Not Found
```
ERROR: aarch64-elf-as not found
```
**Solution**: Install the ARM64 toolchain (see Prerequisites)

### Wrong Toolchain Prefix
If you have a different toolchain (e.g., `aarch64-linux-gnu-`), override the PREFIX:
```bash
make PREFIX=aarch64-linux-gnu-
```
