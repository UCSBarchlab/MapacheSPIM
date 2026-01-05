# ARM64 Assembly Examples for MapacheSPIM

This directory contains educational ARM64 (AArch64) assembly examples designed to demonstrate various programming concepts using the Sail ARM formal specification emulator.

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
- LLVM/Clang with ARM support (requires additional configuration)

### MapacheSPIM

Build and install MapacheSPIM with ARM support:
```bash
cd ../..
mkdir -p build && cd build
cmake -DBUILD_ARM_LIBRARY=ON ..
make
```

## Building Examples

### Build All Examples
```bash
make
```

### Build Individual Examples
```bash
make test_simple    # Simple arithmetic operations
make hello_world    # Hello World with syscalls
make fibonacci      # Recursive Fibonacci calculator
```

### Clean Build Artifacts
```bash
make clean
```

## Running Examples

### Using MapacheSPIM CLI
```bash
make run-simple      # Run simple test
make run-hello       # Run hello world
make run-fibonacci   # Run Fibonacci calculator
```

### Direct Execution
```bash
../../mapachespim_cli.py test_simple/simple
../../mapachespim_cli.py hello_world/hello
../../mapachespim_cli.py fibonacci/fibonacci
```

## Examples Overview

### 1. Simple Test (`test_simple/simple.s`)
**Learning Objectives:**
- Basic ARM64 instruction syntax
- Register operations
- Immediate values
- Branching

**Instructions Covered:**
- `mov` - Move immediate to register
- `add` - Addition
- `sub` - Subtraction
- `lsl` - Logical shift left
- `b` - Unconditional branch
- `svc` - Supervisor call (syscall)

### 2. Hello World (`hello_world/hello.s`)
**Learning Objectives:**
- String data in assembly
- System calls
- Memory addressing

**Concepts:**
- `.data` section for strings
- `adr` for PC-relative addressing
- ARM syscall convention (syscall number in x8)

### 3. Fibonacci (`fibonacci/fibonacci.s`)
**Learning Objectives:**
- Recursive function calls
- Stack frame management
- ARM64 calling convention
- Register save/restore

**ARM64 Calling Convention:**
- x0-x7: Argument/result registers
- x8: Syscall number register
- x9-x15: Temporary registers
- x19-x28: Callee-saved registers
- x29: Frame pointer (FP)
- x30: Link register (LR) - return address
- sp: Stack pointer

**Stack Alignment:**
- ARM64 requires 16-byte stack alignment
- Use `stp`/`ldp` for paired register saves

## Disassembly

View disassembly of compiled programs:

```bash
make dis-simple       # Disassemble simple test
make dis-hello        # Disassemble hello world
make dis-fibonacci    # Disassemble Fibonacci
```

## Toolchain Verification

Check that all required tools are installed:
```bash
make check-tools
```

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

## Linker Script

The `linker.ld` file defines the memory layout:
- **Base address**: 0x80000000
- **Memory size**: 64MB RAM
- **Sections**: `.text`, `.rodata`, `.data`, `.bss`
- **Stack**: 1MB at end of RAM

## Differences from RISC-V

If you're familiar with RISC-V assembly, key differences:

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

## Resources

- **ARM Architecture Reference Manual**: https://developer.arm.com/documentation/
- **ARM Assembly Language**: https://developer.arm.com/documentation/den0024/latest
- **Sail ARM Model**: https://github.com/rems-project/sail-arm
- **MapacheSPIM Documentation**: ../../docs/

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

### MapacheSPIM CLI Not Found
Ensure MapacheSPIM is built and the CLI path in the Makefile is correct:
```bash
MAPACHE_CLI = ../../mapachespim_cli.py
```

## Contributing

When adding new examples:
1. Follow the existing code structure and comments
2. Include learning objectives in file headers
3. Add comprehensive inline comments
4. Update this README with example description
5. Add build targets to Makefile

## License

These examples are part of the MapacheSPIM project and follow the same license terms.
