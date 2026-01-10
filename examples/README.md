# Example Programs

Educational assembly programs organized by ISA for learning computer architecture.

## Directory Structure

```
examples/
├── arm/              # ARM64 (AArch64) examples
├── mips/             # MIPS32 examples
├── riscv/            # RISC-V 64-bit examples
└── x86_64/           # x86-64 examples
```

Each ISA directory contains 5 progressively challenging programs:

| Program | Difficulty | Concepts |
|---------|------------|----------|
| `hello_asm` | Beginner | Basic I/O, arithmetic, syscalls |
| `guess_game` | Beginner+ | User input, loops, conditionals |
| `fibonacci` | Intermediate | Recursion, stack frames, calling conventions |
| `array_stats` | Intermediate | Arrays, memory access, loops |
| `matrix_multiply` | Advanced | Nested loops, 2D arrays, indexing |

## Quick Start

```bash
# Start MapacheSPIM
mapachespim

# Load and run a RISC-V example
(mapachespim) load examples/riscv/fibonacci/fibonacci
(mapachespim) run

# Try an ARM64 example
(mapachespim) load examples/arm/fibonacci/fibonacci
(mapachespim) run
```

## Building Examples

Each ISA directory has a Makefile. You'll need the appropriate cross-compiler:

### RISC-V
```bash
# macOS
brew install riscv64-elf-gcc

# Build
cd examples/riscv && make
```

### ARM64
```bash
# macOS
brew install aarch64-elf-gcc

# Build
cd examples/arm && make
```

### x86-64
```bash
# macOS
brew install x86_64-elf-binutils x86_64-elf-gcc

# Build
cd examples/x86_64 && make
```

### MIPS32
```bash
# Linux
sudo apt install binutils-mips-linux-gnu gcc-mips-linux-gnu

# Build
cd examples/mips && make
```

## Using the Built-in Assembler

MapacheSPIM includes a built-in assembler that doesn't require external toolchains:

```bash
# Assemble a RISC-V program
mapachespim-as examples/riscv/hello_asm/hello_asm.s -o hello_asm

# Then load it
mapachespim
(mapachespim) load hello_asm
(mapachespim) run
```

## Creating Your Own Programs

### RISC-V Template
```assembly
.text
.globl _start

_start:
    # Your code here
    li a0, 42           # Return value
    li a7, 10           # Exit syscall
    ecall
```

### ARM64 Template
```assembly
.text
.globl _start

_start:
    // Your code here
    mov x0, #42         // Return value
    mov x8, #10         // Exit syscall
    svc #0
```

### Syscalls

All ISAs support SPIM-compatible syscalls:

| # | Name | Arguments | Description |
|---|------|-----------|-------------|
| 1 | print_int | a0 = integer | Print integer |
| 4 | print_string | a0 = address | Print null-terminated string |
| 5 | read_int | | Read integer into v0/a0 |
| 10 | exit | | Exit program |
| 11 | print_char | a0 = char | Print ASCII character |

See [Syscall Reference](../docs/user/syscalls.md) for complete details.

## Resources

- [RISC-V ISA Specification](https://riscv.org/specifications/)
- [ARM Architecture Reference](https://developer.arm.com/documentation/)
- [x86-64 Instruction Reference](https://www.felixcloutier.com/x86/)
- [MIPS Architecture](https://www.mips.com/products/architectures/)
- [Console Guide](../docs/user/console-guide.md)
