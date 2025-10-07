# Example Programs

Example assembly programs organized by ISA for educational purposes.

## Directory Structure

```
examples/
├── README.md           # This file
└── riscv/             # RISC-V examples
    ├── fibonacci/     # Recursive Fibonacci
    ├── matrix_multiply/ # 3x3 matrix multiplication
    ├── test_simple/   # Simple test program
    ├── Makefile       # Build all
    └── linker.ld      # Linker script
```

## RISC-V Examples

See [riscv/README.md](riscv/README.md) for details.

- **test_simple** - Basic instructions and registers (beginner)
- **fibonacci** - Function calls, recursion, stack (intermediate)
- **matrix_multiply** - Nested loops, arrays, memory (advanced)

Build and run:
```bash
cd riscv/
make
make run-fibonacci
```

## Using Examples

```bash
mapachespim
(mapachespim) load examples/riscv/fibonacci/fibonacci
(mapachespim) break main
(mapachespim) run
(mapachespim) step
```

## Creating Your Own

RISC-V template:
```assembly
.section .text
.global _start

_start:
    li a0, 42          # Your code here
    li a7, 93          # Exit syscall
    ecall
```

Compile:
```bash
riscv64-unknown-elf-gcc -march=rv64g -mabi=lp64 -static -nostdlib \
    -Tlinker.ld your_program.s -o your_program
```

## Resources

- [RISC-V ISA Specification](https://riscv.org/specifications/)
- [RISC-V Assembly Manual](https://github.com/riscv-non-isa/riscv-asm-manual)
- [Console Guide](../docs/user/console-guide.md)
