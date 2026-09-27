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

# List the examples, then load and run one
(mapachespim) examples
(mapachespim) load riscv/fibonacci
(mapachespim) run

# Try the same program on another ISA
(mapachespim) load arm/fibonacci
(mapachespim) run
```

The examples are included in the installed package, so these names work from any directory. To get
your own editable copy:

```bash
mapachespim --copy-examples my-examples
```

## Building Examples

Each directory has the assembly source (`.s`) next to a prebuilt executable. You can load a source
file directly (`load riscv/fibonacci/fibonacci.s`) and MapacheSPIM assembles it for you. To rebuild
the executables with the bundled assembler, from this directory:

```bash
make            # build all examples
make DEBUG=1    # build with debug info (how the committed binaries are built)
make riscv      # build only one ISA: riscv, mips, arm, or x86_64
```

or assemble a single file:

```bash
mapachespim-as -g riscv/hello_asm/hello_asm.s -o hello_asm
```

RISC-V and MIPS are assembled by MapacheSPIM's built-in assembler. ARM64 and x86-64 use the Keystone
library, which is installed automatically on x86 computers (see the main README for other machines).

The Makefiles inside each ISA directory are an alternative that builds with the GNU cross
toolchains (for example `riscv64-unknown-elf-as`), for anyone who prefers them.

## Creating Your Own Programs

Start each file with an `.isa` line so MapacheSPIM knows which ISA it is for. Each template below
prints a number and exits.

### RISC-V Template
```assembly
.isa riscv64
.text
.globl _start
_start:
    li a0, 42           # Value to print
    li a7, 1            # print_int
    ecall
    li a7, 10           # exit
    ecall
```

### MIPS Template
```assembly
.isa mips32
.text
.globl _start
_start:
    li $a0, 42          # Value to print
    li $v0, 1           # print_int
    syscall
    li $v0, 10          # exit
    syscall
```

### ARM64 Template
```assembly
.isa arm64
.text
.globl _start
_start:
    mov x0, #42         // Value to print
    mov x8, #1          // print_int
    svc #0
    mov x8, #10         // exit
    svc #0
```

### x86-64 Template
```assembly
.isa x86_64
.text
.globl _start
_start:
    movq $42, %rdi      # Value to print
    movq $1, %rax       # print_int
    syscall
    movq $10, %rax      # exit
    syscall
```

### Syscalls

All ISAs support the same SPIM-compatible syscalls; only the registers differ:

| # | Name | Description |
|---|------|-------------|
| 1 | print_int | Print integer |
| 4 | print_string | Print null-terminated string |
| 5 | read_int | Read integer |
| 10 | exit | Exit program |
| 11 | print_char | Print ASCII character |
| 12 | read_char | Read a character |
| 17 | exit2 | Exit with a code |

See [Syscall Reference](../docs/user/syscalls.md) for complete details.

## Resources

- [RISC-V ISA Specification](https://riscv.org/specifications/)
- [ARM Architecture Reference](https://developer.arm.com/documentation/)
- [x86-64 Instruction Reference](https://www.felixcloutier.com/x86/)
- [MIPS Architecture](https://www.mips.com/products/architectures/)
- [Console Guide](../docs/user/console-guide.md)
