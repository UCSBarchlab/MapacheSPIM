# Syscall Reference

MapacheSPIM supports SPIM-compatible syscalls for simple I/O. The syscall numbers are the same on
every ISA; only the registers and the instruction differ.

## Making Syscalls

| ISA | Instruction | Syscall number | Argument | Result |
|-----|-------------|----------------|----------|--------|
| RISC-V | `ecall` | `a7` | `a0` | `a0` |
| MIPS | `syscall` | `$v0` | `$a0` | `$v0` |
| ARM64 | `svc #0` | `x8` | `x0` | `x0` |
| x86-64 | `syscall` | `rax` | `rdi` | `rax` |

For example, on RISC-V:

```asm
li a7, <syscall_number>    # Load syscall number into a7
li a0, <argument>          # Load the argument into a0
ecall                      # Execute syscall
```

## Syscall Table

| Number | Name | Argument | Result | Description |
|--------|------|----------|--------|-------------|
| 1 | print_int | integer | - | Print a signed integer |
| 4 | print_string | address | - | Print a NUL-terminated string |
| 5 | read_int | - | integer | Read a line and parse it as an integer (0 if it isn't one) |
| 10 | exit | - | - | Exit the program with code 0 |
| 11 | print_char | character | - | Print one character |
| 12 | read_char | - | character | Read one character (0 at end of input) |
| 17 | exit2 | exit code | - | Exit the program with the given code (SPIM name) |
| 93 | exit_code | exit code | - | Exit with the given code (Linux RISC-V/ARM64 number) |

Using any other syscall number stops the program with an error such as
`Unknown syscall number 42 in a7`, which usually means the syscall register wasn't set.

## Examples

### Print String
```asm
.data
msg:    .asciz "Hello, World!\n"

.text
    la a0, msg          # Load address of string
    li a7, 4            # Syscall 4 = print_string
    ecall
```

### Print Integer
```asm
    li a0, 42           # Value to print
    li a7, 1            # Syscall 1 = print_int
    ecall
```

### Read Integer
```asm
    li a7, 5            # Syscall 5 = read_int
    ecall               # Result in a0
    mv t0, a0           # Save to t0
```

### Exit Program
```asm
    li a7, 10           # Syscall 10 = exit
    ecall
```

### Exit with Code
```asm
    li a0, 1            # Exit code
    li a7, 17           # Syscall 17 = exit2 (93 also works)
    ecall
```

### The Same on MIPS
```asm
    la $a0, msg         # Load address of string
    li $v0, 4           # Syscall 4 = print_string
    syscall
    li $v0, 10          # Syscall 10 = exit
    syscall
```

## Notes

- `print_int` treats the register as signed (64-bit on RISC-V/ARM64/x86-64, 32-bit on MIPS), so
  `-1` prints as `-1`.
- Input is read a line at a time. `read_char` returns the characters of that line one per call,
  including the newline at the end; `read_int` reads a whole line.
- When running with `mapachespim -e`, the program's exit code becomes the process exit status.
- Syscalls are educational - they don't invoke the actual OS.
