# Syscall Reference

MapacheSPIM supports SPIM-compatible syscalls for simple I/O operations.

## Making Syscalls

```asm
li a7, <syscall_number>    # Load syscall number into a7
li a0, <argument>          # Load arguments into a0-a5
ecall                      # Execute syscall
```

## Syscall Table

| Number | Name | Arguments | Return | Description |
|--------|------|-----------|--------|-------------|
| 1 | print_int | a0 = integer | - | Print integer to console |
| 4 | print_string | a0 = address | - | Print null-terminated string |
| 5 | read_int | - | a0 = integer | Read integer from console |
| 10 | exit | - | - | Exit program (code 0) |
| 11 | print_char | a0 = char | - | Print single character |
| 12 | read_char | - | a0 = char | Read single character |
| 93 | exit_code | a0 = code | - | Exit with code |

## Examples

### Print String
```asm
.data
msg:    .string "Hello, World!\n"

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
    li a7, 93           # Syscall 93 = exit_code
    ecall
```

## Notes

- Register `a7` holds the syscall number (like MIPS `$v0`)
- Arguments use registers `a0-a5` (like MIPS `$a0-$a3`)
- String addresses must point to null-terminated strings
- Syscalls are educational - they don't invoke the actual OS
