# MapacheSPIM Interactive Console Guide

SPIM-like interactive console for RISC-V programs using the Unicorn Engine.

## Quick Start

```bash
# Launch interactive console
mapachespim

# Or load a program on startup
mapachespim examples/riscv/fibonacci/fibonacci
```

## Basic Commands

### File Loading
- `load <file>` - Load a RISC-V ELF executable
  ```
  (mapachespim) load examples/riscv/fibonacci/fibonacci
  ```

### Execution
- `step [n]` - Execute 1 or n instructions (alias: `s`)
  ```
  (mapachespim) step       # Execute 1 instruction
  (mapachespim) step 10    # Execute 10 instructions
  ```

- `run [max]` - Run until halt or max instructions (alias: `r`)
  ```
  (mapachespim) run        # Run until program halts
  (mapachespim) run 1000   # Run max 1000 instructions
  ```

- `continue` - Continue after breakpoint (alias: `c`)

### State Inspection
- `regs` - Display all 32 registers + PC with ABI names
  ```
  (mapachespim) regs

  x0  (zero) = 0x0000000000000000  x1  (  ra) = 0x0000000080000018  ...
  x2  (  sp) = 0x0000000083efffe8  x3  (  gp) = 0x0000000000000000  ...
  ...
  pc                 = 0x0000000080000004
  ```

- `pc` - Show just the program counter
  ```
  (mapachespim) pc
  pc = 0x0000000080000004
  ```

- `mem <addr|section> [len]` - Display memory contents with ASCII sidebar (default 256 bytes)
  ```
  (mapachespim) mem 0x80000000           # By address
  (mapachespim) mem 0x80000000 64        # Show 64 bytes
  (mapachespim) mem .text                # By section name
  (mapachespim) mem .data 128            # Section with length

  0x80000000:  17 01 f0 03  13 01 01 00  97 02 00 00  93 82 82 08  |................|
  0x80000010:  03 a5 02 00  ef 00 40 02  97 02 00 00  93 82 c2 07  |......@.........|
  ...
  ```

- `list [location]` - Display source code (requires debug symbols) (alias: `l`)
  ```
  (mapachespim) list             # Show source around current PC
  (mapachespim) list fibonacci   # Show source around function
  (mapachespim) list 40          # Show source around line 40

  fibonacci.s:
     41:     blt  a0, t0, base_case
     42:     # Recursive case: fib(n) = fib(n-1) + fib(n-2)
     43:     addi sp, sp, -16
     44:     sd   ra, 8(sp)         # <-- PC: 0x80000048
     45:     sd   s0, 0(sp)
     46:     mv   s0, a0
     47:     addi a0, a0, -1
     48:     call fibonacci
     49:     mv   t0, a0
     50:     addi a0, s0, -2

  Tip: Compile with 'as -g' to include debug symbols
  ```

### Breakpoints
- `break <addr>` - Set breakpoint at address (alias: `b`)
  ```
  (mapachespim) break 0x80000010
  Breakpoint set at 0x0000000080000010
  ```

- `info breakpoints` - List all breakpoints
  ```
  (mapachespim) info break

  Breakpoints:
    1. 0x0000000080000010
    2. 0x0000000080000100
  ```

- `info symbols` - List all symbols from symbol table (alias: `info sym`)
  ```
  (mapachespim) info symbols

  Symbols (22 total):
    0x80000000  _start
    0x80000030  main
    0x80000038  fibonacci
    ...
  ```

- `info sections` - List all ELF sections (alias: `info sec`)
  ```
  (mapachespim) info sections

  ELF Sections:
  Name                            Address         Size  Flags
  ----------------------------------------------------------------------
  .text                        0x80000000         2048  AX
  .data                        0x80001000          256  WA
  .rodata                      0x80001100          128  A

  Flags: W=Write, A=Alloc, X=Execute
  Use 'mem <section>' to view section contents (e.g., mem .data)
  ```

- `delete <addr>` - Remove breakpoint at address
  ```
  (mapachespim) delete 0x80000010
  Breakpoint removed at 0x0000000080000010
  ```

- `clear` - Remove all breakpoints

### Utility
- `status` - Show simulator status
- `reset` - Reset simulator (keeps program loaded)
- `help` - Show all commands
- `quit` / `exit` - Exit console (alias: `q`)

## Example Session

```
$ mapachespim
Welcome to MapacheSPIM. Type help or ? to list commands.

(mapachespim) load examples/riscv/fibonacci/fibonacci
✓ Loaded examples/riscv/fibonacci/fibonacci
Entry point: 0x0000000080000000

(mapachespim) step
[0x0000000080000000] Executed 1 instruction

(mapachespim) regs
x0  (zero) = 0x0000000000000000  x1  (  ra) = 0x0000000000000000  ...
...
pc                 = 0x0000000080000004

(mapachespim) break 0x80000038
Breakpoint set at 0x0000000080000038

(mapachespim) run
Breakpoint hit at 0x0000000080000038 after 5 instructions
PC = 0x0000000080000038

(mapachespim) continue
Executed 95 instruction(s)
PC = 0x00000000800000f0

(mapachespim) mem 0x80000000 32

0x80000000:  17 01 f0 03  13 01 01 00  97 02 00 00  93 82 82 08  |................|
0x80000010:  03 a5 02 00  ef 00 40 02  97 02 00 00  93 82 c2 07  |......@.........|

(mapachespim) quit
Goodbye!
```

## RISC-V Register ABI Names

The console shows both numeric (x0-x31) and ABI names:

| Reg | ABI Name | Description |
|-----|----------|-------------|
| x0  | zero     | Hard-wired zero |
| x1  | ra       | Return address |
| x2  | sp       | Stack pointer |
| x3  | gp       | Global pointer |
| x4  | tp       | Thread pointer |
| x5-7 | t0-t2   | Temporaries |
| x8  | s0/fp    | Saved / frame pointer |
| x9  | s1       | Saved register |
| x10-11 | a0-a1 | Function args/return values |
| x12-17 | a2-a7 | Function arguments |
| x18-27 | s2-s11 | Saved registers |
| x28-31 | t3-t6 | Temporaries |

## Command Line Options

```bash
# Launch console
mapachespim

# Load file on startup
mapachespim examples/riscv/fibonacci/fibonacci

# Quiet mode (less verbose)
mapachespim -q examples/riscv/fibonacci/fibonacci
```

## Keyboard Shortcuts

- **Ctrl-C** during `run` - Interrupt execution
- **Ctrl-D** or `quit` - Exit console
- **Tab** - Command completion
- **Up/Down arrows** - Command history

## Tips

1. **Setting multiple breakpoints**: Set breakpoints before running
   ```
   break 0x80000010
   break 0x80000100
   info break
   run
   ```

2. **Examining function calls**: Set breakpoint at function entry
   ```
   break 0x80000050  # Function entry point
   run
   regs              # Check arguments in a0-a7
   ```

3. **Memory inspection**: Use hex addresses or section names
   ```
   mem 0x80000000    # By address
   mem .text         # Code section
   mem .data         # Data section
   mem .rodata       # Read-only data (strings, constants)
   info sections     # List all available sections
   ```

4. **Source code viewing**: Requires debug symbols (compile with `-g`)
   ```
   list              # Show source around current PC
   list main         # Show source around function
   list 25           # Show source around line 25
   ```

5. **Single-stepping**: Use `step n` for multiple steps
   ```
   step 10           # Execute 10 instructions at once
   ```

## Compiling with Debug Symbols

To enable the `list` command for source code viewing, compile your assembly with debug symbols:

```bash
# Assemble with debug symbols
riscv64-unknown-elf-as -march=rv64g -mabi=lp64 -g -o program.o program.s

# Link as normal
riscv64-unknown-elf-ld -T linker.ld -o program program.o
```

The `-g` flag adds DWARF debug information that maps machine addresses to source lines.

## Differences from SPIM

MapacheSPIM is similar to SPIM but has key differences:

1. **RISC-V instead of MIPS**: Uses RISC-V ISA via Unicorn Engine
2. **ELF files**: Loads compiled ELF binaries (not assembly source)
3. **64-bit**: Full RV64I support by default
4. **Source display**: Optional via `list` command (requires `-g` flag)

## Troubleshooting

**Console won't start:**
- Make sure you've installed the package: `pip install -e .`
- Check Python path includes mapachespim package

**Can't load ELF file:**
- Verify file is RISC-V ELF: `file examples/riscv/fibonacci/fibonacci`
- Check file path is correct

**Breakpoint not hit:**
- Verify address is correct: `mem <addr>`
- Check program actually reaches that address

**Ctrl-C doesn't work:**
- Signal handling may take 1-2 instructions
- Try again if needed
