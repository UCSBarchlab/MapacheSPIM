# MapacheSail Interactive Console Guide

SPIM-like interactive console for RISC-V programs using the Sail formal specification.

## Quick Start

```bash
# Launch interactive console
./mapachesail_console

# Or load a program on startup
./mapachesail_console examples/fibonacci/fibonacci
```

## Basic Commands

### File Loading
- `load <file>` - Load a RISC-V ELF executable
  ```
  (mapachesail) load examples/fibonacci/fibonacci
  ```

### Execution
- `step [n]` - Execute 1 or n instructions (alias: `s`)
  ```
  (mapachesail) step       # Execute 1 instruction
  (mapachesail) step 10    # Execute 10 instructions
  ```

- `run [max]` - Run until halt or max instructions (alias: `r`)
  ```
  (mapachesail) run        # Run until program halts
  (mapachesail) run 1000   # Run max 1000 instructions
  ```

- `continue` - Continue after breakpoint (alias: `c`)

### State Inspection
- `regs` - Display all 32 registers + PC with ABI names
  ```
  (mapachesail) regs

  x0  (zero) = 0x0000000000000000  x1  (  ra) = 0x0000000080000018  ...
  x2  (  sp) = 0x0000000083efffe8  x3  (  gp) = 0x0000000000000000  ...
  ...
  pc                 = 0x0000000080000004
  ```

- `pc` - Show just the program counter
  ```
  (mapachesail) pc
  pc = 0x0000000080000004
  ```

- `mem <addr> [len]` - Display memory contents (default 256 bytes)
  ```
  (mapachesail) mem 0x80000000
  (mapachesail) mem 0x80000000 64    # Show 64 bytes

  0x80000000:  17 01 f0 03  13 01 01 00  97 02 00 00  93 82 82 08
  0x80000010:  03 a5 02 00  ef 00 40 02  97 02 00 00  93 82 c2 07
  ...
  ```

### Breakpoints
- `break <addr>` - Set breakpoint at address (alias: `b`)
  ```
  (mapachesail) break 0x80000010
  Breakpoint set at 0x0000000080000010
  ```

- `info breakpoints` - List all breakpoints
  ```
  (mapachesail) info break

  Breakpoints:
    1. 0x0000000080000010
    2. 0x0000000080000100
  ```

- `delete <addr>` - Remove breakpoint at address
  ```
  (mapachesail) delete 0x80000010
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
$ ./mapachesail_console
Sail RISC-V simulator initialized.
Welcome to MapacheSail. Type help or ? to list commands.

(mapachesail) load examples/fibonacci/fibonacci
✓ Loaded examples/fibonacci/fibonacci
Entry point: 0x0000000080000000

(mapachesail) step
[0x0000000080000000] Executed 1 instruction

(mapachesail) regs
x0  (zero) = 0x0000000000000000  x1  (  ra) = 0x0000000000000000  ...
...
pc                 = 0x0000000080000004

(mapachesail) break 0x80000038
Breakpoint set at 0x0000000080000038

(mapachesail) run
Breakpoint hit at 0x0000000080000038 after 5 instructions
PC = 0x0000000080000038

(mapachesail) continue
Executed 95 instruction(s)
PC = 0x00000000800000f0

(mapachesail) mem 0x80000000 32

0x80000000:  17 01 f0 03  13 01 01 00  97 02 00 00  93 82 82 08
0x80000010:  03 a5 02 00  ef 00 40 02  97 02 00 00  93 82 c2 07

(mapachesail) quit
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
./mapachesail_console

# Load file on startup
./mapachesail_console examples/fibonacci/fibonacci

# Quiet mode (less verbose)
./mapachesail_console -q examples/fibonacci/fibonacci
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

3. **Memory inspection**: Use hex addresses
   ```
   mem 0x80000000    # Code section
   mem 0x83efffe0    # Stack area
   ```

4. **Single-stepping**: Use `step n` for multiple steps
   ```
   step 10           # Execute 10 instructions at once
   ```

## Differences from SPIM

MapacheSail is similar to SPIM but has key differences:

1. **RISC-V instead of MIPS**: Uses RISC-V ISA with Sail formal spec
2. **ELF files**: Loads compiled ELF binaries (not assembly source)
3. **Formal specification**: Uses Sail RISC-V model (not custom simulator)
4. **64-bit**: Full RV64I support by default

## Troubleshooting

**Console won't start:**
- Make sure libsailsim is built: `cd libsailsim/build && cmake .. && make`
- Check Python path includes mapachesail package

**Can't load ELF file:**
- Verify file is RISC-V ELF: `file examples/fibonacci/fibonacci`
- Check file path is correct

**Breakpoint not hit:**
- Verify address is correct: `mem <addr>`
- Check program actually reaches that address

**Ctrl-C doesn't work:**
- Signal handling may take 1-2 instructions
- Try again if needed
