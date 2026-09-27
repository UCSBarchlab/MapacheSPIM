# MapacheSPIM Interactive Console Guide

SPIM-like interactive console for RISC-V, MIPS, ARM64, and x86-64 programs using the Unicorn Engine.

## Quick Start

```bash
# Launch interactive console
mapachespim

# Or load a program on startup: your own source file, an ELF, or an example
mapachespim myprog.s
mapachespim riscv/fibonacci
```

## Basic Commands

### File Loading
- `load <file> [isa]` - Load a program
  - Assembly source (`.s`, `.S`, `.asm`) is assembled for you, with debug info so `list` works.
    The ISA comes from an `.isa` directive in the file, or the optional `isa` argument
    (`riscv64`, `mips32`, `arm64`, `x86_64`).
  - ELF executables are loaded directly and their ISA is detected automatically.
  - Bundled examples can be loaded by name.
  ```
  (mapachespim) load myprog.s
  (mapachespim) load myprog.s riscv64
  (mapachespim) load riscv/fibonacci
  (mapachespim) load examples/riscv/fibonacci/fibonacci
  ```

- `reload` - Re-assemble and reload the current program (after you edit it). Breakpoints on
  labels move with their labels.

- `examples [isa]` - List the bundled example programs
  ```
  (mapachespim) examples mips

  MIPS32:
    mips/array_stats         Array Processing with Loops
    mips/fibonacci           Recursive Fibonacci Calculator
    mips/guess_game          Number Guessing Game
    mips/hello_asm           Your First MIPS Assembly Program
    mips/matrix_multiply     3x3 Matrix Multiplication

  Load one with, e.g.:  load mips/array_stats
  ```

### Execution
- `step [n]` - Execute 1 or n instructions (alias: `s`)
  ```
  (mapachespim) step       # Execute 1 instruction
  (mapachespim) step 10    # Execute 10 instructions
  ```

- `run [max]` - Run until the program exits, hits a breakpoint, or reaches max instructions (alias: `r`)
  ```
  (mapachespim) run        # Run until program exits
  (mapachespim) run 1000   # Run max 1000 instructions
  ```

  If the program crashes, you see why and where. For example, with this `prog.s`:
  ```asm
  .isa riscv64
  .text
  .globl _start
  _start: li   a0, 0          # a null pointer
          ld   a0, 0(a0)      # load through it
  ```
  ```
  (mapachespim) load prog.s
  Assembled prog.s (896 bytes)
  Loaded prog.s (RISCV)
  Entry point: 0x0000000080000000
  Source info: prog.s (2 address mappings)

  (mapachespim) run
  Error: Read from unmapped address 0x0 (at PC=0x80000004)
    [0x80000004] 0x03350500  ld a0, 0(a0)  <_start+4>
    prog.s:5: ld   a0, 0(a0)      # load through it
  PC = 0x0000000080000004
  ```

- `continue` - Continue after breakpoint (alias: `c`)

### State Inspection
- `regs [hex|decimal|binary]` - Display all registers + PC with ABI names. A ★ marks registers
  that changed since you last displayed them (`regs peek` shows them without resetting that).
  Here, after loading `riscv/fibonacci` and stepping one instruction:
  ```
  (mapachespim) regs

  x0  (zero) = 0x0000000000000000    x1  (  ra) = 0x0000000000000000
  x2  (  sp) = 0x0000000083effff8    x3  (  gp) = 0x0000000000000000
  x4  (  tp) = 0x0000000000000000    x5  (  t0) = 0x0000000080100000 ★
  x6  (  t1) = 0x0000000000000000    x7  (  t2) = 0x0000000000000000
  x8  (  s0) = 0x0000000000000000    x9  (  s1) = 0x0000000000000000
  x10 (  a0) = 0x0000000000000000    x11 (  a1) = 0x0000000000000000
  x12 (  a2) = 0x0000000000000000    x13 (  a3) = 0x0000000000000000
  x14 (  a4) = 0x0000000000000000    x15 (  a5) = 0x0000000000000000
  x16 (  a6) = 0x0000000000000000    x17 (  a7) = 0x0000000000000000
  x18 (  s2) = 0x0000000000000000    x19 (  s3) = 0x0000000000000000
  x20 (  s4) = 0x0000000000000000    x21 (  s5) = 0x0000000000000000
  x22 (  s6) = 0x0000000000000000    x23 (  s7) = 0x0000000000000000
  x24 (  s8) = 0x0000000000000000    x25 (  s9) = 0x0000000000000000
  x26 ( s10) = 0x0000000000000000    x27 ( s11) = 0x0000000000000000
  x28 (  t3) = 0x0000000000000000    x29 (  t4) = 0x0000000000000000
  x30 (  t5) = 0x0000000000000000    x31 (  t6) = 0x0000000000000000

  pc = 0x0000000080000004
  ```

  On MIPS, `regs` also shows `hi` and `lo`, where `mult` and `div` put their results. On ARM64
  and x86-64 it shows the condition flags that compare instructions set and conditional branches
  test. For example, on x86-64 after `movq $3, %rax` and `cmpq $5, %rax` (3 − 5 is negative and
  borrows):
  ```
  pc = 0x000000000040000f
  rflags: CF=1 ZF=0 SF=1 OF=0 ★
  ```
  ARM64 shows the same four flags as `nzcv: N=1 Z=0 C=0 V=0`.

- `stepreg [n]` - Step, then show the registers, like `step` followed by `regs` (alias: `sr`)

- `pc` - Show just the program counter
  ```
  (mapachespim) pc
  pc = 0x0000000080000004
  ```

- `mem <addr|label|section> [len]` - Display memory contents with ASCII sidebar (default 256 bytes)
  ```
  (mapachespim) mem 0x80000000           # By address
  (mapachespim) mem fib_input 8          # By label
  (mapachespim) mem 0x80000000 64        # Show 64 bytes
  (mapachespim) mem .text                # By section name
  (mapachespim) mem .data 128            # Section with length
  ```

  For example, with `riscv/fibonacci` loaded:
  ```
  (mapachespim) mem 0x80000000 64

  0x80000000:  97 02 10 00  93 82 02 00  03 a5 02 00  ef 00 c0 02  |................|
  0x80000010:  97 02 10 00  93 82 42 ff  23 a0 a2 00  93 08 10 00  |......B.#.......|
  0x80000020:  73 00 00 00  13 05 a0 00  93 08 b0 00  73 00 00 00  |s...........s...|
  0x80000030:  93 08 a0 00  73 00 00 00  63 04 05 04  93 02 10 00  |....s...c.......|
  ```

- `list [location]` - Display source code (requires debug symbols) (alias: `l`)
  ```
  (mapachespim) list             # Show source around current PC
  (mapachespim) list fibonacci   # Show source around function
  (mapachespim) list 40          # Show source around line 40
  ```

  For example, with `riscv/fibonacci` loaded:
  ```
  (mapachespim) list fibonacci

  fibonacci.s:
     75: #   sp+16: saved ra (return address)
     76: #   Total: 24 bytes
     77: # ============================================================================
     78: fibonacci:
     79:     # Base case 1: if n == 0, return 0
     80:     beqz    a0, base_case_zero
     81:
     82:     # Base case 2: if n == 1, return 1
     83:     li      t0, 1
     84:     beq     a0, t0, base_case_one
  ```

  Programs loaded from `.s` files always have source info.

### Breakpoints
- `break <addr|label>` - Set breakpoint at an address or label (alias: `b`)
  ```
  (mapachespim) break fibonacci
  Breakpoint set at fibonacci (0x80000038)
  (mapachespim) break 0x80000010
  Breakpoint set at 0x80000010
  ```

- `info breakpoints` - List all breakpoints
  ```
  (mapachespim) info break

  Breakpoints:
    1. 0x80000010  <_start+16>
    2. 0x80000038  <fibonacci>
  ```

- `info symbols` - List all symbols from symbol table (alias: `info sym`)
  ```
  (mapachespim) info symbols

  Symbols (6 total):
    0x80000000  _start
    0x80000038  fibonacci
    0x80000080  base_case_zero
    0x80000088  base_case_one
    0x80100000  fib_input
    0x80100004  fib_result
  ```

- `info sections` - List all ELF sections (alias: `info sec`)
  ```
  (mapachespim) info sections

  ELF Sections:
  Name                            Address         Size  Flags
  ----------------------------------------------------------------------
  .text                        0x80000000          144  AX
  .data                        0x80100000            8  WA

  Flags: W=Write, A=Alloc, X=Execute
  Use 'mem <section>' to view section contents (e.g., mem .data)
  ```

- `delete <addr|label>` - Remove breakpoint at address or label
  ```
  (mapachespim) delete 0x80000010
  Breakpoint removed at 0x0000000080000010
  ```

- `clear` - Remove all breakpoints

### Utility
- `status` - Show simulator status
- `reset` - Restart the program from the beginning (reloads memory and registers; keeps breakpoints)
- `help` - Show all commands
- `quit` / `exit` - Exit console (alias: `q`)

## Example Session

```
$ mapachespim
Welcome to MapacheSPIM. Type help or ? to list commands, or quickstart for a tutorial.

(mapachespim) load riscv/fibonacci
Loaded riscv/fibonacci (RISCV)
Entry point: 0x0000000080000000
Source info: fibonacci.s (34 address mappings)

(mapachespim) break fibonacci
Breakpoint set at fibonacci (0x80000038)

(mapachespim) run
Breakpoint hit at 0x0000000080000038 after 4 instructions
PC = 0x0000000080000038

(mapachespim) step
[0x80000038] 0x63040504  beqz a0, 0x48  <fibonacci>

(mapachespim) regs

x0  (zero) = 0x0000000000000000    x1  (  ra) = 0x0000000080000010 ★
x2  (  sp) = 0x0000000083effff8    x3  (  gp) = 0x0000000000000000
x4  (  tp) = 0x0000000000000000    x5  (  t0) = 0x0000000080100000 ★
x6  (  t1) = 0x0000000000000000    x7  (  t2) = 0x0000000000000000
x8  (  s0) = 0x0000000000000000    x9  (  s1) = 0x0000000000000000
x10 (  a0) = 0x0000000000000007 ★  x11 (  a1) = 0x0000000000000000
x12 (  a2) = 0x0000000000000000    x13 (  a3) = 0x0000000000000000
x14 (  a4) = 0x0000000000000000    x15 (  a5) = 0x0000000000000000
x16 (  a6) = 0x0000000000000000    x17 (  a7) = 0x0000000000000000
x18 (  s2) = 0x0000000000000000    x19 (  s3) = 0x0000000000000000
x20 (  s4) = 0x0000000000000000    x21 (  s5) = 0x0000000000000000
x22 (  s6) = 0x0000000000000000    x23 (  s7) = 0x0000000000000000
x24 (  s8) = 0x0000000000000000    x25 (  s9) = 0x0000000000000000
x26 ( s10) = 0x0000000000000000    x27 ( s11) = 0x0000000000000000
x28 (  t3) = 0x0000000000000000    x29 (  t4) = 0x0000000000000000
x30 (  t5) = 0x0000000000000000    x31 (  t6) = 0x0000000000000000

pc = 0x000000008000003c

(mapachespim) delete fibonacci
Breakpoint removed at 0x0000000080000038

(mapachespim) continue
13
Program exited with code 0 after 458 instructions

(mapachespim) mem fib_input 64

0x80100000:  07 00 00 00  0d 00 00 00  00 00 00 00  00 00 00 00  |................|
0x80100010:  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  |................|
0x80100020:  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  |................|
0x80100030:  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  |................|

(mapachespim) quit
Goodbye!
```

The program prints its result, 13, and the last `mem` shows its data: `fib_input` (7) in the first
word, and the result it stored in `fib_result` (13, or `0d` in hex) in the next. Words are stored little-endian, so the
low byte comes first.

## Register Names

`regs` shows each register by its conventional name. What those registers are for, by ISA:

| Use | RISC-V | MIPS | ARM64 | x86-64 |
|-----|--------|------|-------|--------|
| Arguments | `a0`-`a7` | `$a0`-`$a3` | `x0`-`x7` | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` |
| Return value | `a0` | `$v0` | `x0` | `rax` |
| Return address | `ra` | `$ra` | `x30` (lr) | pushed on the stack by `call` |
| Stack pointer | `sp` | `$sp` | `sp` | `rsp` |
| Frame pointer | `s0` (fp) | `$fp` | `x29` | `rbp` |
| Temporaries (caller-saved) | `t0`-`t6` | `$t0`-`$t9` | `x9`-`x15` | `rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`-`r11` |
| Saved (callee-saved) | `s0`-`s11` | `$s0`-`$s7` | `x19`-`x28` | `rbx`, `rbp`, `r12`-`r15` |
| Always zero | `zero` | `$zero` | `xzr` | - |
| Syscall number | `a7` | `$v0` | `x8` | `rax` |
| Other | | `hi`, `lo` | `nzcv` flags | `rflags` flags |

RISC-V registers can also be written by number (`x0`-`x31`), and `regs` shows both.

## Command Line Options

```bash
mapachespim                          # Launch the console
mapachespim myprog.s                 # Load a program on startup
mapachespim myprog.s --isa riscv64   # ...for a .s file without an .isa directive
mapachespim -e myprog.s              # Run without the console and exit
mapachespim -e myprog.s --max-steps 1000000
mapachespim --copy-examples my-dir   # Copy the bundled examples somewhere editable
mapachespim --version
```

With `-e`, only the program's output goes to stdout, and the exit status is the program's exit code,
1 if it crashed, or 124 if it did not finish within `--max-steps` instructions (default 10,000,000).
This makes `-e` convenient for testing and autograding:

```bash
echo 7 | mapachespim -e fib.s > output.txt
```

## Keyboard Shortcuts

- **Ctrl-C** during `run` - Interrupt execution
- **Ctrl-D** or `quit` - Exit console
- **Tab** - Complete commands, file paths, example names, and labels (after `break`)
- **Enter** on an empty line - Repeat the last command (handy for `step`)
- **Up/Down arrows** - Command history

## Assembling Programs

The simplest way is to `load` your `.s` file; MapacheSPIM assembles it with debug info. To produce
an ELF file instead, use the bundled assembler:

```bash
mapachespim-as -g program.s -o program           # .isa directive in the file
mapachespim-as -g program.s -o program --isa mips32
```

The `-g` flag adds DWARF debug information that maps machine addresses to source lines, which the
`list` command uses. ELF files from other toolchains (such as GNU `as`/`ld` with `-g`) also load,
as long as they are statically linked executables for a supported ISA.

## Differences from SPIM

MapacheSPIM is similar to SPIM but has key differences:

1. **Several ISAs**: RISC-V (RV64IM), MIPS32, ARM64, and x86-64, all with the same commands and syscalls
2. **Real executables**: Programs are assembled to ELF files, so the same binaries work with other tools
3. **Delay slots**: On MIPS, the assembler fills each branch and jump delay slot with a `nop` (like
   GNU `as` in its default `.set reorder` mode), and the simulator executes delay slots as real
   hardware does. Write `.set noreorder` to fill delay slots yourself
4. **Same code as GNU as**: programs assemble to exactly what GNU `as` produces,
   so disassembly matches what you see in textbooks and `objdump`. One deliberate exception follows
   SPIM instead: on MIPS, the two-operand `div $t0, $t1` / `divu $t0, $t1` is the real instruction
   (results in `hi` and `lo`, which `regs` shows), whereas GNU `as` treats it as `div $t0, $t0, $t1`
5. **Runtime checks**: MIPS `div`/`rem` with three operands trap on division by zero and on
   overflow, as in SPIM, and the console reports "Division by zero"
6. **Source display**: `list` shows your source code next to the program counter

## Troubleshooting

**Console won't start:**
- See the install instructions in the [Quick Start Guide](quick-start.md)
- You can always run `python3 -m mapachespim.console`

**Can't load a file:**
- Check the file path is correct; type `examples` to see the bundled programs
- ELF files must be statically linked executables for RISC-V, MIPS, ARM64, or x86-64

**Breakpoint not hit:**
- Verify address is correct: `mem <addr>`
- Check program actually reaches that address
