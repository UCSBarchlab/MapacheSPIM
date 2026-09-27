# Quick Start Guide

Get started with MapacheSPIM in 5 minutes. This guide installs the simulator, runs an example
program, and then has you write and debug your own RISC-V program.

## Install

You need Python 3.9 or newer on Windows, macOS, or Linux. Check with:

```bash
python3 --version
```

Install MapacheSPIM with [pipx](https://pipx.pypa.io/) (recommended; it keeps MapacheSPIM in its own
environment and puts the command on your path):

```bash
pipx install git+https://github.com/UCSBarchlab/MapacheSPIM.git
```

If you don't have pipx, `pip install git+https://github.com/UCSBarchlab/MapacheSPIM.git` works too,
ideally inside a [virtual environment](https://docs.python.org/3/tutorial/venv.html).

Verify the installation:

```bash
mapachespim --version
```

You do not need a cross-compiler or any other tools: MapacheSPIM assembles your programs itself.

## Run an Example

Start the console and list the example programs that come with MapacheSPIM:

```
$ mapachespim
Welcome to MapacheSPIM. Type help or ? to list commands, or quickstart for a tutorial.

(mapachespim) examples riscv

RISC-V 64-bit:
  riscv/array_stats        Array Processing with Loops
  riscv/fibonacci          Recursive Fibonacci Calculator
  riscv/guess_game         Number Guessing Game
  riscv/hello_asm          Your First RISC-V Assembly Program
  riscv/matrix_multiply    3x3 Matrix Multiplication

Load one with, e.g.:  load riscv/array_stats
```

Load one and look at its source code:

```
(mapachespim) load riscv/hello_asm
Loaded riscv/hello_asm (RISCV)
Entry point: 0x0000000080000000
Source info: hello_asm.s (19 address mappings)

(mapachespim) list

hello_asm.s:
   56:     # We need to:
   57:     #   1. Put the string's address in register a0
   58:     #   2. Put the syscall number (4) in register a7
   59:     #   3. Execute the ecall instruction
   60:
   61>     la      a0, hello_msg   # la = "Load Address" - puts address of hello_msg into a0  # <-- PC: 0x80000000
   62:     li      a7, 4           # li = "Load Immediate" - puts the value 4 into a7
   63:     ecall                   # Make the syscall - this prints the string!
   64:
   65:     # ========================================================================
```

The `>` marks the line the program counter (PC) is on. Step through a few instructions:

```
(mapachespim) step 3
hello_asm.s:61: la      a0, hello_msg   # la = "Load Address" - puts address of hello_msg into a0
[0x80000000] 0x17051000  auipc a0, 0x100  <_start>
[0x80000004] 0x13050500  mv a0, a0  <_start+4>
hello_asm.s:62: li      a7, 4           # li = "Load Immediate" - puts the value 4 into a7
[0x80000008] 0x93084000  addi a7, zero, 4  <_start+8>
```

Each source line is followed by the machine instructions it became. Each instruction shows its
address, its bytes, the instruction, and where it is relative to the nearest label. Notice that the
single `la` in the source became two machine instructions (`auipc` and `addi`, which the
disassembler shows as `mv` because its immediate is 0): `la` is a *pseudo-instruction*.

Run the rest of the program:

```
(mapachespim) run
Hello, Assembly!
Your lucky number is: 42
Goodbye!
Program exited with code 0 after 19 instructions
```

Use `reset` to start the program over from the beginning.

## Write Your Own Program

Create a file called `sum.s` in any text editor:

```asm
.isa riscv64                # This file is RISC-V (64-bit)

.data
msg:    .asciz "The sum is: "

.text
.globl _start
_start:
    li   t0, 0              # t0 = sum
    li   t1, 1              # t1 = i
    li   t2, 10             # t2 = limit
loop:
    add  t0, t0, t1         # sum += i
    addi t1, t1, 1          # i++
    ble  t1, t2, loop       # repeat while i <= limit

    la   a0, msg            # print_string(msg)
    li   a7, 4
    ecall
    mv   a0, t0             # print_int(sum)
    li   a7, 1
    ecall
    li   a7, 10             # exit
    ecall
```

Load it; MapacheSPIM assembles it for you:

```
(mapachespim) load sum.s
Assembled sum.s (1160 bytes)
Loaded sum.s (RISCV)
Entry point: 0x0000000080000000
Source info: sum.s (14 address mappings)

(mapachespim) break loop
Breakpoint set at loop (0x8000000c)

(mapachespim) run
Breakpoint hit at 0x000000008000000c after 3 instructions
PC = 0x000000008000000c

(mapachespim) continue
Breakpoint hit at 0x000000008000000c after 3 instructions
PC = 0x000000008000000c

(mapachespim) regs decimal

x0  (zero) = ...................0    x1  (  ra) = ...................0
x2  (  sp) = ..........2213543928    x3  (  gp) = ...................0
x4  (  tp) = ...................0    x5  (  t0) = ...................1 ★
x6  (  t1) = ...................2 ★  x7  (  t2) = ..................10 ★
x8  (  s0) = ...................0    x9  (  s1) = ...................0
x10 (  a0) = ...................0    x11 (  a1) = ...................0
x12 (  a2) = ...................0    x13 (  a3) = ...................0
x14 (  a4) = ...................0    x15 (  a5) = ...................0
x16 (  a6) = ...................0    x17 (  a7) = ...................0
x18 (  s2) = ...................0    x19 (  s3) = ...................0
x20 (  s4) = ...................0    x21 (  s5) = ...................0
x22 (  s6) = ...................0    x23 (  s7) = ...................0
x24 (  s8) = ...................0    x25 (  s9) = ...................0
x26 ( s10) = ...................0    x27 ( s11) = ...................0
x28 (  t3) = ...................0    x29 (  t4) = ...................0
x30 (  t5) = ...................0    x31 (  t6) = ...................0

pc = ..........2147483660
```

`regs` shows every register; a ★ marks the ones that changed since you last looked, so you can see
`t0` (the sum) and `t1` (the counter) changing each time around the loop. `regs decimal` shows the
values in decimal, with dots in place of leading zeros (`set regs-leading-zeros cut` drops them).

When you find a bug, edit `sum.s` and type `reload` to re-assemble it. Your breakpoints stay on
their labels. If there's a mistake in the program, the error tells you the line:

```
(mapachespim) reload

Error: could not assemble sum.s:
  sum.s: Line 13: unknown register 't9' - add  t0, t0, t9
```

To check a program's output without the interactive console, use `-e`:

```bash
$ mapachespim -e sum.s
The sum is: 55
```

## Essential Commands

| Command | Example | What it does |
|---------|---------|--------------|
| load | `load sum.s` or `load riscv/fibonacci` | Load a program or example |
| reload | `reload` | Re-assemble and reload after editing |
| list | `list` | Show your source code around the PC |
| break | `break loop` | Set a breakpoint at a label (or address) |
| run | `run` | Run until the program exits or hits a breakpoint |
| continue | `continue` | Keep running after a breakpoint |
| step | `step` or `step 5` | Execute 1 or N instructions |
| regs | `regs` or `regs decimal` | Show all registers |
| mem | `mem msg 16` or `mem .data` | Show memory at a label, address, or section |
| disasm | `disasm` or `disasm loop 5` | Disassemble instructions |
| reset | `reset` | Restart the program from the beginning |
| info | `info symbols` / `info breakpoints` | List labels or breakpoints |
| examples | `examples` | List the bundled example programs |
| quit | `quit` or Ctrl-D | Exit the console |

Many commands have short aliases: `s` (step), `b` (break), `r` (run), `c` (continue), `d` (disasm),
`l` (list), `q` (quit). Pressing Enter on an empty line repeats the last command, which is handy
for stepping. Type `help <command>` for details on any command.

## Other ISAs

Everything above works the same for MIPS, ARM64, and x86-64. Use `.isa mips32`, `.isa arm64`, or
`.isa x86_64` in your file, and try `examples mips`, `examples arm`, and `examples x86_64`. See the
[Syscall Reference](syscalls.md) for the registers each ISA uses for syscalls.

To get editable copies of all the examples:

```bash
mapachespim --copy-examples my-examples
```

## Troubleshooting

### `mapachespim: command not found`

- With pipx, run `pipx ensurepath` and open a new terminal.
- With pip in a virtual environment, make sure it is activated.
- You can always run `python3 -m mapachespim.console` instead.

### Still Stuck?

- Read the [Console Guide](console-guide.md)
- Look at the [example programs](../../examples/README.md)
- Open an issue on [GitHub](https://github.com/UCSBarchlab/MapacheSPIM/issues)
