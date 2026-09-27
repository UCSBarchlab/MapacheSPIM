# MapacheSPIM <img src="https://github.com/UCSBarchlab/MapacheSPIM/raw/main/docs/Mapache.png" alt="MapacheSPIM Logo" width="100">

MapacheSPIM is a SPIM-like simulator for assembly programming built on the Unicorn Engine CPU emulator. It provides
an interactive, console-based environment for learning assembly language, debugging programs
instruction-by-instruction, and exploring computer architecture concepts across multiple ISAs.

### Why MapacheSPIM?

When teaching computer architecture or learning a new ISA, you need a simple, interactive way to see exactly
what's happening at the machine level. Traditional simulators are often complex, opaque, or tied to a single
architecture. MapacheSPIM provides a
[SPIM](https://en.wikipedia.org/wiki/SPIM)-like experience - familiar
commands, clear output, and the ability to step through code one instruction at a time - powered by the
battle-tested [Unicorn Engine](https://www.unicorn-engine.org/) CPU emulator.

MapacheSPIM is designed for:
- **Students** learning assembly programming and computer architecture
- **Educators** teaching courses on computer systems
- **Researchers** exploring ISA design and formal methods
- **Anyone** who wants to understand what's really happening inside the machine

The simulator shows you everything: instruction bytes, disassembly, register changes, memory contents, and symbol 
information. You can set breakpoints by function name, step through code, and see exactly which registers changed 
and why.

### Install

MapacheSPIM is a pure Python package that runs on Windows, macOS (Intel and Apple Silicon), and
Linux with Python 3.9 or newer. No cross-compiler or other toolchain is needed: it includes its own
assembler.

The easiest way to install it is with [pipx](https://pipx.pypa.io/), which puts the
`mapachespim` command on your path in its own isolated environment:

```bash
pipx install git+https://github.com/UCSBarchlab/MapacheSPIM.git
```

or, with [uv](https://docs.astral.sh/uv/): `uv tool install git+https://github.com/UCSBarchlab/MapacheSPIM.git`.
Plain `pip install git+https://github.com/UCSBarchlab/MapacheSPIM.git` works too (ideally inside a
virtual environment).

Check that it worked:

```bash
mapachespim --version
```

**Dependencies** (installed automatically):
- `unicorn` - CPU emulator framework
- `capstone` - Disassembler
- `pyelftools` - ELF file parsing
- `keystone-engine` - Assembler for ARM64 and x86-64, installed automatically on x86 machines. RISC-V
  and MIPS use MapacheSPIM's built-in assembler, so they work everywhere; see
  [ISA support](#multi-isa-support) for details.

### Running MapacheSPIM

Start the console by typing:

```bash
mapachespim
```

Type `examples` to see the example programs that come with MapacheSPIM, `quickstart` for a short
tutorial, or `help` for all commands.

### A Quick Example

Here is an example loading the bundled RISC-V Fibonacci program, stopping at a function, and
looking at the source and machine state:

```
$ mapachespim
Welcome to MapacheSPIM. Type help or ? to list commands, or quickstart for a tutorial.

(mapachespim) load riscv/fibonacci
Loaded riscv/fibonacci (RISCV)
Entry point: 0x0000000080000000
Source info: fibonacci.s (32 address mappings)

(mapachespim) break fibonacci
Breakpoint set at fibonacci (0x80000038)

(mapachespim) run
Breakpoint hit at 0x0000000080000038 after 6 instructions
PC = 0x0000000080000038

(mapachespim) list
fibonacci.s:
   84: fibonacci:
   85:     # Base case 1: if n == 0, return 0
   86>     beqz    a0, base_case_zero  # <-- PC: 0x80000038
   87:
   88:     # Base case 2: if n == 1, return 1
   89:     li      t0, 1

(mapachespim) step
[0x80000038] 0x63040504  beqz a0, 0x48  <fibonacci>

(mapachespim) step
[0x8000003c] 0x93021000  addi t0, zero, 1  <fibonacci+4>

(mapachespim) regs

x0  (zero) = 0x0000000000000000    x1  (  ra) = 0x0000000080000018 ★
x2  (  sp) = 0x0000000080181000 ★  x3  (  gp) = 0x0000000000000000
x4  (  tp) = 0x0000000000000000    x5  (  t0) = 0x0000000000000001 ★
...
x10 (  a0) = 0x0000000000000007 ★  x11 (  a1) = 0x0000000000000000
...

pc = 0x0000000080000040

(mapachespim) mem fib_input 8

0x80100000:  07 00 00 00  00 00 00 00                              |........|

(mapachespim) quit
Goodbye!
```

At any point when execution is stopped, you can inspect registers and memory. The full 64-bit value of each
register is shown in hex along with its ABI name (like `a0`, `sp`, `ra`). A star (★) appears next to registers
that have changed since you last looked, to help you follow the execution of the program. Memory is shown in
bytes, grouped into 4-byte words for easier reading.

### Writing Your Own Programs

Write your program in a `.s` file and load it directly; MapacheSPIM assembles it for you (with debug
info, so `list` shows your source):

```asm
# hello.s
.isa riscv64            # which ISA this file is for

.data
msg: .asciz "Hello, world!\n"

.text
.globl _start
_start:
    la   a0, msg        # print_string(msg)
    li   a7, 4
    ecall
    li   a7, 10         # exit
    ecall
```

```
(mapachespim) load hello.s
Assembled hello.s (1096 bytes)
Loaded hello.s (RISCV)
...
(mapachespim) run
Hello, world!
Program exited with code 0 after 6 instructions
```

After editing the file, type `reload` to re-assemble and load the new version; breakpoints on labels
follow their labels. If your file has no `.isa` line, give the ISA when loading: `load hello.s riscv64`.

To start from the examples, copy them somewhere you can edit them:

```bash
mapachespim --copy-examples my-examples
```

You can also run a program without the interactive console, which is handy for testing and
autograding. The exit status is the program's exit code (1 on a runtime error, 124 if it doesn't finish
within `--max-steps` instructions):

```bash
mapachespim -e hello.s
```

The standalone assembler writes an ELF file if you want one: `mapachespim-as -g hello.s -o hello`.

## Features

### Enhanced Step Display

Every step shows:
- The address (`0x80000030`)
- The instruction bytes (`0x13050005`)
- The disassembly (`addi x10, x0, 0x5`)
- The symbol name (`<main>`)

### Symbol Table Support

Use function names instead of memorizing addresses:
```
(mapachespim) break fibonacci    # Set breakpoint by name
(mapachespim) info symbols       # List all functions
(mapachespim) disasm fibonacci   # Disassemble a function
```

### I/O Syscalls

SPIM-compatible syscalls for printing and input:
```assembly
# Print "Hello, World!"
la a0, msg          # Load string address
li a7, 4            # Syscall 4 = print_string
ecall

# Exit program
li a7, 10           # Syscall 10 = exit
ecall
```

Supported syscalls: `print_int` (1), `print_string` (4), `read_int` (5), `exit` (10), `print_char` (11), `read_char` (12), `exit2` (17), `exit_code` (93)

See [Syscall Reference](https://github.com/UCSBarchlab/MapacheSPIM/blob/main/docs/user/syscalls.md) for complete details.

### Console Commands

Familiar SPIM-like interface:

| Command | Alias | Description |
|---------|-------|-------------|
| `load <file>` | | Load a `.s` file (assembled for you), an ELF executable, or an example |
| `reload` | | Re-assemble and reload the current program after editing |
| `examples` | | List the bundled example programs |
| `step [n]` | `s` | Execute n instructions (default 1) |
| `run [max]` | `r` | Run until exit, breakpoint, or max instructions |
| `break <addr>` | `b` | Set breakpoint at address or label |
| `continue` | `c` | Continue after breakpoint |
| `reset` | | Restart the program from the beginning |
| `regs` | | Show all registers |
| `pc` | | Show program counter |
| `mem <addr> [len]` | | Show memory contents (address, label, or section) |
| `disasm <addr> [n]` | `d` | Disassemble n instructions |
| `list` | `l` | Show source code around the PC |
| `info symbols` | | List all symbols |
| `info sections` | | List ELF sections |
| `quit` | `q` | Exit simulator |

See [Console Guide](https://github.com/UCSBarchlab/MapacheSPIM/blob/main/docs/user/console-guide.md) for complete command reference.

## What Makes This Special?

### Built on Unicorn Engine

MapacheSPIM is powered by the [Unicorn Engine](https://www.unicorn-engine.org/), a battle-tested CPU emulator framework based on QEMU. This means:

- **Reliable** - Built on the same codebase that powers countless virtual machines
- **Multi-ISA** - Support for RISC-V, ARM64, x86-64, and MIPS32
- **Fast** - Efficient emulation using proven QEMU technology
- **Easy to Install** - Pure `pip install`, no C/C++ compilation required

### Multi-ISA Support

MapacheSPIM supports four instruction set architectures, each with the same console commands,
syscalls, and a matching set of example programs:

| ISA | Examples | Assembling `.s` files |
|-----|----------|-----------------------|
| RISC-V 64-bit (RV64IM) | `examples/riscv/` | Built in, works everywhere\* |
| MIPS32 (big-endian) | `examples/mips/` | Built in, works everywhere\* |
| ARM64 (AArch64) | `examples/arm/` | Uses [Keystone](https://www.keystone-engine.org/) |
| x86-64 (AT&T or Intel syntax) | `examples/x86_64/` | Uses [Keystone](https://www.keystone-engine.org/) |

Keystone is installed automatically on x86 machines (Windows, Intel Macs, x86 Linux). Its PyPI release
has no prebuilt package for ARM machines such as Apple Silicon Macs, so it is not installed there by
default; you can still run and debug ARM64 and x86-64 programs (including all the bundled examples), and
can try `pip install 'mapachespim[keystone]'` to build Keystone from source (this needs CMake and a C++
compiler).

\* The built-in RISC-V and MIPS assemblers produce byte-for-byte the same machine code as GNU `as`
(the standard assembler used in textbooks and courses), including its pseudo-instruction expansions,
data directives, and branch relaxation. This is checked continuously by randomized differential tests
that assemble hundreds of thousands of instructions with both and compare the results.

Loading an ELF file detects its ISA automatically.

### Student-Friendly Design

Inspired by SPIM, designed for education:

- **Clear Output** - See exactly what changed, no guessing
- **Symbolic Debugging** - Use function names, not just addresses
- **Helpful Errors** - Understand what went wrong
- **Progressive Complexity** - Start simple, add features as needed
- **Instant Feedback** - See results of every instruction

## Documentation

- [Quick Start Guide](https://github.com/UCSBarchlab/MapacheSPIM/blob/main/docs/user/quick-start.md) - Get running in 5 minutes
- [Console Guide](https://github.com/UCSBarchlab/MapacheSPIM/blob/main/docs/user/console-guide.md) - Complete command reference
- [Syscall Reference](https://github.com/UCSBarchlab/MapacheSPIM/blob/main/docs/user/syscalls.md) - I/O syscalls for programs
- [Examples Guide](https://github.com/UCSBarchlab/MapacheSPIM/blob/main/examples/README.md) - Learn from example programs

## Development

```bash
git clone https://github.com/UCSBarchlab/MapacheSPIM.git
cd MapacheSPIM
pip install -e ".[dev]"

python -m pytest tests/          # run the test suite
ruff check mapachespim/          # lint
ruff format mapachespim/         # format
mypy mapachespim/                # type check
make -C examples DEBUG=1         # rebuild the example binaries
```

See [docs/RELEASING.md](https://github.com/UCSBarchlab/MapacheSPIM/blob/main/docs/RELEASING.md) for how to publish a release.

## License

- Unicorn Engine - GPLv2 License
- Capstone - BSD License
- MapacheSPIM - MIT License
- Examples - Educational use

## Contact

- Issues: [GitHub Issues](https://github.com/UCSBarchlab/MapacheSPIM/issues)
- Discussions: [GitHub Discussions](https://github.com/UCSBarchlab/MapacheSPIM/discussions)

<img src="https://github.com/UCSBarchlab/MapacheSPIM/raw/main/docs/Mapache.png" alt="MapacheSPIM Logo" width="300">
