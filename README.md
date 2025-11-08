# MapacheSPIM <img src="docs/Mapache.png" alt="MapacheSPIM Logo" width="100">

MapacheSPIM is a SPIM-like simulator for assembly programming built on the Sail formal specification. It provides 
an interactive, console-based environment for learning assembly language, debugging programs 
instruction-by-instruction, and exploring computer architecture concepts.  This is code is experimental and not supported just yet.

### Why MapacheSPIM?

When teaching computer architecture or learning a new ISA, you need a simple, interactive way to see exactly 
what's happening at the machine level. Traditional simulators are often complex, opaque, or tied to a single 
architecture. MapacheSPIM provides a 
[SPIM](https://en.wikipedia.org/wiki/SPIM)-like experience - familiar 
commands, clear output, and the ability to step through code one instruction at a time - but built on formally 
verified ISA specifications using the [Sail language](https://github.com/rems-project/sail).

MapacheSPIM is designed for:
- **Students** learning assembly programming and computer architecture
- **Educators** teaching courses on computer systems
- **Researchers** exploring ISA design and formal methods
- **Anyone** who wants to understand what's really happening inside the machine

The simulator shows you everything: instruction bytes, disassembly, register changes, memory contents, and symbol 
information. You can set breakpoints by function name, step through code, and see exactly which registers changed 
and why.

### Install

The easiest way to get started with MapacheSPIM is to clone from GitHub:

```git clone https://github.com/your-org/MapacheSPIM.git
cd MapacheSPIM
pip install -e .
```

**Prerequisites:**
- Python 3.8+
- CMake 3.10+ (for building the C backend)
- C++ compiler (GCC or Clang)
- RISC-V toolchain (optional, for compiling your own assembly)

### Running MapacheSPIM

Run the console by typing:

```mapachespim
```

This will start the interactive console where you can load programs, set breakpoints, step through code, and 
inspect machine state. Type `help` at the console to see available commands.

### A Quick Example

Here is an example loading a RISC-V fibonacci program, stepping through the first few instructions, and examining 
the machine state:

```
$ mapachespim
Welcome to MapacheSPIM. Type help or ? to list commands.

(mapachespim) load examples/riscv/fibonacci/fibonacci
Loaded examples/riscv/fibonacci/fibonacci
Entry point: 0x0000000080000000

(mapachespim) info symbols
Symbols (11 total):
  0x80000000  _start
  0x80000034  exit_loop
  0x80000038  fibonacci
  0x80000080  base_case_zero
  ...

(mapachespim) break fibonacci
Breakpoint set at fibonacci (0x80000038)

(mapachespim) run
Breakpoint hit at 0x0000000080000038 after 6 instructions
PC = 0x0000000080000038

(mapachespim) step
[0x80000038] 0x63040504  beq x10, x0, 0x48  <fibonacci>

(mapachespim) step
[0x8000003c] 0x93021000  addi x5, x0, 0x1  <fibonacci+4>

(mapachespim) continue
Breakpoint hit at 0x0000000080000038 after 7 instructions
PC = 0x0000000080000038

(mapachespim) regs

(mapachespim) regs

x0  (zero) = 0x0000000000000000    x1  (  ra) = 0x000000008000005c ★ 
x2  (  sp) = 0x0000000083efffe8 ★  x3  (  gp) = 0x0000000000000000   
x4  (  tp) = 0x0000000000000000    x5  (  t0) = 0x0000000000000001 ★ 
x6  (  t1) = 0x0000000000000000    x7  (  t2) = 0x0000000000000000   
x8  (  s0) = 0x0000000000000000    x9  (  s1) = 0x0000000000000000   
x10 (  a0) = 0x0000000000000006 ★  x11 (  a1) = 0x0000000000001000   
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

pc = 0x0000000080000038

(mapachespim) mem .text

0x80000000:  17 01 f0 03  13 01 01 00  97 02 00 00  93 82 82 08  |................|
0x80000010:  03 a5 02 00  ef 00 40 02  97 02 00 00  93 82 c2 07  |......@.........|
0x80000020:  23 a0 a2 00  93 02 10 00  17 13 00 00  13 03 83 fd  |#...............|
0x80000030:  23 30 53 00  6f 00 00 00  63 04 05 04  93 02 10 00  |#0S.o...c.......|
0x80000040:  63 04 55 04  13 01 81 fe  23 38 11 00  23 34 81 00  |c.U.....#8..#4..|
0x80000050:  23 30 a1 00  13 05 f5 ff  ef f0 1f fe  13 04 05 00  |#0..............|
0x80000060:  03 35 01 00  13 05 e5 ff  ef f0 1f fd  33 05 a4 00  |.5..........3...|
0x80000070:  83 30 01 01  03 34 81 00  13 01 81 01  67 80 00 00  |.0...4......g...|
0x80000080:  13 05 00 00  67 80 00 00  13 05 10 00  67 80 00 00  |....g.......g...|

(mapachespim) quit
Goodbye!
```

At any point when execution is stopped, you can inspect registers and memory. The full 64-bit value of each 
register is shown in hex along with its ABI name (like `a0`, `sp`, `ra`). A star (★) appears next to registers
that have changed to help you follow the execution of the program.  Memory is shown in bytes, grouped into 
4-byte words for easier reading.

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

Supported syscalls: `print_int` (1), `print_string` (4), `read_int` (5), `exit` (10), `print_char` (11), `read_char` (12), `exit_code` (93)

See [Syscall Reference](docs/user/syscalls.md) for complete details.

### Console Commands

Familiar SPIM-like interface:

| Command | Alias | Description |
|---------|-------|-------------|
| `load <file>` | | Load an ELF executable |
| `step [n]` | `s` | Execute n instructions (default 1) |
| `run [max]` | `r` | Run until halt or max instructions |
| `break <addr>` | `b` | Set breakpoint at address or symbol |
| `continue` | `c` | Continue after breakpoint |
| `regs` | | Show all registers |
| `pc` | | Show program counter |
| `mem <addr> [len]` | | Show memory contents |
| `disasm <addr> [n]` | `d` | Disassemble n instructions |
| `info symbols` | | List all symbols |
| `info sections` | | List ELF sections |
| `list` | `l` | Show source code (if debug info) |
| `quit` | `q` | Exit simulator |

See [Console Guide](docs/user/console-guide.md) for complete command reference.

## What Makes This Special?

### Built on Formal Specifications

MapacheSPIM uses the [Sail RISC-V](https://github.com/riscv/sail-riscv) formal specification - the official model adopted by RISC-V International. This means:

- **Formally Verified** - ISA semantics are mathematically proven correct
- **Complete** - All RISC-V extensions supported (RV32/64 I/M/A/F/D/C)
- **Up-to-Date** - Maintained by ISA experts, always current
- **Educational** - Learn formal methods alongside assembly

The simulator executes the *exact* same Sail code that's used to verify RISC-V processors. You're learning from the official specification, not someone's interpretation.

### ISA-Agnostic Architecture

The core simulator is completely ISA-independent:

```
MapacheSPIM/
├── lib/                 # ISA-agnostic core (C/Python)
├── backends/riscv/      # RISC-V Sail backend
├── backends/arm/        # ARM backend (future)
└── backends/cheri/      # CHERI backend (future)
```

Adding a new architecture just requires adding a Sail specification - the console, debugging tools, and Python API work unchanged. This makes MapacheSPIM ideal for ISA research and exploring new architectures.

### Student-Friendly Design

Inspired by SPIM, designed for education:

- **Clear Output** - See exactly what changed, no guessing
- **Symbolic Debugging** - Use function names, not just addresses
- **Helpful Errors** - Understand what went wrong
- **Progressive Complexity** - Start simple, add features as needed
- **Instant Feedback** - See results of every instruction

## Documentation

- [Quick Start Guide](docs/user/quick-start.md) - Get running in 5 minutes
- [Console Guide](docs/user/console-guide.md) - Complete command reference
- [Syscall Reference](docs/user/syscalls.md) - I/O syscalls for programs
- [Examples Guide](examples/README.md) - Learn from example programs

## Testing

```bash
# Run all test suites (137 tests total)
python3 tests/test_simulator.py              # API tests (31 tests)
python3 tests/test_console_working.py        # Console tests (38 tests)
python3 tests/test_disasm_comprehensive.py   # Disassembly tests (30 tests)
python3 tests/test_symbols.py                # Symbol tests (24 tests)
python3 tests/test_program_correctness.py    # Correctness tests (10 tests)
python3 tests/test_io_syscalls.py            # I/O syscall tests (4 tests)
```

All tests verify:
- Correct program execution (fibonacci, matrix multiplication)
- Console command functionality
- Symbol table handling
- Disassembly accuracy
- Syscall behavior

## License

- Sail RISC-V - BSD 2-Clause License
- MapacheSPIM - [Your License Here]
- Examples - Educational use

## Contact

- Issues: [GitHub Issues](https://github.com/your-org/MapacheSPIM/issues)
- Discussions: [GitHub Discussions](https://github.com/your-org/MapacheSPIM/discussions)

<img src="docs/Mapache.png" alt="MapacheSPIM Logo">
