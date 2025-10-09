# MapacheSPIM

MapacheSPIM is a simulator for assembly programming built on the Sail formal specification.  The goals of the project
are ease of use for begginers and students, extensibility for researchers, ISA independence, and ease of debugging.
It provides a SPIM-like programing and debugging experience across ISAs with features that include:

- Enhanced step display - See instructions, register changes, and symbols
- Symbol table support - Use function names for breakpoints
- Register tracking - Automatic highlighting of changes
- Formal specification - Built on Sail's proven models
- ISA-agnostic design - Ready to support ARM, CHERI, and more

Perfect for computer architecture courses, assembly programming labs, ISA research and education, and formal methods teaching.
Less useful if you want timing, power, or multicore operation.

[Full Quick Start Guide](docs/user/quick-start.md) - Get started in 5 minutes

## Features

### For Students

- **Enhanced Step Display** - See instructions, bytes, and disassembly
  ```
  [0x80000000] 0x9302a000  addi x5, x0, 0xa  <main>
  Register changes:
    x5  (  t0) : 0x0000000000000000 -> 0x000000000000000a  *
  ```

- **Symbol Table Support** - Use function names instead of addresses
  ```
  (mapachespim) break fibonacci    # Set breakpoint by name
  (mapachespim) info symbols       # List all functions
  ```

- **Automatic Register Tracking** - See what changed after each step

- **I/O Syscalls** - SPIM-compatible syscalls for printing and input
  - print_int, print_string, print_char
  - read_int, read_char
  - exit, exit_code

- **SPIM-like Commands** - Familiar interface for MIPS students
  - load, step, run, break, continue
  - regs, mem, disasm, info
  - Short aliases: s, r, b, c, d

### For Developers

- **ISA-Agnostic Design** - Ready to support ARM, CHERI, and more
- **Formal Specification** - Built on Sail's proven formal models
- **Extensible Architecture** - Clean APIs for adding features

## Documentation

### For Users
- [Quick Start Guide](docs/user/quick-start.md) - Get started in 5 minutes
- [Console Guide](docs/user/console-guide.md) - Complete command reference
- [Syscall Reference](docs/user/syscalls.md) - I/O syscalls for programs
- [Examples Guide](examples/README.md) - Learn from example programs

## What Makes This Special?

### Built on Formal Specifications

MapacheSPIM uses the [Sail RISC-V](https://github.com/riscv/sail-riscv) formal specification - the official model adopted by RISC-V 
International. This means:

- Built on clear and widely used spec - Formally verified ISA semantics
- Complete - All RISC-V extensions supported (M, A, F, D, C, V, etc.)
- Up-to-date - Maintained by ISA experts
- Educational - Teaches formal methods alongside assembly

### ISA-Agnostic Architecture

The core library is completely ISA-agnostic, making it "easy" to add new architectures:

```
MapacheSPIM/
├── lib/                 # ISA-agnostic core
├── backends/riscv/      # RISC-V backend (current)
├── backends/arm/        # ARM backend (future)
└── backends/cheri/      # CHERI backend (future)
```

Adding a new ISA, in theory, just requires adding the Sail backend submodule - zero core code changes needed.

### Student-Friendly Design

Inspired by SPIM, designed for education:

- Clear output - See exactly what changed
- Symbolic debugging - Use function names
- Helpful errors - Understand what went wrong
- Progressive complexity - Start simple, add features as needed

## Installation

### Prerequisites

- Python 3.8+ (python3 --version)
- CMake 3.10+ (cmake --version)
- C++ compiler (GCC or Clang)
- RISC-V toolchain (for compiling examples)

## Example Session

```
$ mapachespim
Welcome to MapacheSPIM. Type help or ? to list commands.

(mapachespim) load examples/riscv/fibonacci/fibonacci
Loaded examples/riscv/fibonacci/fibonacci
Entry point: 0x0000000080000000

(mapachespim) info symbols
Symbols (22 total):
  0x80000000  _start
  0x80000030  main
  0x80000038  fibonacci
  ...

(mapachespim) break main
Breakpoint set at main (0x80000030)

(mapachespim) run
Breakpoint hit at main (0x80000030)

(mapachespim) step
[0x80000030] <main>  0x13050005  addi x10, x0, 0x5
Register changes:
  x10 (  a0) : 0x0000000000000000 -> 0x0000000000000005  *

(mapachespim) regs
x0  (zero) = 0x0000000000000000  x1  (  ra) = 0x0000000000000000
x2  (  sp) = 0x0000000083f00000  x3  (  gp) = 0x0000000000000000
...
x10 (  a0) = 0x0000000000000005  ...

(mapachespim) continue
Program halted after 42 instructions

(mapachespim) quit
Goodbye!
```

## Testing

```bash
# Run all tests
python3 tests/test_console_working.py      # Console tests (38 tests)
python3 tests/test_disasm_comprehensive.py # Disassembly tests (30 tests)
python3 tests/test_symbols.py              # Symbol tests (24 tests)
python3 tests/test_program_correctness.py  # Correctness tests (10 tests)
python3 tests/test_io_syscalls.py          # I/O syscall tests (4 tests)

# All 137 tests passing
```

## License

- Sail RISC-V - BSD 2-Clause License
- MapacheSPIM - [Your License Here]
- Examples - Educational use

## Contact

- Issues: [GitHub Issues](https://github.com/your-org/MapacheSPIM/issues)
- Discussions: [GitHub Discussions](https://github.com/your-org/MapacheSPIM/discussions)

---

<p align="center">
  <img src="docs/Mapache.png" alt="MapacheSPIM Logo" width="150">
</p>

