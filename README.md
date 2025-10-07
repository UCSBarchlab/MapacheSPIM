# MapacheSPIM

Educational RISC-V Assembly Debugger with SPIM-like Interface

MapacheSPIM is an interactive debugger for RISC-V assembly programs, built on the official Sail formal specification. It provides a SPIM-like debugging experience with enhanced features for students learning computer architecture.

## Quick Start

```bash
# Clone and setup
git clone --recursive https://github.com/your-org/MapacheSPIM.git
cd MapacheSPIM
./scripts/setup.sh  # One-command setup (coming soon)

# Or manual install
cd backends/riscv/sail-riscv && ./build_simulators.sh && cd ../../..
cd libsailsim/build && cmake .. && make && cd ../..
pip3 install -e .

# Start debugging
mapachespim
(mapachespim) load examples/riscv/fibonacci/fibonacci
(mapachespim) break main
(mapachespim) run
(mapachespim) step
```

[Full Quick Start Guide](docs/user/quick-start.md) - Get started in 5 minutes

## Features

### For Students

- **Enhanced Step Display** - See instructions, bytes, and disassembly
  ```
  [0x80000000] <main>  0x9302a000  addi x5, x0, 0xa
  Register changes:
    x5  (  t0) : 0x0000000000000000 -> 0x000000000000000a  *
  ```

- **Symbol Table Support** - Use function names instead of addresses
  ```
  (mapachespim) break fibonacci    # Set breakpoint by name
  (mapachespim) info symbols       # List all functions
  ```

- **Automatic Register Tracking** - See what changed after each step

- **SPIM-like Commands** - Familiar interface for MIPS students
  - load, step, run, break, continue
  - regs, mem, disasm, info
  - Short aliases: s, r, b, c, d

### For Developers

- **ISA-Agnostic Design** - Ready to support ARM, CHERI, and more
- **Formal Specification** - Built on Sail's proven formal models
- **Extensible Architecture** - Clean APIs for adding features
- **Comprehensive Tests** - 78 tests, 100% passing

## Documentation

### For Users
- [Quick Start Guide](docs/user/quick-start.md) - Get started in 5 minutes
- [Console Guide](docs/user/console-guide.md) - Complete command reference
- [Examples Guide](examples/README.md) - Learn from example programs

### For Developers
- [Architecture Overview](docs/developer/architecture.md) - System design
- [Multi-ISA Strategy](docs/developer/multi-isa.md) - How we support multiple ISAs
- [Testing Guide](docs/developer/testing.md) - Testing practices

### Design and History
- [Implementation Plan](docs/design/implementation-plan.md) - Project roadmap
- [SPIM Comparison](docs/design/spim-comparison.md) - Feature comparison
- [Enhancement History](docs/design/enhancement-history.md) - What we built

[Documentation Index](docs/README.md) - Browse all documentation

## What Makes This Special?

### Built on Formal Specifications

MapacheSPIM uses the [Sail RISC-V](https://github.com/riscv/sail-riscv) formal specification - the official model adopted by RISC-V International. This means:

- Proven correct - Formally verified ISA semantics
- Complete - All extensions (M, A, F, D, C, V, etc.)
- Up-to-date - Maintained by ISA experts
- Educational - Teaches formal methods alongside assembly

### ISA-Agnostic Architecture

The core library is completely ISA-agnostic, making it easy to add new architectures:

```
MapacheSPIM/
├── libsailsim/          # ISA-agnostic core
├── backends/riscv/      # RISC-V backend (current)
├── backends/arm/        # ARM backend (future)
└── backends/cheri/      # CHERI backend (future)
```

Adding a new ISA just requires adding the Sail backend submodule - zero core code changes needed.

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

### Quick Install

```bash
# Clone with submodules
git clone --recursive https://github.com/your-org/MapacheSPIM.git
cd MapacheSPIM

# Build Sail backend
cd backends/riscv/sail-riscv
./build_simulators.sh
cd ../../..

# Build C library
cd libsailsim/build
cmake ..
make
cd ../..

# Install Python package
pip3 install -e .

# Verify
mapachespim --version
```

See the [Quick Start Guide](docs/user/quick-start.md) for detailed instructions.

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
python3 tests/test_console_working.py      # Console tests (24 tests)
python3 tests/test_disasm_comprehensive.py # Disassembly tests (30 tests)
python3 tests/test_symbols.py              # Symbol tests (24 tests)

# All 78 tests passing
```

## Project Structure

```
MapacheSPIM/
├── docs/                    # All documentation
│   ├── user/               # User guides
│   ├── developer/          # Developer docs
│   ├── design/             # Design documents
│   └── history/            # Historical records
├── libsailsim/             # C library (ISA-agnostic)
├── mapachespim/            # Python bindings and console
├── backends/               # ISA backends
│   └── riscv/             # RISC-V backend (submodule)
├── examples/               # Example programs
│   └── riscv/             # RISC-V examples
├── tests/                  # Test suite
└── scripts/                # Build and utility scripts
```

## Roadmap

### Current (Phase 1-5: POC Complete)
- [x] POC 1: C wrapper library (libsailsim)
- [x] POC 2: Python bindings
- [x] POC 3: Interactive console
- [x] POC 4: Register and memory inspection
- [x] POC 5: Disassembly support
- [x] Enhanced step display
- [x] Register change tracking
- [x] Symbol table support

### Near-term
- [x] Documentation consolidation
- [x] Multi-ISA structure
- [x] Project rename (to MapacheSPIM)
- [ ] One-command setup script
- [ ] C++ console foundation

### Future
- [ ] ARM backend support
- [ ] CHERI backend support
- [ ] Watchpoints and conditional breakpoints
- [ ] Call stack / backtrace
- [ ] TUI interface with panels
- [ ] Performance optimizations

## Contributing

We welcome contributions! Here's how to help:

1. Try it out - Use it for teaching or learning
2. Report bugs - Open issues with reproduction steps
3. Suggest features - Tell us what students need
4. Add examples - Share educational programs
5. Improve docs - Help others understand
6. Add backends - Support new ISAs

See CONTRIBUTING.md (coming soon) for guidelines.

## License

- Sail RISC-V - BSD 2-Clause License
- MapacheSPIM - [Your License Here]
- Examples - Educational use

## Acknowledgments

- Sail RISC-V Team - Prashanth Mundkur, Peter Sewell, and contributors
- RISC-V International - For adopting Sail as the formal specification
- Sail Language - Kathyrn Gray, Gabriel Kerneis, and the Sail team
- SPIM - James Larus, for inspiring the interface

## Contact

- Issues: [GitHub Issues](https://github.com/your-org/MapacheSPIM/issues)
- Discussions: [GitHub Discussions](https://github.com/your-org/MapacheSPIM/discussions)
- Email: [your-email@example.com]

[Get Started in 5 Minutes](docs/user/quick-start.md)
