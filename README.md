# MapacheSail

Educational RISC-V assembly examples using the Sail RISC-V formal specification model.

## Overview

This repository contains educational materials for teaching RISC-V assembly programming using the official [Sail RISC-V](https://github.com/riscv/sail-riscv) formal specification model as an emulator.

## Contents

- **sail-riscv/** - RISC-V Sail model (git submodule from https://github.com/riscv/sail-riscv)
- **examples/** - Educational RISC-V assembly programs
  - Fibonacci calculator (recursive implementation)
  - Matrix multiplication (3x3 matrices with nested loops)

## Getting Started

### Prerequisites

1. **RISC-V GNU Toolchain**:
   - macOS: `brew tap riscv-software-src/riscv && brew install riscv-tools`
   - Ubuntu: `sudo apt-get install gcc-riscv64-unknown-elf`

2. **Sail Compiler** (for building the emulator):
   - Download from [Sail releases](https://github.com/rems-project/sail/releases) (v0.19.1 or later)
   - Or install from source using opam

### Building the Sail RISC-V Emulator

```bash
cd sail-riscv
./build_simulators.sh
```

The emulator will be built at `sail-riscv/build/c_emulator/sail_riscv_sim`.

### Building and Running Examples

```bash
cd examples
make                  # Build all examples
make run-fibonacci    # Run fibonacci with instruction trace
make run-matrix       # Run matrix multiplication with instruction trace
```

See [examples/README.md](examples/README.md) for more details.

## About Sail

[Sail](https://github.com/rems-project/sail) is a language for describing the instruction-set architecture (ISA) semantics of processors. The RISC-V Sail model is the official formal specification adopted by RISC-V International.

The Sail RISC-V model supports:
- RV32I and RV64I base ISAs
- M, A, F, D, C extensions
- Vector (V) extension
- Cryptography extensions
- Bit manipulation extensions
- Machine, Supervisor, and User privilege modes
- Virtual memory (Sv32, Sv39, Sv48, Sv57)
- And many more extensions

## Educational Use

These examples are designed for undergraduate computer architecture courses to help students:
- Understand RISC-V assembly programming
- Learn calling conventions and stack management
- Practice with memory operations and addressing modes
- Trace instruction execution at the ISA level

## License

- The Sail RISC-V model is licensed under the BSD 2-Clause License
- Educational examples in this repository are provided for teaching purposes

## Acknowledgments

The Sail RISC-V model was originally developed by Prashanth Mundkur at SRI International and further developed by researchers at the University of Cambridge and others in the RISC-V community.
