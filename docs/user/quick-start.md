# Quick Start Guide

Get started with MapacheSPIM in 5 minutes. This guide will help you install the simulator and debug your first RISC-V program.

## Prerequisites

You'll need:
- macOS or Linux (Windows via WSL)
- Python 3.8+
- CMake 3.10+
- C++ compiler (GCC or Clang)

Check your Python version:
```bash
python3 --version  # Should be 3.8 or higher
```

## Installation

### Option 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone --recursive https://github.com/your-org/MapacheSPIM.git
cd MapacheSPIM

# One-command setup (if available)
./scripts/setup.sh
```

### Option 2: Manual Install

```bash
# Clone with submodules
git clone --recursive https://github.com/your-org/MapacheSPIM.git
cd MapacheSPIM

# Build Sail RISC-V backend
cd backends/riscv/sail-riscv
./build_simulators.sh
cd ../../..

# Build C library
cd lib
mkdir -p build && cd build
cmake ..
make
cd ../..

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python package
pip install -e .

# Verify installation
mapachespim --version
```

## Your First Program

Let's debug a simple Fibonacci program that's already included.

### Step 1: Start the Console

```bash
mapachespim
```

You'll see:
```
Welcome to MapacheSPIM. Type help or ? to list commands.
(mapachespim)
```

### Step 2: Load a Program

```
(mapachespim) load examples/riscv/fibonacci/fibonacci
Loaded examples/riscv/fibonacci/fibonacci
Entry point: 0x0000000080000000
```

### Step 3: See Available Symbols

```
(mapachespim) info symbols
```

You'll see function names and their addresses.

### Step 4: Set a Breakpoint

```
(mapachespim) break main
Breakpoint set at main (0x80000030)
```

### Step 5: Run to Breakpoint

```
(mapachespim) run
Breakpoint hit at main (0x80000030)
```

### Step 6: Step Through Code

```
(mapachespim) step
[0x80000030] <main>  0x13050005  addi x10, x0, 0x5
Register changes:
  x10 (  a0) : 0x0000000000000000 -> 0x0000000000000005  *
```

You just saw:
- The address (0x80000030)
- The function name (<main>)
- The instruction bytes (0x13050005)
- The disassembly (addi x10, x0, 0x5)
- Which register changed

### Step 7: Inspect Registers

```
(mapachespim) regs
```

See all 32 registers with their ABI names and values.

### Step 8: Continue Execution

```
(mapachespim) step 5
```

Step through 5 more instructions to see the program flow.

### Step 9: Quit

```
(mapachespim) quit
Goodbye!
```

## Essential Commands

Here are the commands you'll use most:

| Command | Example | What it does |
|---------|---------|--------------|
| load | load examples/riscv/fibonacci/fibonacci | Load a program |
| break | break main | Set breakpoint at function |
| run | run | Run until breakpoint/halt |
| step | step or step 5 | Execute 1 or N instructions |
| regs | regs | Show all registers |
| mem | mem 0x80000000 64 | Show memory contents |
| disasm | disasm 0x80000000 10 | Disassemble instructions |
| info symbols | info symbols | List all symbols |
| info breakpoints | info breakpoints | List breakpoints |
| delete | delete 0x80000030 | Remove breakpoint |
| clear | clear | Remove all breakpoints |
| pc | pc | Show program counter |
| quit | quit or Ctrl-D | Exit console |

Tip: Many commands have short aliases:
- step -> s
- break -> b
- run -> r
- continue -> c
- disasm -> d
- quit -> q

## Debugging Tips

### 1. Use Symbolic Breakpoints
```
(mapachespim) break fibonacci
(mapachespim) run
```

Much easier than memorizing addresses.

### 2. Watch Register Changes
Single-step automatically shows what changed:
```
(mapachespim) step
[0x80000000] <_start>  0x9302a000  addi x5, x0, 0xa
Register changes:
  x5  (  t0) : 0x0000000000000000 -> 0x000000000000000a  *
```

### 3. Disassemble to Understand Code
```
(mapachespim) disasm 0x80000000 10
```

See the next 10 instructions before executing them.

### 4. Multi-step for Known-Good Code
```
(mapachespim) step 10
```

Skip over initialization code quickly.

### 5. Check Memory Contents
```
(mapachespim) mem 0x80000000 32
```

See the raw instruction bytes.

## Example Debugging Session

Here's a complete session debugging the Fibonacci program:

```
$ mapachespim
(mapachespim) load examples/riscv/fibonacci/fibonacci
Loaded examples/riscv/fibonacci/fibonacci

(mapachespim) info symbols
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

(mapachespim) step
[0x80000034] <main+4>  0x040000ef  jal ra, fibonacci
Register changes:
  x1  (  ra) : 0x0000000000000000 -> 0x0000000080000038  *

(mapachespim) regs
x0  (zero) = 0x0000000000000000  x1  (  ra) = 0x0000000080000038  ...
x10 (  a0) = 0x0000000000000005  ...

(mapachespim) continue
Program halted after 42 instructions

(mapachespim) quit
Goodbye!
```

## Next Steps

Now that you've run your first program:

1. [Console Guide](console-guide.md) - Learn all commands in detail
2. [Examples](../../examples/README.md) - Explore more example programs
3. Write Your Own - Create and debug your own RISC-V programs

## Troubleshooting

### Command Not Found: mapachespim

If the console doesn't start, try:
```bash
# Run from Python package
python3 -m mapachespim.console

# Or use the script directly
./mapachespim_console
```

### Import Error

Make sure you installed the Python package:
```bash
pip3 install -e .
```

### Build Errors

Check you have all prerequisites:
```bash
python3 --version  # 3.8+
cmake --version    # 3.10+
gcc --version      # Any recent version
```

### Library Not Found

Build the C library first:
```bash
cd lib/build
cmake ..
make
cd ../..
```

### Still Stuck?

- Check the [full console guide](console-guide.md)
- Look at [example programs](../../examples/README.md)
- Open an issue on GitHub

## What's Next?

After mastering the basics, explore:

- Advanced Debugging - Watchpoints, conditional breakpoints (future)
- Multiple ISAs - ARM and CHERI support (future)
- Custom Programs - Write and compile your own RISC-V code
- C++ Console - Native performance console (future)
