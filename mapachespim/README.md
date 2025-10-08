# MapacheSPIM Python API

Python bindings for the Sail RISC-V simulator.

## Installation

No installation required - just ensure the C library is built:

```bash
cd lib
mkdir -p build && cd build
cmake ..
make
```

## Quick Start

```python
from mapachespim import SailSimulator

# Initialize simulator
sim = SailSimulator()

# Load a RISC-V ELF file
sim.load_elf("examples/riscv/fibonacci/fibonacci")

# Single-step execution
print(f"PC: 0x{sim.get_pc():x}")
sim.step()

# Read registers
print(f"x10 (a0): {sim.get_reg(10)}")
all_regs = sim.get_all_regs()

# Read memory
data = sim.read_mem(0x80000000, 16)

# Run until halt (or max steps)
steps = sim.run(max_steps=1000)
print(f"Executed {steps} instructions")
```

## API Reference

### SailSimulator Class

#### Initialization
- `SailSimulator(config_file=None)` - Create simulator instance
  - `config_file`: Optional path to Sail config JSON

#### Program Loading
- `load_elf(elf_path)` - Load RISC-V ELF executable
  - Returns: `True` on success
  - Raises: `RuntimeError` on failure

#### Execution Control
- `step()` - Execute one instruction
  - Returns: `StepResult` (OK, HALT, WAITING, or ERROR)

- `run(max_steps=0)` - Run until halt or max steps
  - `max_steps`: Maximum instructions to execute (0 = unlimited)
  - Returns: Number of instructions executed

- `reset()` - Reset simulator to initial state

#### State Inspection
- `get_pc()` - Get program counter
  - Returns: 64-bit PC value

- `set_pc(pc)` - Set program counter
  - `pc`: 64-bit address

- `get_reg(reg_num)` - Get register value
  - `reg_num`: Register number (0-31)
  - Returns: 64-bit register value

- `set_reg(reg_num, value)` - Set register value
  - `reg_num`: Register number (1-31, x0 is read-only)
  - `value`: 64-bit value to set

- `get_all_regs()` - Get all 32 register values
  - Returns: List of 32 integers (x0-x31)

#### Memory Access
- `read_mem(addr, length)` - Read memory
  - `addr`: Memory address
  - `length`: Number of bytes to read
  - Returns: `bytes` object

- `write_mem(addr, data)` - Write memory
  - `addr`: Memory address
  - `data`: bytes or str to write
  - Returns: `True` on success

#### Context Manager Support

```python
with SailSimulator() as sim:
    sim.load_elf("program.elf")
    sim.run(1000)
# Automatically cleaned up
```

## Example: Tracing Execution

```python
from mapachespim import SailSimulator, StepResult

sim = SailSimulator()
sim.load_elf("examples/riscv/fibonacci/fibonacci")

print(f"Entry: 0x{sim.get_pc():x}")

# Trace first 10 instructions
for i in range(10):
    pc = sim.get_pc()
    print(f"[{i}] PC=0x{pc:x}")

    result = sim.step()
    if result == StepResult.HALT:
        print("Program halted")
        break

# Show final register state
regs = sim.get_all_regs()
print(f"\nReturn value (a0): {regs[10]}")
```

## Architecture

The Python bindings use `ctypes` to wrap the C API from `libsailsim`:

```
Python (SailSimulator)
    ↓ ctypes
C API (libsailsim)
    ↓
Sail RISC-V Model (formal specification)
```

This provides a clean Pythonic interface while maintaining the performance and correctness of the underlying Sail formal specification.
