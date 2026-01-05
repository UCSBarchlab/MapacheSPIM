# MapacheSPIM Python API

Python simulator for RISC-V and ARM programs, powered by the Unicorn Engine.

## Installation

```bash
pip install -e .
```

Dependencies (installed automatically):
- `unicorn>=2.0.0` - CPU emulator framework
- `capstone>=5.0.0` - Disassembler
- `pyelftools>=0.29` - ELF file parsing

## Quick Start

```python
from mapachespim import SailSimulator, ISA

# Initialize simulator (defaults to RISC-V)
sim = SailSimulator()

# Or specify ISA explicitly
sim = SailSimulator(isa=ISA.ARM)

# Load an ELF file
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
- `SailSimulator(isa=None)` - Create simulator instance
  - `isa`: `ISA.RISCV` or `ISA.ARM` (default: RISCV)

#### Program Loading
- `load_elf(elf_path)` - Load ELF executable
  - Automatically detects ISA from ELF headers
  - Raises: `FileNotFoundError` if file doesn't exist
  - Raises: `RuntimeError` on invalid ELF

#### Execution Control
- `step()` - Execute one instruction
  - Returns: `StepResult` (OK, HALT, SYSCALL, or ERROR)

- `run(max_steps=0)` - Run until halt or max steps
  - `max_steps`: Maximum instructions (0 = unlimited)
  - Returns: Number of instructions executed

- `reset()` - Reset simulator state

#### State Inspection
- `get_pc()` - Get program counter (64-bit)
- `set_pc(pc)` - Set program counter
- `get_reg(reg_num)` - Get register value (0-31)
- `set_reg(reg_num, value)` - Set register value (1-31)
- `get_all_regs()` - Get all 32 registers as list

#### Memory Access
- `read_mem(addr, length)` - Read memory, returns `bytes`
- `write_mem(addr, data)` - Write memory

#### Symbol Table
- `get_symbols()` - Get all symbols as `{name: address}` dict
- `lookup_symbol(name)` - Look up symbol address by name
- `addr_to_symbol(addr)` - Convert address to `(name, offset)` tuple

#### Disassembly
- `disasm(addr)` - Disassemble instruction at address

### ISA Enum
- `ISA.RISCV` - RISC-V 64-bit
- `ISA.ARM` - ARM64 (AArch64)

### Helper Functions
- `create_simulator(elf_path)` - Create simulator and load ELF in one call
- `detect_elf_isa(elf_path)` - Detect ISA from ELF file

## Example: Tracing Execution

```python
from mapachespim import SailSimulator, StepResult

sim = SailSimulator()
sim.load_elf("examples/riscv/fibonacci/fibonacci")

# Trace first 10 instructions
for i in range(10):
    pc = sim.get_pc()
    disasm = sim.disasm(pc)
    print(f"[{i}] 0x{pc:x}: {disasm}")

    result = sim.step()
    if result == StepResult.HALT:
        print("Program halted")
        break

# Show result
regs = sim.get_all_regs()
print(f"\nReturn value (a0): {regs[10]}")
```

## Architecture

```
Python API (SailSimulator)
    ↓
Unicorn Engine (CPU emulation)
    ↓
Capstone (disassembly)
```

The simulator uses Unicorn Engine for accurate CPU emulation and Capstone for
disassembly. Both RISC-V 64-bit and ARM64 are supported with the same API.
