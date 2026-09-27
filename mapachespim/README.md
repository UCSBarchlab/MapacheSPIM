# MapacheSPIM Python API

Python simulator for RISC-V, MIPS, ARM64, and x86-64 programs, powered by the Unicorn Engine.

## Installation

See the [main README](../README.md#install). For development, `pip install -e ".[dev]"` from the
repository root.

## Quick Start

```python
from mapachespim import Simulator, ISA

# Initialize simulator (ISA auto-detected from ELF)
sim = Simulator()

# Or specify ISA explicitly
sim = Simulator(isa=ISA.ARM)

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

# Run until the program exits (or max steps); syscalls print to stdout
steps = sim.run(max_steps=1000)
print(f"Executed {steps} instructions, exit code {sim.exit_code}")
```

## API Reference

### Simulator Class

#### Initialization
- `Simulator(isa=None)` - Create simulator instance
  - `isa`: `ISA.RISCV`, `ISA.ARM`, `ISA.X86_64`, or `ISA.MIPS` (default: take the ISA of each
    loaded ELF). A simulator created for one ISA refuses ELF files for another.

#### Program Loading
- `load_elf(elf_path)` - Load ELF executable into a fresh machine state
  - Automatically detects ISA from ELF headers
  - Raises: `FileNotFoundError` if file doesn't exist
  - Raises: `RuntimeError` on invalid ELF

#### Execution Control
- `step()` - Execute one instruction
  - Returns: `StepResult` (OK, HALT, SYSCALL, or ERROR)
  - A syscall instruction returns `SYSCALL` without performing it; pass the result to
    `check_termination()` to perform it (this is what `run()` and the console do)
  - After the program exits, returns `HALT` without executing anything

- `check_termination(result)` - Perform a pending syscall and decide whether to stop
  - Returns: `(stop, reason)`, where reason is `"syscall_exit"`, `"halt"`, `"error"`,
    `"tohost"`, or `None`

- `run(max_steps=None)` - Run until the program stops or `max_steps` instructions
  - `max_steps`: Maximum instructions (`None` = unlimited)
  - Returns: Number of instructions executed

- `reset()` - Reload the current ELF and start over

#### Program Status and I/O
- `exited` / `exit_code` - Whether the program exited via a syscall, and its exit code
- `last_error` - Description of the last execution error, e.g.
  `"Read from unmapped address 0x0 (at PC=0x80000004)"`
- `stdout` / `stdin` - Streams used by the I/O syscalls (default: the process's streams).
  Assign e.g. `io.StringIO` objects to capture output or provide input

#### State Inspection
- `get_pc()` - Get program counter (64-bit)
- `set_pc(pc)` - Set program counter
- `get_reg(reg_num)` - Get register value
- `set_reg(reg_num, value)` - Set register value
- `get_all_regs()` - Get all GPRs as list
- `get_isa()` - Get current ISA enum
- `get_isa_name()` - Get ISA name as string
- `get_register_count()` - Get number of GPRs (32 for RISC-V/ARM, 16 for x86-64)
- `get_reg_name(n)` - Get ABI name for register n

#### Memory Access
- `read_mem(addr, length)` - Read memory, returns `bytes`
- `write_mem(addr, data)` - Write memory

#### Symbol Table
- `get_symbols()` - Get all symbols as `{name: address}` dict
- `lookup_symbol(name)` - Look up symbol address by name
- `addr_to_symbol(addr)` - Convert address to `(name, offset)` tuple

#### Disassembly
- `disasm(addr)` - Disassemble instruction at address
- `disasm_with_size(addr)` - Disassemble and return `(text, length_in_bytes)` (x86-64
  instructions vary in length)

### ISA Enum
- `ISA.RISCV` - RISC-V 64-bit
- `ISA.ARM` - ARM64 (AArch64)
- `ISA.X86_64` - x86-64
- `ISA.MIPS` - MIPS32 (big-endian)

### Helper Functions
- `create_simulator(elf_path)` - Create simulator and load ELF in one call
- `detect_elf_isa(elf_path)` - Detect ISA from ELF file

### Assembling from Python

```python
from mapachespim.toolchain import assemble

result = assemble(source_text, isa="riscv64", debug=True)
if result.success:
    open("prog", "wb").write(result.elf_bytes)
else:
    print("\n".join(result.errors))
```

### Bundled Examples

```python
from mapachespim.examples import find_example, list_examples

for example in list_examples():
    print(example.short_name, example.description)
sim.load_elf(str(find_example("mips/fibonacci")))
```

## Example: Tracing Execution

```python
from mapachespim import Simulator

sim = Simulator()
sim.load_elf("examples/riscv/fibonacci/fibonacci")

# Trace first 10 instructions
for i in range(10):
    pc = sim.get_pc()
    disasm = sim.disasm(pc)
    print(f"[{i}] 0x{pc:x}: {disasm}")

    done, reason = sim.check_termination(sim.step())
    if done:
        print(f"Stopped: {reason}")
        break

# Show result
regs = sim.get_all_regs()
print(f"\nReturn value (a0): {regs[10]}")
```

## Architecture

```
Python API (Simulator)
    ↓
Unicorn Engine (CPU emulation)
    ↓
Capstone (disassembly)
```

The simulator uses Unicorn Engine for accurate CPU emulation and Capstone for
disassembly. RISC-V 64-bit, MIPS32, ARM64, and x86-64 are supported with the same API.
