# ISA Backends

This directory contains ISA-specific backends as git submodules. Each backend is a Sail formal specification that provides the simulation engine for that architecture.

## Current Backends

### RISC-V (riscv/)
- Status: Active (primary backend)
- Repository: https://github.com/riscv/sail-riscv
- Sail Version: 0.18+
- Architecture: RV32/RV64 with extensions M, A, F, D, C, V, etc.
- Documentation: [Sail RISC-V](https://github.com/riscv/sail-riscv)

Build:
```bash
cd backends/riscv/sail-riscv
./build_simulators.sh
```

## Future Backends

### ARM (arm/)
- Status: Planned
- Repository: https://github.com/rems-project/sail-arm
- Architecture: ARMv8-A

### CHERI (cheri/)
- Status: Planned
- Repository: https://github.com/CTSRD-CHERI/sail-cheri-riscv
- Architecture: CHERI-RISC-V (capability extensions)

## Backend Contract

Every backend must provide these Sail-generated interfaces:

### Core Execution
```c
void setup_library();
void model_init();
void model_fini();
bool ztry_step(sail_int step, bool verbose);
```

### Memory Model
```c
mach_bits read_mem(uint64_t addr);
void write_mem(uint64_t addr, uint8_t value);
```

### Register Access
ISA-specific (e.g., zrX() for RISC-V, zR() for ARM)

### Disassembly
```c
void zencdec_backwards(zinstruction*, uint32_t);
void zassembly_forwards(sail_string*, zinstruction);
```

### ELF Loading (ISA-Agnostic)
```cpp
class ELF {
    static ELF open(const string& path);
    uint64_t entry() const;
    map<string, uint64_t> symbols() const;
    // ...
};
```

## Adding a New Backend

See [docs/developer/multi-isa.md](../docs/developer/multi-isa.md) for detailed instructions.

Quick start:
```bash
# 1. Add submodule
cd backends/
mkdir -p <isa-name>
cd <isa-name>
git submodule add <sail-repo-url>

# 2. Build backend
cd sail-<isa-name>
./build_simulators.sh

# 3. Add examples
mkdir -p ../../examples/<isa-name>

# 4. Add tests
mkdir -p ../../tests/isa/<isa-name>

# 5. Document
# Update this README.md
```

## Directory Structure

```
backends/
├── README.md           # This file
├── riscv/
│   └── sail-riscv/    # RISC-V Sail model (submodule)
│       ├── model/     # Sail formal specification
│       ├── c_emulator/# Generated C code
│       └── ...
├── arm/               # Future
│   └── sail-arm/
└── cheri/             # Future
    └── sail-cheri/
```

## Testing Backends

Each backend should have ISA-specific tests:

```bash
# RISC-V tests
python3 tests/isa/riscv/test_riscv_basic.py

# ARM tests (future)
python3 tests/isa/arm/test_arm_basic.py
```

## See Also

- [Multi-ISA Strategy](../docs/developer/multi-isa.md) - Architecture and design
- [Architecture](../docs/developer/architecture.md) - Overall system design
- [Sail Documentation](https://github.com/rems-project/sail) - Sail language
