# Multi-ISA Strategy

This document explains how MapacheSPIM supports multiple Instruction Set Architectures (ISAs) through a clean, extensible design based on Sail formal specifications.

---

## Design Philosophy

**Goal:** Support RISC-V, ARM, CHERI, and any other Sail-supported ISA with **zero changes** to the core library.

**Approach:** Leverage Sail's formal specifications as the common interface.

---

## Current State (RISC-V Only)

```
MapacheSPIM/
├── libsailsim/            # ISA-agnostic core ✅
├── mapachespim/           # ISA-agnostic Python ✅
├── sail-riscv/            # RISC-V backend (submodule)
└── examples/              # RISC-V examples
```

**Status:**
- ✅ Core library is ISA-agnostic
- ✅ Symbol table uses Sail's ELF loader (works for all ISAs)
- ⚠️ Only RISC-V backend currently integrated
- ⚠️ Examples are RISC-V specific

---

## Target State (Multi-ISA)

```
MapacheSPIM/                # Note: Renamed from MapacheSPIM
├── lib/                   # ISA-agnostic core ✅
├── python/                # ISA-agnostic Python ✅
├── backends/              # ISA backends (submodules)
│   ├── riscv/
│   │   └── sail-riscv/   # RISC-V formal spec
│   ├── arm/
│   │   └── sail-arm/     # ARM formal spec
│   └── cheri/
│       └── sail-cheri/   # CHERI formal spec
├── examples/              # Organized by ISA
│   ├── riscv/
│   ├── arm/
│   └── shared/           # ISA-agnostic examples
└── tests/
    └── isa/              # ISA-specific tests
        ├── riscv/
        └── arm/
```

---

## Sail Backend Contract

Every ISA backend must provide these interfaces (all backends inherit from Sail):

### 1. Core Execution Model

```c
// Initialize/cleanup model
void setup_library();
void model_init();
void model_fini();

// Initialize registers
void zinitializze_registers(unit);

// Execute one instruction
bool ztry_step(sail_int step_number, bool verbose);

// Halt condition
extern bool zhtif_done;
extern int64_t zhtif_exit_code;
```

### 2. Memory Model

```c
// Read/write memory
mach_bits read_mem(uint64_t address);
void write_mem(uint64_t address, uint8_t value);
```

### 3. Register Access (ISA-Specific)

**RISC-V Example:**
```c
// Read register X[n]
sbits zrX(int reg_num);

// Write register X[n]
void zwX(int reg_num, sbits value);

// PC
extern sbits zPC;
extern sbits znextPC;
```

**ARM Example (future):**
```c
// Read register R[n]
sbits zR(int reg_num);

// Write register R[n]
void zwR(int reg_num, sbits value);

// PC
extern sbits zPC;
```

**Note:** ISA-specific register access is hidden behind library abstraction.

### 4. Disassembly

```c
// Decode instruction
void zencdec_backwards(zinstruction* result, uint32_t instr_bits);

// Convert to assembly string
void zassembly_forwards(sail_string* result, zinstruction instr);
```

**Why this works:** Sail generates these for every ISA!

### 5. ELF Loading (ISA-Agnostic!)

```cpp
class ELF {
public:
    // Open ELF file
    static ELF open(const std::string& filename);

    // Get architecture (RV32/RV64/ARM32/ARM64/etc.)
    Architecture architecture() const;

    // Get entry point
    uint64_t entry() const;

    // Load segments into memory
    void load(std::function<void(uint64_t addr, const uint8_t* data, uint64_t len)> writer) const;

    // Get symbol table (works for ALL ISAs!)
    std::map<std::string, uint64_t> symbols() const;
};
```

**Key Insight:** Sail's ELF loader works for **all ISAs** - this is why our symbol table support is ISA-agnostic!

---

## ISA Detection

### From ELF Header

```cpp
enum class ISA {
    RISCV,
    ARM,
    CHERI,
    UNKNOWN
};

ISA detect_isa_from_elf(const std::string& elf_path) {
    ELF elf = ELF::open(elf_path);

    // ELF machine type in header
    uint16_t machine = elf.machine_type();

    switch (machine) {
        case EM_RISCV:   return ISA::RISCV;
        case EM_ARM:     return ISA::ARM;
        case EM_AARCH64: return ISA::ARM;  // 64-bit ARM
        // CHERI uses RISC-V or ARM base + extensions
        default:         return ISA::UNKNOWN;
    }
}
```

### Runtime Backend Selection

```cpp
// In sailsim_init()
ISA isa = detect_isa_from_elf(elf_path);

switch (isa) {
    case ISA::RISCV:
        // Use RISC-V backend
        backend = load_riscv_backend();
        break;

    case ISA::ARM:
        // Use ARM backend
        backend = load_arm_backend();
        break;

    default:
        return error("Unsupported ISA");
}
```

---

## Adding a New ISA Backend

### Example: Adding ARM Support

#### Step 1: Add Sail ARM Submodule

```bash
cd backends/
mkdir -p arm
cd arm

# Add Sail ARM as submodule
git submodule add https://github.com/rems-project/sail-arm.git
cd sail-arm

# Build ARM simulator
./build_simulators.sh
```

#### Step 2: Verify Backend Contract

Check that `sail-arm` provides required interfaces:

```bash
# Check for required functions in generated code
grep -r "model_init" sail-arm/c_emulator/
grep -r "ztry_step" sail-arm/c_emulator/
grep -r "read_mem" sail-arm/c_emulator/
```

**Expected:** All Sail-generated backends provide these!

#### Step 3: Create Backend Adapter (if needed)

If ARM register access differs:

```cpp
// lib/src/backends/arm_adapter.cpp
#include "sail_arm_model.h"

uint64_t arm_get_reg(int reg_num) {
    // ARM uses zR(n) instead of zrX(n)
    sbits reg_value = zR(reg_num);
    return reg_value.bits;
}

void arm_set_reg(int reg_num, uint64_t value) {
    zwR(reg_num, make_sbits(value));
}
```

#### Step 4: Update Build System

```cmake
# CMakeLists.txt
option(BUILD_ARM_BACKEND "Build ARM backend" OFF)

if(BUILD_ARM_BACKEND)
    add_subdirectory(backends/arm/sail-arm)
    target_link_libraries(mapachesim sail_arm_emulator)
endif()
```

#### Step 5: Add ARM Examples

```bash
mkdir -p examples/arm/hello
# Add ARM hello world program
```

#### Step 6: Add ARM Tests

```bash
mkdir -p tests/isa/arm/
# Add ARM-specific tests
```

#### Step 7: Update Documentation

```bash
# Update docs to mention ARM support
echo "✅ ARM support added!"
```

**Total Time:** < 1 day for developer familiar with system!

---

## Backend Directory Structure

### Proposed Layout

```
backends/
├── README.md              # Backend registry and guide
├── riscv/
│   ├── README.md         # RISC-V backend info
│   └── sail-riscv/       # Submodule
│       ├── model/        # Sail formal spec
│       ├── c_emulator/   # Generated C code
│       └── ...
├── arm/
│   ├── README.md         # ARM backend info
│   └── sail-arm/         # Submodule
│       ├── model/        # Sail formal spec
│       ├── c_emulator/   # Generated C code
│       └── ...
└── cheri/
    ├── README.md         # CHERI backend info
    └── sail-cheri/       # Submodule
```

### Backend README Template

```markdown
# ARM Backend

**Status:** Experimental
**Sail Version:** 0.15
**Architecture:** ARMv8-A

## Build Instructions

```bash
cd sail-arm
./build_simulators.sh
```

## Supported Features

- [x] ARMv8-A base ISA
- [x] Integer operations
- [ ] Floating point (TODO)
- [ ] NEON/SIMD (TODO)

## Testing

```bash
python3 tests/isa/arm/test_arm_basic.py
```

## References

- [ARM Architecture Reference Manual](https://...)
- [Sail ARM Repository](https://github.com/rems-project/sail-arm)
```

---

## ISA-Specific Adaptations

Some ISAs may need small adaptations:

### Register Count

```cpp
// lib/src/mapachesim.cpp
int get_register_count(ISA isa) {
    switch (isa) {
        case ISA::RISCV: return 32;  // x0-x31
        case ISA::ARM:   return 31;  // r0-r30 + SP
        default:         return 0;
    }
}
```

### Register Names

```cpp
const char* get_register_name(ISA isa, int reg_num) {
    switch (isa) {
        case ISA::RISCV:
            return riscv_register_names[reg_num];  // "x0", "ra", "sp", ...

        case ISA::ARM:
            return arm_register_names[reg_num];     // "r0", "r1", ...

        default:
            return "?";
    }
}
```

### Instruction Width

```cpp
int get_instruction_width(ISA isa) {
    switch (isa) {
        case ISA::RISCV: return 4;  // 32-bit instructions (ignoring compressed)
        case ISA::ARM:   return 4;  // 32-bit instructions (ARMv8 A64)
        default:         return 4;
    }
}
```

**Key Point:** These are **configuration**, not major code changes!

---

## Multi-ISA Console Experience

### Automatic ISA Detection

```
$ mapachesim
(mapachesim) load examples/riscv/fibonacci/fibonacci
✓ Loaded RISC-V program
Entry point: 0x80000000

(mapachesim) info isa
Architecture: RV64IMAFDC
Registers: 32 (x0-x31)
Instruction width: 32-bit

(mapachesim) load examples/arm/hello/hello
✓ Loaded ARM program
Entry point: 0x00400000

(mapachesim) info isa
Architecture: ARMv8-A
Registers: 31 (r0-r30 + SP)
Instruction width: 32-bit
```

### ISA-Aware Display

**RISC-V:**
```
(mapachesim) step
[0x80000000] <main>  0x9302a000  addi x5, x0, 0xa
Register changes:
  x5  (  t0) : 0x0000000000000000 → 0x000000000000000a  ★
```

**ARM:**
```
(mapachesim) step
[0x00400000] <main>  0xe3a05005  mov r5, #5
Register changes:
  r5         : 0x0000000000000000 → 0x0000000000000005  ★
```

---

## Testing Multi-ISA Support

### ISA-Agnostic Tests

```python
# tests/test_multi_isa.py

def test_load_riscv_program():
    sim = Simulator()
    sim.load('examples/riscv/hello/hello')
    assert sim.get_isa() == ISA.RISCV

def test_load_arm_program():
    sim = Simulator()
    sim.load('examples/arm/hello/hello')
    assert sim.get_isa() == ISA.ARM

def test_symbol_table_works_for_all_isas():
    """Symbol table should work regardless of ISA"""
    for example in ['riscv/hello', 'arm/hello']:
        sim = Simulator()
        sim.load(f'examples/{example}/{example.split("/")[1]}')

        symbols = sim.get_symbols()
        assert len(symbols) > 0
        assert 'main' in symbols  # All should have main
```

### ISA-Specific Tests

```python
# tests/isa/riscv/test_riscv_specific.py

def test_riscv_compressed_instructions():
    """Test RISC-V specific compressed instructions"""
    sim = Simulator()
    sim.load('examples/riscv/compressed/compressed')
    # ...

# tests/isa/arm/test_arm_specific.py

def test_arm_conditional_execution():
    """Test ARM specific conditional execution"""
    sim = Simulator()
    sim.load('examples/arm/conditional/conditional')
    # ...
```

---

## Benefits of This Approach

### 1. Zero Code Changes for New ISAs

Adding ARM doesn't require modifying:
- ✅ Core library (`libsailsim/`)
- ✅ Python bindings (`mapachespim/`)
- ✅ Symbol table code
- ✅ Disassembly code
- ✅ Console commands

Only need:
- Add backend submodule
- Add ISA-specific examples
- Add ISA-specific tests
- Small configuration (register count, names)

### 2. Formal Specification Foundation

All ISAs use Sail formal specifications:
- Proven correctness
- Maintained by ISA experts
- Same quality regardless of ISA

### 3. Consistent User Experience

Students get same debugging experience across ISAs:
- Same commands
- Same features (symbols, disassembly, register tracking)
- Same UI

### 4. Educational Value

Students can compare ISAs side-by-side:
- RISC-V vs ARM instruction encoding
- Register conventions
- Calling conventions
- ISA design tradeoffs

---

## Roadmap

### Phase 1: RISC-V Only (Current)
- [x] RISC-V backend integrated
- [x] Symbol table working
- [x] Disassembly working
- [x] Console working

### Phase 2: Multi-ISA Structure (Next)
- [ ] Move `sail-riscv/` to `backends/riscv/sail-riscv/`
- [ ] Create `backends/README.md`
- [ ] Organize examples by ISA
- [ ] Update build system
- [ ] Test that RISC-V still works

### Phase 3: ARM Support (Future)
- [ ] Add `backends/arm/sail-arm/` submodule
- [ ] Create ARM adapter if needed
- [ ] Add ARM examples
- [ ] Add ARM tests
- [ ] Document ARM support

### Phase 4: CHERI Support (Future)
- [ ] Add `backends/cheri/sail-cheri/` submodule
- [ ] CHERI-specific adaptations (capability registers)
- [ ] CHERI examples
- [ ] CHERI tests

---

## FAQ

### Q: Why use Sail backends instead of writing our own?

**A:** Formal specifications are:
- Proven correct
- Maintained by experts
- Well-tested
- Cover all edge cases

Writing our own would take years and likely have bugs.

### Q: What if an ISA doesn't have a Sail backend?

**A:** Most modern ISAs have Sail specifications:
- RISC-V: Yes
- ARM: Yes
- CHERI: Yes
- x86: Partial
- MIPS: Yes

For ISAs without Sail, we'd need a different strategy.

### Q: How much code changes per ISA?

**A:** Minimal:
- Add submodule: 1 command
- Configuration: ~50 lines (register names, etc.)
- Examples: New directory
- Tests: New directory

Core library: **zero changes** needed!

### Q: Can we support multiple ISAs simultaneously?

**A:** Yes! Load different backends and switch based on ELF:

```cpp
backend = select_backend_for_elf(elf_path);
```

### Q: What about ISA extensions?

**A:** Sail supports extensions:
- RISC-V: M, A, F, D, C, V, etc.
- ARM: NEON, SVE, etc.
- CHERI: Capability extensions

All handled by Sail backend automatically!

---

## See Also

- [Architecture](architecture.md) - Overall system architecture
- [Adding ISA Guide](adding-isa.md) - Step-by-step guide (coming soon)
- [Sail Documentation](https://github.com/rems-project/sail) - Sail language docs
