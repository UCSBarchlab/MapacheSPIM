# MapacheSail Architecture

This document describes the overall system architecture, component interactions, and design decisions.

---

## System Overview

MapacheSail is a layered architecture for ISA-agnostic assembly debugging built on Sail formal specifications:

```
┌─────────────────────────────────────────────────────────┐
│              User Interfaces (Frontends)                │
│  ┌──────────────────┐        ┌─────────────────────┐  │
│  │  Python Console  │        │  C++ Console (TBD)  │  │
│  │  (mapachesail/)  │        │  (future)           │  │
│  └────────┬─────────┘        └──────────┬──────────┘  │
└───────────┼────────────────────────────────┼───────────┘
            │                                │
            │          C API                 │
┌───────────┼────────────────────────────────┼───────────┐
│           │     libsailsim (ISA-agnostic)  │           │
│  ┌────────┴──────────────────────────────┴────────┐   │
│  │   • Core API (sailsim.h / sailsim.cpp)         │   │
│  │   • Memory inspection                           │   │
│  │   • Register inspection                         │   │
│  │   • Symbol table management                     │   │
│  │   • Disassembly                                 │   │
│  └────────────────────┬────────────────────────────┘   │
└─────────────────────────┼────────────────────────────────┘
                          │
              ┌───────────┴──────────────┐
              │  ISA Backend Interface   │
              │  (Sail-generated code)   │
              └───────────┬──────────────┘
                          │
        ┌─────────────────┼─────────────────────┐
        │                 │                     │
┌───────┴──────┐  ┌──────┴────────┐  ┌────────┴──────┐
│  RISC-V      │  │  ARM          │  │  CHERI        │
│  (sail-riscv)│  │  (sail-arm)   │  │  (sail-cheri) │
│  [current]   │  │  [future]     │  │  [future]     │
└──────────────┘  └───────────────┘  └───────────────┘
```

---

## Component Details

### 1. ISA Backends (Sail Submodules)

**Location:** `sail-riscv/` (will move to `backends/riscv/sail-riscv/`)

**Purpose:** Formal ISA specifications and generated simulators

**Key Components:**
- Sail formal model (`model/*.sail`)
- Generated C emulator
- ELF loader with symbol table support
- ISA-specific instruction decoding
- Memory model
- Register file

**Interface Contract:** Each backend must provide:
```c
// Core execution
void model_init();
void model_fini();
bool ztry_step(sail_int step, bool verbose);

// Memory access
mach_bits read_mem(uint64_t addr);
void write_mem(uint64_t addr, uint8_t byte);

// Register access (ISA-specific names)
sbits zrX(int reg_num);  // RISC-V example
void zwX(int reg_num, sbits value);

// Disassembly
void zencdec_backwards(zinstruction*, uint32_t);
void zassembly_forwards(sail_string*, zinstruction);

// ELF loading
class ELF {
    static ELF open(const string& path);
    uint64_t entry() const;
    map<string, uint64_t> symbols() const;
    void load(function<...>) const;
};
```

**Why Submodules:**
- Sail backends maintained by upstream projects
- Easy to update to latest formal specs
- Clean separation of concerns
- Multiple ISAs without code duplication

---

### 2. Core Library (libsailsim)

**Location:** `libsailsim/` (will move to `lib/`)

**Purpose:** ISA-agnostic API wrapping Sail backends

**Key Files:**
- `sailsim.h` - Public C API
- `sailsim.cpp` - Implementation
- `elf_loader.h` - ISA-agnostic ELF handling (from Sail)

**API Layers:**

```c
// Public API (sailsim.h)
typedef struct sailsim_context sailsim_context_t;

// Lifecycle
sailsim_context_t* sailsim_init(const char* config);
void sailsim_destroy(sailsim_context_t* ctx);

// ELF loading
bool sailsim_load_elf(sailsim_context_t* ctx, const char* path);

// Execution
sailsim_step_result_t sailsim_step(sailsim_context_t* ctx);
uint64_t sailsim_run(sailsim_context_t* ctx, uint64_t max_steps);

// State inspection
uint64_t sailsim_get_pc(sailsim_context_t* ctx);
uint64_t sailsim_get_reg(sailsim_context_t* ctx, int reg);
bool sailsim_read_mem(sailsim_context_t* ctx, uint64_t addr, void* buf, size_t len);

// Disassembly
bool sailsim_disasm(sailsim_context_t* ctx, uint64_t addr, char* buf, size_t bufsize);

// Symbols (uses Sail's ELF loader)
size_t sailsim_get_symbol_count(sailsim_context_t* ctx);
bool sailsim_lookup_symbol(sailsim_context_t* ctx, const char* name, uint64_t* addr);
bool sailsim_addr_to_symbol(sailsim_context_t* ctx, uint64_t addr, char* name, ...);
```

**Design Decisions:**
- **Opaque context:** `sailsim_context_t` hides implementation details
- **Error handling:** Return codes + `sailsim_get_error()` for details
- **Memory safety:** Bounds checking, buffer size parameters
- **ISA-agnostic:** No RISC-V-specific assumptions in API

---

### 3. Python Bindings (mapachesail/)

**Location:** `mapachesail/`

**Purpose:** Python wrapper for libsailsim

**Key Files:**
- `sail_backend.py` - ctypes bindings to C library
- `console.py` - Interactive debugging console
- `__init__.py` - Package initialization

**Architecture:**

```python
# Python Layer
class SailSimulator:
    """High-level Python interface"""
    def __init__(self):
        self._lib = ctypes.CDLL('libsailsim.dylib')
        self._setup_functions()
        self._ctx = self._lib.sailsim_init(None)

    def load_elf(self, path):
        """Load ELF with Pythonic interface"""
        result = self._lib.sailsim_load_elf(self._ctx, path.encode())
        if not result:
            raise RuntimeError(self._get_error())

    def get_symbols(self):
        """Return dict of symbols"""
        count = self._lib.sailsim_get_symbol_count(self._ctx)
        symbols = {}
        for i in range(count):
            name, addr = self._get_symbol_by_index(i)
            symbols[name] = addr
        return symbols
```

**Console Architecture:**

```python
class MapacheSailConsole(cmd.Cmd):
    """Interactive debugging console"""

    def __init__(self):
        self.sim = SailSimulator()
        self.breakpoints = set()
        self.show_reg_changes = True

    def do_step(self, arg):
        """Execute instructions with enhanced display"""
        pc = self.sim.get_pc()
        instr_disasm = self.sim.disasm(pc)
        instr_bytes = self.sim.read_mem(pc, 4)

        # Snapshot registers if tracking changes
        if self.show_reg_changes:
            prev_regs = self.sim.get_all_regs()

        # Execute
        self.sim.step()

        # Display instruction with symbol
        sym, offset = self.sim.addr_to_symbol(pc)
        print(f'[{pc:#010x}] <{sym}+{offset}>  {instr_hex}  {instr_disasm}')

        # Show register changes
        if self.show_reg_changes:
            self._show_register_changes(prev_regs)
```

---

## Data Flow

### Loading an ELF File

```
User: load fibonacci
    │
    ├──> Python: console.do_load('fibonacci')
    │       ├──> SailSimulator.load_elf('fibonacci')
    │       │       ├──> C: sailsim_load_elf(ctx, 'fibonacci')
    │       │       │       ├──> Sail: ELF::open('fibonacci')
    │       │       │       ├──> Sail: elf.load([](addr, data, len) {...})
    │       │       │       ├──> Sail: elf.symbols() → map<string, uint64>
    │       │       │       └──> Store in ctx->symbols
    │       │       └──< Return success
    │       └──< Return
    └──< Display "✓ Loaded fibonacci"
```

### Stepping with Symbol Display

```
User: step
    │
    ├──> Python: console.do_step('')
    │       ├──> Get PC: pc = sim.get_pc()
    │       ├──> Get symbol: sym, off = sim.addr_to_symbol(pc)
    │       ├──> Disassemble: disasm = sim.disasm(pc)
    │       ├──> Read bytes: bytes = sim.read_mem(pc, 4)
    │       ├──> Snapshot regs: prev = sim.get_all_regs()
    │       │
    │       ├──> Execute: sim.step()
    │       │       ├──> C: sailsim_step(ctx)
    │       │       │       ├──> Sail: ztry_step(step_num, verbose)
    │       │       │       │       └──> Execute one instruction
    │       │       │       └──< Return OK/HALT/ERROR
    │       │       └──< Return result
    │       │
    │       ├──> Get new regs: curr = sim.get_all_regs()
    │       ├──> Compare: changes = diff(prev, curr)
    │       │
    │       └──> Display:
    │               "[0x80000000] <main>  0x13050005  addi x5, x0, 0xa"
    │               "Register changes:"
    │               "  x5 (t0) : 0x0 → 0xa  ★"
    │
    └──< Done
```

---

## Key Design Principles

### 1. ISA-Agnostic Core
**Goal:** Support multiple ISAs without changing core code

**Implementation:**
- All ISA-specific code in backends (submodules)
- Core library uses abstract interfaces
- Symbol table from Sail (works for all ISAs)
- Generic disassembly interface

**Example:** Adding ARM support
```bash
# Add ARM backend
cd backends/arm
git submodule add https://github.com/rems-project/sail-arm.git

# No changes needed to core library!
# Just point to ARM's Sail interface
```

### 2. Formal Specification Foundation
**Goal:** Trustworthy simulation based on formal models

**Implementation:**
- Use Sail's proven formal specs
- Disassembly from Sail (not objdump)
- Memory model from Sail
- Instruction semantics from Sail

**Benefits:**
- Matches ISA specification exactly
- Well-tested by formal methods community
- Maintained by ISA experts

### 3. Student-Friendly UX
**Goal:** SPIM-like debugging experience

**Implementation:**
- Enhanced step display (instruction + changes)
- Symbol table integration
- Register change tracking
- Clear, helpful error messages

**Design Choices:**
- Show what changed, not just final state
- Use function names, not just addresses
- Provide context (where you are in code)

### 4. Extensible Architecture
**Goal:** Easy to add features without breaking existing code

**Extension Points:**
- New commands: Add `do_<command>` method in console
- New ISAs: Add backend submodule
- New frontends: Link against libsailsim C API
- New features: Extend C API, Python wraps it

---

## Memory Management

### Reference-Counted Global State

**Problem:** Sail backends use global state (GMP variables, registers)

**Solution:** Reference counting for `model_init()/model_fini()`

```cpp
static bool g_sail_model_initialized = false;
static int g_simulator_instance_count = 0;

void ensure_sail_model_initialized() {
    if (!g_sail_model_initialized) {
        model_init();  // Only call once
        g_sail_model_initialized = true;
    }
    g_simulator_instance_count++;
}

void cleanup_sail_model_if_last() {
    g_simulator_instance_count--;
    if (g_simulator_instance_count == 0) {
        model_fini();  // Only call when last instance destroyed
    }
}
```

**Why:** Prevents double-free errors when creating multiple simulator instances (common in tests).

---

## Configuration System

**Current:** JSON configuration files

```json
{
    "architecture": "RV64IMAFDC",
    "start_pc": "0x80000000",
    "mem_size": "0x10000000"
}
```

**Future:** Runtime detection from ELF header

```cpp
ISA detect_isa_from_elf(const string& path) {
    ELF elf = ELF::open(path);
    switch (elf.machine_type()) {
        case EM_RISCV: return ISA::RISCV;
        case EM_ARM: return ISA::ARM;
        default: throw runtime_error("Unsupported ISA");
    }
}
```

---

## Testing Strategy

### Unit Tests
- `tests/test_symbols.py` - Symbol table API
- `tests/test_disasm.py` - Disassembly
- `tests/test_console.py` - Console commands

### Integration Tests
- Full debugging sessions
- Multi-step execution
- Complex programs (fibonacci, matrix multiply)

### ISA-Specific Tests
- `tests/isa/riscv/` - RISC-V specific tests
- Future: `tests/isa/arm/` - ARM specific tests

---

## Build System

**CMake Structure:**

```cmake
MapacheSail/
├── CMakeLists.txt                 # Top-level
├── libsailsim/CMakeLists.txt     # C library
└── cpp/CMakeLists.txt            # C++ console (future)
```

**Build Flow:**
1. Sail backend builds first (submodule)
2. libsailsim links against Sail libraries
3. Python package installed with `pip install -e .`
4. C++ console links against libsailsim (future)

---

## Future Architecture

### Planned Components

1. **C++ Console** (`cpp/`)
   - Native performance
   - Shared C library
   - TUI with panels

2. **Multiple ISAs** (`backends/`)
   - ARM: `backends/arm/sail-arm/`
   - CHERI: `backends/cheri/sail-cheri/`
   - Auto-detect from ELF

3. **Watchpoints** (library feature)
   - Memory watchpoints
   - Register watchpoints
   - Conditional breakpoints

4. **Call Stack** (library feature)
   - Track function calls
   - Backtrace display
   - Stack unwinding

---

## Performance Considerations

**Hot Paths:**
- Single step execution
- Register inspection
- Symbol lookup

**Optimizations:**
- Symbol table: `std::map` for O(log n) lookup
- Addr→symbol: `upper_bound` for O(log n) search
- Register changes: Only track for single steps
- Memory reads: Batch where possible

**Not Optimized Yet:**
- Disassembly (infrequent operation)
- ELF loading (one-time operation)
- Symbol table loading (one-time operation)

---

## See Also

- [Multi-ISA Strategy](multi-isa.md) - How we support multiple ISAs
- [Testing Guide](testing.md) - Testing practices
- [Implementation Plan](../design/implementation-plan.md) - Overall roadmap
