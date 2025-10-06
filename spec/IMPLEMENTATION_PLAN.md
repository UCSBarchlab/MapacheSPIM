# MapacheSail Implementation Plan
## Interactive RISC-V Simulator Using Sail Backend

### Overview
Build a Python-based interactive console similar to the original MapacheSim (SPIM-like interface) but using the Sail RISC-V formal specification as the simulation engine. This provides a teaching tool with a formally verified ISA backend.

---

## Architecture

```
┌─────────────────────────────────────┐
│   Python Console (mapache.py)      │
│   - cmd.Cmd interactive shell       │
│   - Commands: step, run, regs, mem  │
│   - Breakpoints, labels             │
└──────────────┬──────────────────────┘
               │ ctypes/cffi
┌──────────────▼──────────────────────┐
│   Python Bindings (sail_wrapper.py) │
│   - Expose C API to Python          │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   C Library (libsailsim.so)         │
│   - Wrapper around Sail-gen C code  │
│   - step(), get_reg(), get_mem()    │
│   - load_elf(), set_breakpoint()    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Sail RISC-V Generated C Code      │
│   - ztry_step() - execute 1 instr   │
│   - Sail runtime functions          │
└─────────────────────────────────────┘
```

---

## Critical Proof-of-Concepts (Simplified MVP)

### POC 1: Build Sail RISC-V as a Controllable Library
**Goal:** Modify the Sail RISC-V build to create a shared library instead of standalone executable.

**Tasks:**
1. ✅ Understand existing `riscv_sim.cpp` architecture
2. Create `libsailsim` wrapper:
   - Extract core simulation logic from `riscv_sim.cpp`
   - Create C API functions (no C++ symbols)
   - Build as shared library (.so/.dylib)

**Key Functions to Expose:**
```c
// Initialization
void* sail_init(void);
void sail_load_elf(void* ctx, const char* elf_path);
void sail_reset(void* ctx);

// Execution
int sail_step(void* ctx);  // Returns: 0=ok, 1=breakpoint, 2=halt, -1=error
void sail_run(void* ctx, uint64_t max_steps);

// State Inspection
uint64_t sail_get_pc(void* ctx);
uint64_t sail_get_reg(void* ctx, int reg_num);
void sail_read_mem(void* ctx, uint64_t addr, void* buf, size_t len);

// Disassembly
const char* sail_disasm(void* ctx, uint64_t addr);
```

**Deliverable:** `libsailsim.so` + `sailsim.h`

---

### POC 2: Python Bindings with ctypes
**Goal:** Create Python wrapper to call the C library.

**Tasks:**
1. Use Python `ctypes` to load `libsailsim.so`
2. Wrap all C API functions
3. Handle type conversions (uint64_t ↔ Python int)
4. Manage context lifecycle

**File:** `mapachesail/sail_backend.py`
```python
import ctypes
from ctypes import c_void_p, c_char_p, c_uint64, c_int

class SailSimulator:
    def __init__(self, lib_path="./libsailsim.so"):
        self.lib = ctypes.CDLL(lib_path)
        self._setup_functions()
        self.ctx = self.lib.sail_init()

    def step(self):
        return self.lib.sail_step(self.ctx)

    def get_pc(self):
        return self.lib.sail_get_pc(self.ctx)

    def get_reg(self, reg_num):
        return self.lib.sail_get_reg(self.ctx, reg_num)

    # etc...
```

**Deliverable:** `sail_backend.py` with working Python→C calls

---

### POC 3: Minimal Python Console
**Goal:** Interactive console that can step through RISC-V programs.

**Tasks:**
1. Create `MapacheSailConsole(cmd.Cmd)` class
2. Implement essential commands:
   - `load <elf>` - Load RISC-V ELF file
   - `step [n]` - Execute n instructions
   - `run` - Run to completion
   - `regs` - Display registers (x0-x31, pc)
   - `mem <addr>` - Display memory at address

**File:** `mapachesail/console.py` (based on `original_console.py`)

**Deliverable:** Working interactive console for stepping RISC-V ELF files

---

### POC 4: Register & Memory Inspection
**Goal:** Pretty-print register and memory state.

**Tasks:**
1. Get all 32 RISC-V registers from Sail
2. Format register display (like original MapacheSim)
3. Read memory ranges
4. Display memory in hex dump format

**Register Display Format:**
```
x0 = 0x00000000  x1 = 0x7ffffff8  x2 = 0x7ffffff0  x3 = 0x00000000
x4 = 0x00000000  x5 = 0x00000001  x6 = 0x00000000  x7 = 0x00000000
...
pc = 0x80000050
```

**Memory Display Format:**
```
0x80000000:  24 02 00 04  3c 04 00 04  34 84 00 00  00 00 00 0c
0x80000010:  24 02 00 05  00 40 20 20  0c 00 40 11  00 40 28 20
```

**Deliverable:** Functions for formatted state display

---

### POC 5: Disassembly Support
**Goal:** Show disassembled instructions during stepping.

**Tasks:**
1. Expose Sail's built-in disassembler (it already has one!)
2. OR use external RISC-V disassembler (riscv-gnu-toolchain objdump)
3. Display format: `[PC] raw_hex instruction`

**Example Output:**
```
(mapachesail) step
[0x80000000] 0x00000297   auipc x5, 0x0
```

**Deliverable:** Instruction display during stepping

---

## Phase 1 Implementation Order (MVP)

### Week 1: Sail Library Wrapper
- [ ] Study `riscv_sim.cpp` and Sail-generated code
- [ ] Create `sailsim_wrapper.cpp` with C API
- [ ] Modify CMakeLists.txt to build shared library
- [ ] Test C API directly from C test program

### Week 2: Python Bindings
- [ ] Create `sail_backend.py` with ctypes
- [ ] Test init, load_elf, step, get_reg from Python
- [ ] Handle errors and edge cases
- [ ] Add unit tests

### Week 3: Console Interface
- [ ] Port `original_console.py` structure
- [ ] Implement: load, step, run, regs, mem commands
- [ ] Test with simple RISC-V programs
- [ ] Add help text and error handling

### Week 4: Polish & Testing
- [ ] Disassembly integration
- [ ] Test with example programs (fibonacci, matrix_mult)
- [ ] Documentation
- [ ] Demo video

---

## Future Enhancements (Beyond MVP)

### Phase 2: Advanced Debugging
- Breakpoints (address, label, register value)
- Watchpoints (memory changes)
- Reverse execution (if Sail supports it)
- Call stack tracking

### Phase 3: ISA Abstraction
- Abstract backend interface
- Support multiple Sail models (ARM, MIPS via Sail)
- Plugin architecture for different ISAs

### Phase 4: Educational Features
- Instruction statistics
- Pipeline visualization
- Cache simulation integration
- Performance profiling

### Phase 5: Integration
- Jupyter notebook kernel
- VS Code debug adapter
- GDB remote protocol support

---

## Technical Challenges & Solutions

### Challenge 1: Sail-Generated Code is C++
**Problem:** Sail generates C++, but ctypes works better with C ABI
**Solution:** Create thin C wrapper (`extern "C"`) around C++ code

### Challenge 2: Memory Management
**Problem:** Sail uses custom memory structures
**Solution:** Copy data to Python buffers, don't expose Sail internals

### Challenge 3: Register Access
**Problem:** Sail might not expose individual register getters
**Solution:** Access Sail's internal register array or use Sail's trace callbacks

### Challenge 4: No Assembly Support Initially
**Problem:** Original MapacheSim assembled code, Sail only runs ELF
**Solution:** Use GNU RISC-V assembler externally, load resulting ELF

### Challenge 5: Breakpoints
**Problem:** Sail runs continuously, no built-in breakpoint support
**Solution:** Check PC after each step in wrapper layer

---

## File Structure (Proposed)

```
MapacheSail/
├── sail-riscv/              # Git submodule (existing)
├── libsailsim/              # C wrapper library
│   ├── CMakeLists.txt
│   ├── sailsim.h           # C API header
│   ├── sailsim_wrapper.cpp # Implementation
│   └── test_api.c          # C API tests
├── mapachesail/             # Python package
│   ├── __init__.py
│   ├── sail_backend.py     # ctypes bindings
│   ├── console.py          # Interactive console
│   ├── formatters.py       # Display helpers
│   └── riscv_defs.py       # RISC-V constants
├── examples/                # Test programs (existing)
├── spec/                    # Specifications (existing)
├── tests/                   # Python tests
│   ├── test_backend.py
│   └── test_console.py
├── setup.py                 # Python package setup
└── README.md
```

---

## Success Criteria (MVP Complete When...)

1. ✅ Can load a RISC-V ELF file
2. ✅ Can single-step through instructions
3. ✅ Can view register state (x0-x31, PC)
4. ✅ Can view memory contents
5. ✅ Can run until completion
6. ✅ Shows disassembled instructions while stepping
7. ✅ Works with fibonacci and matrix_multiply examples

---

## Testing Strategy

### Unit Tests
- C API functions (load, step, get_reg, etc.)
- Python bindings (type conversions, error handling)
- Console commands (parsing, execution)

### Integration Tests
- Load and run fibonacci.elf
- Verify register values at specific PCs
- Check memory contents after execution
- Compare output with standalone Sail emulator

### Educational Use Cases
- Student loads program and steps through
- Instructor sets breakpoint at function entry
- Student examines stack pointer changes
- Memory dump shows data segment

---

## Timeline Estimate

- **POC 1 (Sail Library):** 1-2 weeks
- **POC 2 (Python Bindings):** 1 week
- **POC 3 (Console):** 1 week
- **POC 4 (State Display):** 3-5 days
- **POC 5 (Disassembly):** 3-5 days
- **Testing & Polish:** 1 week

**Total MVP:** 5-7 weeks

---

## Next Steps

1. **Immediate:** Build Sail RISC-V to understand generated code structure
2. **Then:** Create minimal C wrapper with just `init()` and `step()`
3. **Then:** Test from Python with ctypes
4. **Then:** Expand to full console

Would you like to proceed with POC 1 (building the Sail library wrapper)?
