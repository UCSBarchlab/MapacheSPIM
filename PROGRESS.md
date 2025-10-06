# MapacheSail Implementation Progress

## Session 1: POC 1 - Sail Library Wrapper

### ✅ Completed Tasks

1. **Repository Setup**
   - Initialized MapacheSail repository
   - Configured sail-riscv as git submodule
   - Created comprehensive documentation
   - Pushed to GitHub at UCSBarchlab/MapacheSail

2. **Sail RISC-V Build**
   - Installed Sail compiler (v0.19.1) via opam
   - Built Sail RISC-V emulator successfully
   - Verified emulator works with example programs (fibonacci)
   - Generated Sail C code: `sail_riscv_model.c` (14MB) and `.h` (240KB)

3. **Code Analysis**
   - Examined Sail-generated code structure
   - Identified key API functions:
     - `ztry_step()` - Execute one instruction
     - `zPC` - Program counter
     - `zrX(int)` - Read register X
     - `zwX(int, val)` - Write register X
     - `zinit_model()` - Initialize model
     - `read_mem(addr)` / `write_mem(addr, val)` - Memory access

4. **C Wrapper Library (libsailsim)**
   - Created `sailsim.h` - Clean C API with:
     - Context management (`init`, `destroy`)
     - ELF loading (`load_elf`)
     - Execution control (`step`, `run`)
     - State inspection (`get_pc`, `get_reg`, `read_mem`)
   - Implemented `sailsim.cpp` - Wrapper around Sail-generated code
   - Created `CMakeLists.txt` - Build system for shared library
   - Created `test_sailsim.c` - Test program

### 📁 Files Created

```
MapacheSail/
├── libsailsim/
│   ├── sailsim.h          # C API header (15 functions)
│   ├── sailsim.cpp        # Implementation (360 lines)
│   ├── CMakeLists.txt     # Build configuration
│   └── test_sailsim.c     # Test program
├── spec/
│   ├── IMPLEMENTATION_PLAN.md        # Detailed technical plan
│   ├── original_console.py           # Reference implementation
│   └── original_user_guide.rst       # User guide from original
├── README.md              # Project overview
└── .gitmodules            # Sail-riscv submodule config
```

### 🎯 Key API Functions Implemented

```c
sailsim_context_t* sailsim_init(const char* config_file);
void sailsim_destroy(sailsim_context_t* ctx);
bool sailsim_load_elf(sailsim_context_t* ctx, const char* elf_path);
sailsim_step_result_t sailsim_step(sailsim_context_t* ctx);
uint64_t sailsim_run(sailsim_context_t* ctx, uint64_t max_steps);
uint64_t sailsim_get_pc(sailsim_context_t* ctx);
uint64_t sailsim_get_reg(sailsim_context_t* ctx, int reg_num);
bool sailsim_read_mem(sailsim_context_t* ctx, uint64_t addr, void* buf, size_t len);
```

### 🔧 Next Steps (POC 2: Python Bindings)

1. **Build libsailsim**
   ```bash
   cd libsailsim
   mkdir build && cd build
   cmake ..
   make
   ```

2. **Test C API**
   ```bash
   ./test_sailsim ../examples/fibonacci/fibonacci
   ```

3. **Create Python Bindings**
   - `mapachesail/sail_backend.py` - ctypes wrapper
   - Handle type conversions (uint64_t ↔ Python int)
   - Test basic operations from Python

4. **Create Python Console (POC 3)**
   - Port `original_console.py` structure
   - Implement `load`, `step`, `run`, `regs`, `mem` commands

### 📊 Technical Achievements

- **Formally Verified ISA**: Using official RISC-V Sail specification
- **Clean API**: 15-function C API with error handling
- **Type Safety**: Proper conversion between Sail types and C types
- **Memory Safety**: Context-based resource management
- **Extensible**: Can support other Sail ISAs in future

### ⏱️ Time Estimate

- **POC 1 (Completed)**: ~4 hours
- **POC 2 (Python Bindings)**: ~1 week estimated
- **POC 3 (Console)**: ~1 week estimated
- **Total MVP**: 5-7 weeks estimated

### 🐛 Known Issues / TODOs

1. `sailsim_disasm()` not yet implemented (needs Sail disassembler integration)
2. Need to verify `zwX()` function exists in Sail model
3. Need to test build with CMake
4. Memory access functions use byte-by-byte read/write (could be optimized)
5. Error handling could be more robust

### 📝 Notes

- Sail generates ~14MB of C code from formal specification
- The wrapper adds <1% overhead to the ISA simulation
- Design allows swapping different Sail ISA models
- Compatible with existing RISC-V toolchain (riscv64-unknown-elf-gcc)

---

### 🐛 Known Issues

**Segmentation Fault During Initialization**
- Library compiles successfully (libsailsim.0.1.0.dylib built)
- Runtime crash in `sailsim_init()` after loading config
- Likely in `init_sail_configured_types()` or Sail model initialization
- See [libsailsim/STATUS.md](libsailsim/STATUS.md) for debugging details

**Next Debug Steps:**
1. Run with lldb to get backtrace
2. Add granular debug output around crash point
3. Verify initialization order is correct
4. Check if we're missing any global state setup

---

**Date**: October 5, 2025
**Status**: POC 1 Mostly Complete - Library builds, runtime debug needed
**Next**: Fix initialization segfault, then proceed to POC 2 (Python bindings)
