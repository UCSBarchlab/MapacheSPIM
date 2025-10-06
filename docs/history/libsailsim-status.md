# libsailsim Build Status

## ✅ Successfully Completed - POC 1 WORKING!

**Date:** October 6, 2025

**Status:** 🎉 POC 1 Complete - Library fully functional!

### Core Functionality ✅

1. **Library Architecture**
   - Clean C API wrapper around Sail-generated C++ code
   - 15 core functions for simulator control
   - Proper type conversions (sbits ↔ uint64_t)

2. **CMake Build System**
   - Links against Sail RISC-V model
   - Includes all required dependencies (GMP, softfloat, etc.)
   - Builds shared library (libsailsim.0.1.0.dylib - 5.4MB)

3. **Working Features**
   - ✅ Simulator initialization with default config
   - ✅ ELF loading
   - ✅ Step-by-step execution
   - ✅ Register access (get/set)
   - ✅ Memory access (read/write)
   - ✅ PC access and tracking
   - ✅ Test program executes successfully

### Test Results

```
Initializing Sail RISC-V simulator...
Simulator initialized successfully!
Loading ELF file: ../../examples/fibonacci/fibonacci
Entry PC: 0x80000000

Single-stepping first 10 instructions:
[0] PC = 0x0000000080000000
[1] PC = 0x0000000080000004
...
[9] PC = 0x0000000080000044

Register state: [all registers displayed correctly]
```

## 🔧 Technical Achievements

### Initialization Sequence (CRITICAL!)

The correct initialization order was discovered through debugging:

```cpp
1. setup_library()                     // Sail runtime
2. sail_config_set_string(config_json) // Load config into global state
3. init_sail_configured_types()        // Set abstract types from config
4. model_init()                        // Initialize GMP variables
5. zset_pc_reset_address(0x80000000)   // Set reset PC
6. zinit_model(config_json)            // Initialize with config
7. zinit_boot_requirements(UNIT)       // Boot setup
```

**Key insight:** `sail_config_set_string()` must be called BEFORE `model_init()` so the config is available when the model initializes.

### Issues Resolved During Development

1. **GMP C++ linkage conflicts** - Removed `extern "C"` wrapper around sail.h
2. **Missing headers** - Added correct include paths for riscv_platform_impl.h and elfio
3. **sbits type conversion** - Created helper functions for struct conversion
4. **Missing global variables** - Added all required config_* and trace_log globals
5. **Segmentation fault** - Discovered correct initialization sequence using lldb
6. **Config loading** - Must use `sail_config_set_string()` before `model_init()`

### Type Conversions
```cpp
// sbits = {uint64_t len; uint64_t bits;}
static inline sbits make_sbits(uint64_t value) {
    return {.bits = value, .len = 64};
}
static inline uint64_t get_sbits_value(sbits s) {
    return s.bits;
}
```

### Global Variables Required
```cpp
bool config_print_instr = false;
bool config_print_reg = false;
bool config_print_mem_access = false;
bool config_print_platform = false;
bool config_print_rvfi = false;
bool config_print_step = false;
bool config_use_abi_names = false;
bool config_enable_rvfi = false;
FILE *trace_log = stdout;
```

## 🎯 Success Criteria ✅ ALL MET!

- [x] Initialize simulator without crash
- [x] Load ELF file
- [x] Execute at least one instruction
- [x] Read register state
- [x] Display PC

## Files Modified
- `libsailsim/sailsim.h` - API header
- `libsailsim/sailsim.cpp` - Implementation
- `libsailsim/CMakeLists.txt` - Build system
- `libsailsim/test_sailsim.c` - Test program

## Build Commands
```bash
cd libsailsim/build
cmake ..
make
./test_sailsim ../../examples/fibonacci/fibonacci
```
