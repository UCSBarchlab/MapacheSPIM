# libsailsim Build Status

## ✅ Successfully Completed

1. **Library Architecture Designed**
   - Clean C API wrapper around Sail-generated C++ code
   - 15 core functions for simulator control
   - Proper type conversions (sbits ↔ uint64_t)

2. **CMake Build System Created**
   - Links against Sail RISC-V model
   - Includes all required dependencies (GMP, softfloat, etc.)
   - Builds shared library (libsailsim.dylib)

3. **Core Functionality Implemented**
   - ✅ Simulator initialization
   - ✅ ELF loading
   - ✅ Step execution
   - ✅ Register access (get/set)
   - ✅ Memory access (read/write)
   - ✅ PC access

4. **Successfully Built**
   - libsailsim.0.1.0.dylib (5.4MB)
   - test_sailsim executable
   - No compilation errors (only format warnings)

## ⚠️ Current Issue: Segmentation Fault

**Status:** Library compiles successfully but crashes during initialization

**Error:** Segmentation fault in `sailsim_init()`

**Progress:**
- ✅ Fixed GMP C++ linkage issues
- ✅ Fixed header include paths
- ✅ Fixed sbits type conversions
- ✅ Fixed initialization order (config must be loaded before init_sail_configured_types)
- ✅ Config error resolved
- ❌ Segfault during initialization (likely in zinit_model or init_sail_configured_types)

**Last Known State:**
- Prints "Initializing Sail RISC-V simulator..."
- Segfaults before printing "Simulator initialized successfully!"
- Crash happens after zinit_model() or during init_sail_configured_types()

## 🔍 Next Steps for Debugging

1. **Add more debug output** to pinpoint exact location of segfault:
   ```cpp
   printf("Before zinit_model\n"); fflush(stdout);
   zinit_model(ctx->config_str);
   printf("After zinit_model\n"); fflush(stdout);
   ```

2. **Run with debugger:**
   ```bash
   lldb ./test_sailsim
   run ../../examples/fibonacci/fibonacci
   bt  # backtrace when it crashes
   ```

3. **Check if we need model_init()** - we might be double-initializing

4. **Verify config file** is valid and loads correctly

5. **Alternative approach:** Skip init_sail_configured_types() and see if basic stepping works

## 📊 Technical Details

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

### Initialization Order (Correct)
1. `setup_library()` - Sail runtime
2. `zset_pc_reset_address()` - Set reset PC
3. `zinit_model(config_file)` - Load config and init model
4. `init_sail_configured_types()` - Set configured types from config
5. `zinit_boot_requirements()` - Boot setup

### Global Variables Required
- config_print_*
- config_use_abi_names
- config_enable_rvfi
- trace_log

## 🎯 Success Criteria (Not Yet Met)

- [ ] Initialize simulator without crash
- [ ] Load ELF file
- [ ] Execute at least one instruction
- [ ] Read register state
- [ ] Display PC

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
