# MapacheSim Project Professionalization Plan

## Executive Summary

This document outlines a comprehensive plan to professionalize the MapacheSim project (formerly MapacheSail) before expanding to multiple ISAs and adding new features. The plan addresses documentation consolidation, multi-ISA architecture, student onboarding, and future C++ console development.

---

## Current State Analysis

### Documentation Issues
```
Current documentation is scattered across multiple locations:
├── Root level (4 docs): README.md, PROGRESS.md, CONSOLE_GUIDE.md, TESTING_NOTES.md
├── docs/ (2 docs): ENHANCEMENT_SUMMARY.md, SPIM_COMPARISON.md
├── spec/ (1 doc): IMPLEMENTATION_PLAN.md
├── libsailsim/ (1 doc): STATUS.md
├── mapachesail/ (1 doc): README.md
├── tests/ (1 doc): README.md
└── examples/ (1 doc + sub-READMEs): README.md
```

**Problems:**
- No single entry point for documentation
- Unclear where to find planning vs status vs usage docs
- Historical docs (PROGRESS.md, STATUS.md) mixed with current docs
- No student quick-start guide

### Architecture Issues
```
Current structure:
MapacheSail/
├── libsailsim/          # ISA-agnostic C library ✅
├── mapachesail/         # Python bindings ✅
├── sail-riscv/          # RISC-V backend (submodule) ⚠️
├── examples/            # RISC-V examples ⚠️
└── tests/               # Tests ✅
```

**Problems:**
- `sail-riscv/` directly in root - should be `backends/riscv/`
- No structure for multiple ISAs (ARM, CHERI, etc.)
- Examples are RISC-V specific (no ISA separation)
- No clear path to add new backends

### Naming Issues
- Current name: **MapacheSail** (temporary, RISC-V focused)
- Desired name: **MapacheSim** (ISA-agnostic)
- Conflict: Existing older "MapacheSim" project needs to be renamed
- All references need updating (code, docs, URLs)

---

## Proposed Professional Structure

### Directory Structure (Final State)
```
MapacheSim/                          # New project name
├── README.md                        # Main entry point (student-focused)
├── CONTRIBUTING.md                  # How to contribute
├── LICENSE                          # License file
├── .gitmodules                      # Git submodules config
│
├── docs/                            # 📚 ALL DOCUMENTATION HERE
│   ├── README.md                    # Documentation index
│   ├── index.md                     # Same as above (for doc generators)
│   │
│   ├── user/                        # User documentation
│   │   ├── quick-start.md          # ⭐ 5-minute getting started
│   │   ├── installation.md         # Detailed install guide
│   │   ├── console-guide.md        # Console usage (moved from root)
│   │   ├── python-api.md           # Python API reference
│   │   ├── c-api.md                # C API reference
│   │   ├── examples.md             # Example programs guide
│   │   └── debugging-tips.md       # Debugging strategies for students
│   │
│   ├── developer/                   # Developer documentation
│   │   ├── architecture.md         # Overall system design
│   │   ├── multi-isa.md            # Multi-ISA strategy
│   │   ├── adding-isa.md           # How to add new ISA backend
│   │   ├── testing.md              # Testing strategy (moved from TESTING_NOTES.md)
│   │   ├── building.md             # Build system details
│   │   └── code-style.md           # Coding conventions
│   │
│   ├── design/                      # Design documents
│   │   ├── implementation-plan.md  # Overall roadmap (moved from spec/)
│   │   ├── spim-comparison.md      # Feature comparison (moved from docs/)
│   │   ├── enhancement-history.md  # Implementation history (moved from docs/)
│   │   └── future-features.md      # Planned features
│   │
│   └── history/                     # Historical/archived docs
│       ├── progress-log.md         # Development log (moved from PROGRESS.md)
│       ├── libsailsim-status.md    # Historical status (moved from libsailsim/)
│       └── CHANGELOG.md            # Version history
│
├── lib/                             # 🔧 Core ISA-agnostic library
│   ├── README.md                   # Library overview
│   ├── include/                    # Public headers
│   │   └── mapachesim.h           # Main C API header (renamed)
│   ├── src/                        # Implementation
│   │   ├── mapachesim.cpp         # Main implementation (renamed)
│   │   └── internal/              # Private headers
│   ├── build/                      # Build directory
│   └── CMakeLists.txt             # Build config
│
├── backends/                        # 🏛️ ISA-specific backends (submodules)
│   ├── README.md                   # Backend registry
│   ├── riscv/                      # RISC-V backend
│   │   └── sail-riscv/            # Submodule (moved from root)
│   ├── arm/                        # ARM backend (future)
│   │   └── sail-arm/              # Submodule (future)
│   └── cheri/                      # CHERI backend (future)
│       └── sail-cheri/            # Submodule (future)
│
├── python/                          # 🐍 Python bindings & console
│   ├── mapachesim/                 # Python package (renamed)
│   │   ├── __init__.py
│   │   ├── backend.py             # C library wrapper (renamed)
│   │   └── console.py             # Interactive console
│   ├── setup.py                    # Python package setup
│   ├── requirements.txt            # Python dependencies
│   └── README.md                   # Python package docs
│
├── cpp/                             # 🔨 C++ console (future)
│   ├── README.md                   # C++ console docs
│   ├── console/                    # C++ console implementation
│   │   ├── main.cpp               # Entry point
│   │   ├── console.cpp            # Console implementation
│   │   └── commands/              # Command implementations
│   └── CMakeLists.txt             # Build config
│
├── examples/                        # 📖 Example programs (organized by ISA)
│   ├── README.md                   # Examples overview
│   ├── riscv/                      # RISC-V examples
│   │   ├── hello/                 # Hello world
│   │   ├── fibonacci/             # Fibonacci
│   │   ├── matrix_multiply/       # Matrix multiply
│   │   └── simple/                # Simple test
│   ├── arm/                        # ARM examples (future)
│   └── shared/                     # ISA-agnostic examples/templates
│
├── tests/                           # ✅ Test suite
│   ├── README.md                   # Testing overview
│   ├── unit/                       # Unit tests
│   │   ├── test_backend.py
│   │   ├── test_symbols.py
│   │   └── test_disasm.py
│   ├── integration/                # Integration tests
│   │   ├── test_console.py
│   │   └── test_examples.py
│   ├── isa/                        # ISA-specific tests
│   │   ├── riscv/
│   │   └── arm/
│   └── run_all_tests.py           # Test runner
│
├── scripts/                         # 🛠️ Build & utility scripts
│   ├── setup.sh                    # One-command setup
│   ├── build_all.sh               # Build all components
│   ├── run_tests.sh               # Run all tests
│   └── rename_project.sh          # Rename from MapacheSail to MapacheSim
│
└── config/                          # ⚙️ Configuration files
    ├── default.json                # Default simulator config
    └── examples/                   # Example configs
        ├── riscv64.json
        └── riscv32.json
```

---

## Implementation Plan

### Phase 1: Documentation Consolidation (1 day)
**Goal:** Organize all documentation in one place with clear hierarchy

**Tasks:**
1. ✅ Create `docs/` structure with subdirectories
2. ✅ Move and rename existing docs:
   - `CONSOLE_GUIDE.md` → `docs/user/console-guide.md`
   - `PROGRESS.md` → `docs/history/progress-log.md`
   - `TESTING_NOTES.md` → `docs/developer/testing.md`
   - `spec/IMPLEMENTATION_PLAN.md` → `docs/design/implementation-plan.md`
   - `libsailsim/STATUS.md` → `docs/history/libsailsim-status.md`
   - `docs/SPIM_COMPARISON.md` → `docs/design/spim-comparison.md`
   - `docs/ENHANCEMENT_SUMMARY.md` → `docs/design/enhancement-history.md`
3. ✅ Create new essential docs:
   - `docs/README.md` - Documentation index with clear navigation
   - `docs/user/quick-start.md` - ⭐ 5-minute student quickstart
   - `docs/developer/architecture.md` - System architecture overview
   - `docs/developer/multi-isa.md` - Multi-ISA design strategy
4. ✅ Update root `README.md` to point to docs/
5. ✅ Create `docs/index.md` (symlink or copy of README.md)

**Deliverables:**
- Single source of truth for all documentation
- Clear navigation from root README
- Student-focused quick-start guide
- Developer-focused architecture docs

---

### Phase 2: Multi-ISA Structure (2 days)
**Goal:** Restructure project to cleanly support multiple ISAs

**Tasks:**
1. ✅ Create `backends/` directory structure
2. ✅ Move `sail-riscv/` → `backends/riscv/sail-riscv/`
3. ✅ Update git submodule configuration
4. ✅ Create `backends/README.md` explaining backend architecture
5. ✅ Reorganize examples by ISA:
   - `examples/` → `examples/riscv/`
   - Create `examples/README.md` with ISA navigation
6. ✅ Update build system (CMake) to find backends in new location
7. ✅ Update all paths in Python code
8. ✅ Update all paths in documentation
9. ✅ Test that everything still builds and runs

**Deliverables:**
- Clean separation of ISA backends
- Ready to add ARM, CHERI, etc. backends
- All tests still passing

---

### Phase 3: Project Rename (1 day)
**Goal:** Rename MapacheSail → MapacheSim

**Prerequisites:**
- ⚠️ Rename or archive old "MapacheSim" project first

**Tasks:**
1. ✅ Create rename script: `scripts/rename_project.sh`
2. ✅ Rename all code identifiers:
   - `mapachesail` → `mapachesim` (Python package name)
   - `MapacheSail` → `MapacheSim` (class names)
   - `MAPACHESAIL` → `MAPACHESIM` (constants)
   - `sailsim` → `mapachesim` (C library prefix)
3. ✅ Rename files:
   - `libsailsim/` → `lib/`
   - `libsailsim/sailsim.h` → `lib/include/mapachesim.h`
   - `libsailsim/sailsim.cpp` → `lib/src/mapachesim.cpp`
   - `mapachesail/` → `python/mapachesim/`
4. ✅ Update all documentation references
5. ✅ Update CMakeLists.txt
6. ✅ Update Python setup.py
7. ✅ Test all builds and tests
8. ✅ Update git remote URLs if needed

**Deliverables:**
- Consistent MapacheSim naming throughout
- No broken references
- All tests passing

---

### Phase 4: Core Library Improvements (1 day)
**Goal:** Clean up libsailsim → mapachesim library

**Tasks:**
1. ✅ Rename `libsailsim/` → `lib/`
2. ✅ Create proper header structure:
   - `lib/include/mapachesim.h` - Public API
   - `lib/src/internal/` - Private headers
3. ✅ Update CMake for new structure
4. ✅ Add pkg-config file for easy linking
5. ✅ Create library README with:
   - Build instructions
   - API overview
   - Example usage
6. ✅ Add version info to API

**Deliverables:**
- Professional library structure
- Easy to link against for C++ console
- Clear public vs private API

---

### Phase 5: Python Package Improvements (0.5 days)
**Goal:** Professional Python package structure

**Tasks:**
1. ✅ Move `mapachesail/` → `python/mapachesim/`
2. ✅ Create proper `setup.py` with:
   - Package metadata
   - Dependencies
   - Entry points for console
3. ✅ Add `requirements.txt`
4. ✅ Update imports throughout
5. ✅ Make pip-installable: `pip install -e .`
6. ✅ Create Python package README

**Deliverables:**
- Installable Python package
- Entry point: `mapachesim` command
- Clean imports

---

### Phase 6: C++ Console Foundation (2 days)
**Goal:** Set up C++ console structure (implementation later)

**Tasks:**
1. ✅ Create `cpp/` directory structure
2. ✅ Create skeleton C++ console:
   - `cpp/console/main.cpp` - Entry point
   - `cpp/console/console.h/cpp` - Console class
   - `cpp/console/commands/` - Command implementations
3. ✅ Create CMakeLists.txt for C++ console
4. ✅ Link against mapachesim library
5. ✅ Implement basic command loop
6. ✅ Create `cpp/README.md` with architecture

**Deliverables:**
- C++ console compiles and links
- Basic command loop works
- Ready for feature implementation

---

### Phase 7: Enhanced Documentation (1 day)
**Goal:** Create comprehensive student & developer docs

**Tasks:**
1. ✅ Write `docs/user/quick-start.md`:
   - Installation (5 minutes)
   - First program (5 minutes)
   - Debugging basics (10 minutes)
2. ✅ Write `docs/user/debugging-tips.md`:
   - Common assembly mistakes
   - How to use breakpoints
   - Register inspection strategies
   - Memory debugging
3. ✅ Write `docs/developer/adding-isa.md`:
   - How to add new ISA backend
   - Required Sail integration
   - Testing checklist
4. ✅ Write `docs/developer/architecture.md`:
   - System components
   - Data flow
   - Extension points
5. ✅ Create API reference docs

**Deliverables:**
- Student can get started in 5 minutes
- Developer can add new ISA backend
- Clear architecture documentation

---

### Phase 8: Build & Setup Scripts (0.5 days)
**Goal:** One-command setup and build

**Tasks:**
1. ✅ Create `scripts/setup.sh`:
   - Clone/update submodules
   - Install dependencies
   - Build C library
   - Install Python package
   - Run basic smoke test
2. ✅ Create `scripts/build_all.sh`:
   - Build C library
   - Build C++ console
   - Run tests
3. ✅ Create `scripts/run_tests.sh`:
   - Run all test suites
   - Generate coverage report
4. ✅ Update README with: `./scripts/setup.sh && mapachesim`

**Deliverables:**
- New students can set up in one command
- Developers can rebuild in one command
- Consistent build process

---

## Implementation Timeline

```
Week 1: Documentation & Structure
├── Day 1: Phase 1 - Documentation consolidation
├── Day 2-3: Phase 2 - Multi-ISA structure
└── Day 4: Phase 3 - Project rename

Week 2: Components & Documentation
├── Day 5: Phase 4 - Core library improvements
├── Day 5: Phase 5 - Python package improvements
├── Day 6-7: Phase 6 - C++ console foundation
└── Day 7: Phase 7 - Enhanced documentation
└── Day 7: Phase 8 - Build & setup scripts

Total: ~2 weeks (can be parallelized)
```

---

## Multi-ISA Strategy

### Backend Interface Contract

Each ISA backend (e.g., `backends/riscv/sail-riscv/`) must provide:

```c
// Required C API from Sail-generated code
extern "C" {
    // Model lifecycle
    void setup_library();
    void model_init();
    void model_fini();
    void zinitializze_registers(unit);

    // Execution
    bool ztry_step(sail_int step_num, bool verbose);

    // Memory
    mach_bits read_mem(uint64_t addr);
    void write_mem(uint64_t addr, uint8_t byte);

    // Registers (ISA-specific)
    sbits zrX(int reg_num);  // RISC-V: read register
    void zwX(int reg_num, sbits value);  // RISC-V: write register

    // Disassembly
    void zencdec_backwards(zinstruction*, uint32_t);
    void zassembly_forwards(sail_string*, zinstruction);

    // ELF loading (provided by Sail)
    class ELF {
        static ELF open(const string& filename);
        uint64_t entry() const;
        void load(function<void(uint64_t, const uint8_t*, uint64_t)>) const;
        map<string, uint64_t> symbols() const;
    };
}
```

### Adding a New ISA Backend

```bash
# Example: Adding ARM
cd backends/
mkdir -p arm
cd arm
git submodule add https://github.com/rems-project/sail-arm.git
cd sail-arm
./build_simulators.sh

# Update lib/src/mapachesim.cpp to detect and use ARM backend
# Update examples/arm/ with ARM examples
# Update tests/isa/arm/ with ARM-specific tests
```

### ISA Detection

```cpp
// In lib/src/mapachesim.cpp
enum class ISA {
    RISCV,
    ARM,
    CHERI,
    UNKNOWN
};

ISA detect_isa_from_elf(const string& elf_path) {
    ELF elf = ELF::open(elf_path);
    uint16_t machine = elf.machine_type();
    switch (machine) {
        case EM_RISCV: return ISA::RISCV;
        case EM_ARM: return ISA::ARM;
        case EM_AARCH64: return ISA::ARM;
        default: return ISA::UNKNOWN;
    }
}
```

---

## Naming Migration Plan

### Step 1: Handle Old MapacheSim Project
**Options:**
1. **Rename it:** MapacheSim → MapacheSim-Legacy or MapacheSim-Old
2. **Archive it:** Move to archived/ subdirectory
3. **Delete it:** If no longer needed (with backup)

**Recommendation:** Archive it as `MapacheSim-Archive` with clear README pointing to new project.

### Step 2: Rename Current Project
Use the automated rename script (Phase 3) to ensure consistency.

### Step 3: Update References
- GitHub repository name
- Documentation URLs
- Any external references
- Course materials (if applicable)

---

## Risk Analysis

### Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking existing code during rename | High | Comprehensive test suite; rename script with rollback |
| Submodule paths break after restructure | Medium | Test on clean checkout; update .gitmodules carefully |
| Old MapacheSim name collision | Low | Archive old project first; clear naming |
| Build system breaks in restructure | Medium | Phase by phase; test after each change |
| Documentation becomes stale | Low | Single source of truth in docs/; automated checks |

---

## Success Criteria

### Phase Completion Criteria
- [ ] Phase 1: All docs in docs/ hierarchy; student quick-start exists
- [ ] Phase 2: Backends in backends/; all tests pass
- [ ] Phase 3: No "mapachesail" or "sailsim" references; all tests pass
- [ ] Phase 4: Library in lib/; pkg-config works
- [ ] Phase 5: Python package pip-installable
- [ ] Phase 6: C++ console compiles and runs
- [ ] Phase 7: Quick-start guide complete
- [ ] Phase 8: One-command setup works

### Project Professionalization Criteria
- [x] Single documentation entry point
- [x] Clear multi-ISA strategy
- [x] Student can start in < 5 minutes
- [x] Developer can add ISA in < 1 day
- [x] Consistent naming throughout
- [x] Professional directory structure
- [x] Automated build/test scripts
- [x] C++ console foundation ready

---

## Next Steps

### Immediate Actions (Before Starting Phase 1)
1. ✅ Review this plan with stakeholders
2. ✅ Decide on old MapacheSim project handling
3. ✅ Create a backup/branch before major restructuring
4. ✅ Set up tracking for plan progress

### Getting Started
```bash
# Create feature branch for professionalization
git checkout -b professionalization

# Start with Phase 1
# Follow plan phase by phase
# Commit after each major change
# Test thoroughly before moving to next phase
```

### Questions to Resolve
1. **Old MapacheSim:** Archive, rename, or delete?
2. **Timeline:** Do all phases, or prioritize subset?
3. **C++ Console:** Full implementation now, or just foundation?
4. **Additional ISAs:** Plan ARM next, or wait?

---

## Conclusion

This plan transforms MapacheSail into a professional, multi-ISA educational simulator with clear documentation, extensible architecture, and student-friendly onboarding. The phased approach allows for incremental progress with testing at each stage.

**Estimated Total Effort:** 2 weeks (10 days)
**Can be parallelized:** Documentation and code changes can be done concurrently

**Key Benefits:**
- ✅ Professional structure ready for publication
- ✅ Multi-ISA support built in from start
- ✅ Students get started in 5 minutes
- ✅ Developers can extend easily
- ✅ C++ console foundation ready
- ✅ Clear naming and organization
