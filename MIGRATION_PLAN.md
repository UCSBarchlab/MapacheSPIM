# MapacheSPIM: SAIL to Unicorn Migration Plan

## Current Status

**Branch:** `feature/unicorn-backend`

**Test Results:** 175 passing, 8 failing (95.6% pass rate)

**Core Migration:** Complete - Unicorn Engine backend is fully functional

---

## What's Already Done

### Completed Work

1. **New Unicorn Backend** (`unicorn_backend.py` - 779 lines)
   - Full `UnicornSimulator` class replacing SAIL
   - Multi-ISA support: RISC-V 64-bit and ARM64
   - Capstone disassembly integration
   - SPIM-compatible syscall emulation (1, 4, 5, 10, 11, 12, 93)
   - Memory mapping with proper stack setup
   - HTIF tohost termination mechanism

2. **Pure Python ELF Loader** (`elf_loader.py` - 226 lines)
   - Uses `pyelftools` (no C++ ELFIO dependency)
   - ISA auto-detection from ELF headers
   - Symbol table parsing

3. **Updated Dependencies** (`setup.py`)
   - `unicorn>=2.0.0`
   - `capstone>=5.0.0`
   - `pyelftools>=0.29`
   - No C/C++ compilation required

4. **Console Integration** (`console.py`)
   - All commands working with Unicorn backend
   - Output properly redirected for test compatibility

5. **Test Programs**
   - RISC-V: fibonacci, matrix_multiply, test_simple, hello_world
   - ARM64: fibonacci, hello_world, test_simple

---

## Remaining Work

### Phase 1: Fix Remaining Test Failures (8 tests)

#### 1.1 Disassembly Tests (5 failures)
**Issue:** Capstone uses ABI register names (`t0`, `zero`) but tests expect numeric names (`x5`, `x0`)

**Failing Tests:**
- `test_disasm_basic`
- `test_disasm_register_names`
- `test_disasm_instruction_types`
- `test_disasm_all_test_simple_instructions`
- `test_disasm_after_step`

**Solution Options:**
- A) Update tests to accept ABI names (user-friendly, modern approach)
- B) Configure Capstone to use numeric names (if supported)
- C) Post-process disassembly output to convert names

**Recommended:** Option A - ABI names are more readable and standard

#### 1.2 Symbol Tests (2 failures)
**Issue:** Console output not being captured properly in some test scenarios

**Failing Tests:**
- `test_addr_to_symbol_far_from_any_symbol`
- `test_step_shows_symbol_in_output`

**Solution:** Investigate output capture mechanism and fix test assertions

#### 1.3 Simulator Edge Case (1 failure)
**Issue:** `test_load_nonexistent_file` - Error handling behavior differs

**Solution:** Ensure proper exception is raised for non-existent files

---

### Phase 2: Code Cleanup

#### 2.1 Remove Deprecated SAIL Code
- [ ] Delete `mapachespim/sail_backend.py` (602 lines)
- [ ] Delete `mapachespim/simulator_cffi.py` (173 lines)

#### 2.2 Clean Up Development Artifacts
- [ ] Remove `test_cffi_simple.py`
- [ ] Remove `test_cffi_arm.py`
- [ ] Remove `test_no_steps.py`
- [ ] Remove `test_one_step.py`
- [ ] Remove `test_simple_double_step.py`
- [ ] Remove `debug_arm_crash.py`
- [ ] Remove `debug_with_lldb*.sh`
- [ ] Remove `a.txt.save`

#### 2.3 Clean Up Old Build Artifacts (if present)
- [ ] Remove `lib/` directory (old C++ wrappers)
- [ ] Remove `backends/` directory (SAIL submodules)
- [ ] Remove `.gitmodules` if referencing SAIL

---

### Phase 3: Documentation Updates

#### 3.1 Update README.md
- [ ] Remove all references to SAIL
- [ ] Update installation instructions (pip only, no cmake)
- [ ] Document Unicorn Engine dependency
- [ ] Update architecture diagram if present

#### 3.2 Update/Remove Planning Docs
- [ ] Update `ARM_PLAN.md` with completion status
- [ ] Remove or archive old migration docs

#### 3.3 Add Migration Notes
- [ ] Document breaking changes (if any)
- [ ] Note version bump to 0.2.0-unicorn

---

### Phase 4: Final Validation

#### 4.1 Full Test Suite
- [ ] All 183 tests passing
- [ ] Manual testing of console commands
- [ ] Test both RISC-V and ARM programs

#### 4.2 Installation Test
- [ ] Fresh virtualenv install via `pip install -e .`
- [ ] Verify all dependencies install correctly
- [ ] Test on clean system

#### 4.3 Performance Validation
- [ ] Run fibonacci and matrix_multiply
- [ ] Compare execution with expected results
- [ ] Check for memory leaks or crashes

---

### Phase 5: Commit and Merge

#### 5.1 Commit Changes
- [ ] Stage all migration-related changes
- [ ] Create descriptive commit message
- [ ] Reference any related issues

#### 5.2 Merge to Main
- [ ] Create pull request
- [ ] Document changes in PR description
- [ ] Merge feature branch

---

## Architecture Summary

### Before (SAIL-based)
```
User → Console → sail_backend.py → libsailsim.so → SAIL OCaml
                                         ↓
                                   C++ ELFIO Library
```

### After (Unicorn-based)
```
User → Console → unicorn_backend.py → Unicorn Engine (QEMU-based)
                         ↓
                    elf_loader.py → pyelftools
                         ↓
                    Capstone (disassembly)
```

**Benefits:**
- No C/C++ compilation required
- Pure pip install
- Battle-tested emulation (Unicorn/QEMU)
- Better ARM support
- Easier maintenance
- Cross-platform compatibility

---

## Files Changed

| File | Action | Notes |
|------|--------|-------|
| `mapachespim/unicorn_backend.py` | NEW | Core simulator |
| `mapachespim/elf_loader.py` | NEW | ELF parsing |
| `mapachespim/__init__.py` | MODIFIED | Export Unicorn |
| `mapachespim/console.py` | MODIFIED | Output fixes |
| `mapachespim/sail_backend.py` | DELETE | Old SAIL wrapper |
| `mapachespim/simulator_cffi.py` | DELETE | Unused CFFI |
| `setup.py` | MODIFIED | New dependencies |
| `README.md` | MODIFIED | Updated docs |
| Various test files | DELETE | Debug artifacts |

---

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1: Fix Tests | ~1 hour |
| Phase 2: Cleanup | ~30 min |
| Phase 3: Docs | ~30 min |
| Phase 4: Validation | ~30 min |
| Phase 5: Merge | ~15 min |
| **Total** | **~3 hours** |

---

## Success Criteria

1. All 183 tests passing
2. No SAIL code or references remaining
3. Clean `pip install` works
4. Both RISC-V and ARM programs execute correctly
5. Console fully functional
6. Documentation updated
