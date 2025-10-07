# Project Rename: MapacheSPIM → MapacheSPIM

This document outlines the systematic plan for renaming the project from MapacheSPIM to MapacheSPIM.

## Rationale

MapacheSPIM is a tribute to the original SPIM (MIPS simulator) while establishing the project's identity as a multi-ISA educational simulator.

## Rename Checklist

### 1. Python Package
- [ ] Rename directory: `mapachespim/` → `mapachespim/`
- [ ] Update imports in all Python files
- [ ] Update console prompt: `(mapachespim)` → `(mapachespim)`
- [ ] Update command-line tool entry point

### 2. Package Metadata
- [ ] Update `setup.py`:
  - Package name: `mapachespim` → `mapachespim`
  - Entry point: `mapachespim` → `mapachespim`
  - Description references
- [ ] Update `__init__.py` if needed

### 3. Documentation
- [ ] Update all markdown files in `docs/`
- [ ] Update `README.md`
- [ ] Update `examples/README.md`
- [ ] Update `backends/README.md`
- [ ] Remove "will be renamed to MapacheSPIM" notes

### 4. Test Files
- [ ] Update test imports
- [ ] Update test paths to examples
- [ ] Update any hardcoded references

### 5. Build System
- [ ] Check CMakeLists.txt for any references
- [ ] Update library target names if needed

### 6. Git Repository (Future)
- [ ] Repository URL will change
- [ ] Update all GitHub links in documentation

## File Changes Required

### Python Files
```
mapachespim/__init__.py
mapachespim/console.py
mapachespim/sail_backend.py
tests/test_console_working.py
tests/test_symbols.py
tests/test_disasm_comprehensive.py
setup.py
```

### Documentation Files
```
README.md
docs/README.md
docs/user/quick-start.md
docs/user/console-guide.md
docs/developer/architecture.md
docs/developer/multi-isa.md
examples/README.md
backends/README.md
```

## Execution Order

1. **Python package directory rename** - Use `git mv` to preserve history
2. **Update all Python imports** - Change import statements
3. **Update setup.py** - Package name and entry points
4. **Update all documentation** - Global find/replace
5. **Test installation** - `pip install -e .`
6. **Test functionality** - Run all tests
7. **Commit changes** - Single atomic commit

## Testing Plan

After rename:
```bash
# Uninstall old package
pip3 uninstall mapachespim

# Install new package
pip3 install -e .

# Test command works
mapachespim --version

# Run all tests
python3 tests/test_console_working.py
python3 tests/test_symbols.py
python3 tests/test_disasm_comprehensive.py

# Manual smoke test
mapachespim
(mapachespim) load examples/riscv/fibonacci/fibonacci
(mapachespim) break main
(mapachespim) run
(mapachespim) step
(mapachespim) quit
```

## Rollback Plan

If issues arise:
```bash
git reset --hard HEAD~1  # Undo the rename commit
pip3 install -e .         # Reinstall old version
```

## Notes

- Use `git mv` for all file/directory moves to preserve history
- Make all changes in a single commit for easy rollback
- Update documentation to remove "will be renamed" notes
- Keep library name as `libsailsim` (ISA-agnostic, doesn't need rename)
