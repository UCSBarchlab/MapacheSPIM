# MapacheSPIM Test Suite

## Running the tests

From the repository root:

```bash
python -m pytest tests/                        # everything
python -m pytest tests/test_isa_conformance.py # one file
python -m pytest tests/ -k mips                # tests whose names mention mips
```

CI runs the suite on Linux, Windows, and macOS (Apple Silicon) against the installed wheel, plus
`ruff check`, `ruff format --check`, and `mypy` on `mapachespim/`.

### Comparing the assemblers with GNU `as`

The `test_differential_*.py` tests assemble randomized programs with both the built-in assemblers
and GNU `as` and require byte-identical output. They need the GNU cross binutils and are skipped
without them:

```bash
sudo apt install binutils-riscv64-linux-gnu binutils-mips-linux-gnu \
    binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
python -m pytest tests/test_differential_*.py
MAPACHESPIM_FUZZ_SCALE=50 python -m pytest tests/test_differential_*.py   # much deeper (CI runs this)
```

## What is tested where

Tests that run for **every registered ISA** (parametrized over `mapachespim.isa.ISA_SPECS` or the
bundled examples), so a new ISA is covered as soon as it is registered:

| File | What it checks |
|------|----------------|
| `test_isa_registry.py` | Every ISA has a consistent spec, engine binding, assembler target, and examples; name/alias/ELF lookups; `.isa` directives |
| `test_isa_conformance.py` | Assembles and runs small programs per ISA: every syscall, every register mapping, the register API, the default memory map |
| `test_syscalls.py` | `SyscallHandler` and `ProgramIO` with a fake machine (no emulator) |
| `test_elf_output.py` | ELF headers and symbol tables are well formed; bundled binaries match the assembler; the loader rejects unsupported files |
| `test_e2e_all_isas.py` | Every example program on every ISA: loading, stepping, results, console, `-e` mode |
| `test_simulator_parts.py` | `SymbolTable`, `Disassembler`, and `run_until()` |

Other areas:

| Area | Files |
|------|-------|
| Simulator API | `test_simulator.py`, `test_python_bindings.py`, `test_multi_isa.py`, `test_loading.py`, `test_symbols.py`, `test_program_correctness.py`, `test_io_syscalls.py`, `test_cross_isa_regression.py`, `test_mips_backend.py`, `test_x86_backend.py`, `test_arm_*.py` |
| Console | `test_console_working.py`, `test_console_commands.py`, `test_console_disasm.py`, `test_debug_info.py`, `test_disasm*.py` |
| Assembler | `test_toolchain.py`, `test_isa_specification.py`, `test_forward_references.py`, `test_assembler_accuracy.py`, `test_*_encoder.py`, `test_differential_*.py` (with `gnu_reference.py`) |
| Fixed bugs | `test_regressions.py` |

## Writing tests

- Prefer the public API (`Simulator`, `assemble`, the console's `onecmd`) over private attributes,
  so tests survive refactoring.
- For behavior every ISA should share, parametrize over `ISA_SPECS` instead of copying a test per
  ISA:

  ```python
  import pytest
  from mapachespim import ISA_SPECS, Simulator

  @pytest.mark.parametrize("spec", ISA_SPECS, ids=lambda spec: spec.name)
  def test_stack_pointer_starts_near_stack_top(spec):
      sim = Simulator(isa=spec.isa)
      ...
  ```

- To give a program input or capture its output, set `sim.stdin` / `sim.stdout` to `io.StringIO`
  objects and use `sim.run_until()`; the real syscalls then run.
- If a change to the assembler changes the bundled example binaries, rebuild them with
  `make -B debug` in `examples/` (`test_elf_output.py` checks they are current).
