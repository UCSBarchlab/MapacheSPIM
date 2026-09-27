# Architecture and Adding an ISA

MapacheSPIM has two halves that share one description of each instruction set:

- the **simulator**, which loads ELF executables and runs them on the
  [Unicorn Engine](https://www.unicorn-engine.org/), disassembling with
  [Capstone](https://www.capstone-engine.org/), and
- the **toolchain**, a pure-Python assembler that produces the same bytes as GNU `as` and writes
  ELF files with DWARF line information.

Nothing outside the files listed under "Per-ISA code" below branches on which ISA is in use.
Everything else asks the ISA registry.

## Module map

```
mapachespim/
  isa.py            ISASpec for each ISA: names, memory layout, registers, syscall ABI,
                    syscall instruction, instruction sizes, ELF machine, GNU as dialect
  memory_map.py     MemoryLayout (where .text/.data/stack go) for each ISA
  engines.py        Unicorn and Capstone constants for each ISA            (per-ISA code)

  unicorn_backend.py  UnicornSimulator: machine setup, step/run_until, registers, memory
  syscalls.py         SPIM syscalls (table-driven), ProgramIO for program stdin/stdout
  disassembler.py     Capstone wrapper
  symbols.py          SymbolTable: name -> address and address -> nearest symbol
  elf_loader.py       Reads an ELF's ISA, segments, sections, and symbols
  debug_info.py       DWARF line table -> source lines (for the console's `list`)
  examples.py         The bundled example programs

  console.py        The interactive console and the `mapachespim` command

  toolchain/
    __init__.py     assemble(), assemble_file()
    assembler.py    ISA-independent assembler: layout passes, labels, fixups, ELF output
    targets.py      A Target per ISA that drives its encoder              (per-ISA code)
    directives.py   GNU as directive parser and source splitting
    riscv.py, mips.py, arm64.py, x86.py   Instruction encoders            (per-ISA code)
    expr.py         Expression evaluation shared by the encoders
    elf_builder.py  ELF32/ELF64 writer
    dwarf.py        DWARF .debug_line writer
    cli.py          The `mapachespim-as` command
```

## How a program runs

1. `elf_loader.load_elf_file()` reads the ELF header and asks `isa.spec_for_elf()` which
   `ISASpec` matches its machine and word size.
2. `UnicornSimulator.load_elf()` creates a Unicorn machine from `engines.engine_for(spec)`, maps the
   spec's memory layout, copies in the segments, and points the stack pointer at the layout's stack.
3. `step()` checks whether the next instruction matches `spec.syscall_instruction`. If so it skips
   it and returns `StepResult.SYSCALL`; otherwise Unicorn executes one instruction.
4. `check_termination()` performs a pending syscall with `syscalls.SyscallHandler`, which reads the
   syscall number and argument from the registers named by `spec.syscall_abi`.
5. `run_until()` repeats steps until a `StopReason` (exit, error, breakpoint, ...) or a step limit.
   The console's `run`, `-e` mode, and `Simulator.run()` all use it.

## How a program is assembled

1. `DirectiveParser` splits the source into statements and sections, following GNU `as` rules
   for the ISA (`spec.asm`: comment characters, `.word` size, `.align` meaning, MIPS data
   auto-alignment).
2. `Assembler` asks `targets.target_for(isa, parser)` for a `Target`. The target may rewrite the
   program first (ARM64 literal pools), gives the encoder per-line options (MIPS `.set reorder`,
   x86 syntax), supplies the nops used to pad code, and can grow instructions during layout (x86
   short/long jumps).
3. The assembler lays out `.text` until label addresses are stable, encodes each instruction with
   the target, fills in data that refers to labels, and writes an ELF file with `ELFBuilder`
   (using `spec.elf_machine`, `spec.elf_flags`, word size, and byte order).

## Adding an ISA

1. **`isa.py`** — add a member to `ISA` and an `ISASpec`, and list it in `ISA_SPECS`. Add a
   `MemoryLayout` for it in `memory_map.py`. If the ISA has instructions that deliberately trap
   (like MIPS `break` for division by zero), give it a `describe_trap` function.
2. **`engines.py`** — add an `EngineBinding` with the Unicorn architecture, mode, PC and SP
   registers, one Unicorn register constant per register in `spec.registers.names` (look them up
   by name: Unicorn's constants are not always consecutive), and the Capstone architecture and mode.
3. **Assembler** — write `toolchain/<isa>.py` with `encode(text, address, labels, **options)` and
   `instruction_size(text, labels, address, **options)`, then add a `Target` subclass in
   `toolchain/targets.py` and list it in `TARGETS`. Override only what differs from the defaults
   (for example `code_padding` to pad code with that ISA's nop).
4. **Examples** — add `examples/<spec.examples_dir>/` with at least `hello_asm`, `fibonacci`,
   `array_stats`, `matrix_multiply`, and `guess_game`, a `linker.ld`, and a `Makefile` target, then
   build the binaries with `make -B debug` in `examples/`.
5. **Tests** — add the ISA's entries to `SYSCALL_PROGRAMS` and `SET_REGISTER` in
   `tests/test_isa_conformance.py`. If GNU binutils exist for it, add a
   `tests/test_differential_<isa>.py` like the existing ones.

The registry tests (`tests/test_isa_registry.py`) fail until steps 1–4 are consistent, and the
conformance tests then run the new ISA through the whole pipeline: assembling, loading, every
syscall, and every register. Most other cross-ISA tests (`test_e2e_all_isas.py`,
`test_elf_output.py`, `test_syscalls.py`) are parametrized over the registry or the examples and
cover the new ISA automatically.

## Testing

See [tests/README.md](../../tests/README.md).
