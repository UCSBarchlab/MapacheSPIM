# Changelog

## Unreleased

### Console
- `regs` shows MIPS `hi` and `lo`, and the condition flags on ARM64 (`nzcv: N Z C V`) and
  x86-64 (`rflags: CF ZF SF OF`), with ★ when they change. New `Simulator.get_special_regs()`
  and `get_flags()`.
- `regs` and `pc` ask you to load a program first instead of showing an unset machine.

### Examples and docs
- The RISC-V `fibonacci` and `matrix_multiply` examples exit with the exit syscall, like the
  other ISAs, instead of the HTIF `tohost` mechanism; `fibonacci` now prints its result.
- Removed the out-of-date `examples/arm/README.md`. The Console Guide has a register table for
  all four ISAs in place of the RISC-V-only one.

### Code structure
- Each ISA is described once, in `mapachespim/isa.py`; the simulator, disassembler, ELF loader and
  writer, assembler, console, and command-line tools all read their ISA-specific facts from it.
  Emulator constants are in `engines.py` and each ISA's assembler hooks in `toolchain/targets.py`.
  See `docs/dev/architecture.md`, which also explains how to add an ISA.
- New `Simulator.run_until()` with `StopReason` and `RunResult`; the console uses it for `run`
  and `-e`. New `Simulator.spec`, `symbols`, `get_sections()`, and `find_section()`.
- Removed: `mapachespim.toolchain.memory_map` (use `mapachespim.memory_map`), the `SailSimulator`
  alias, the per-ISA `*Config` classes, `STACK_TOP`/`STACK_SIZE`/`STACK_ADDR`, and
  `mapachespim.elf_loader.Architecture`.
- Tests that every registered ISA must pass: syscalls, register mapping, ELF output, and more.

### Fixed
- ARM64 registers x29 (fp) and x30 (lr) showed and changed the wrong (vector) registers.
- ARM64 programs crashed on `read_int` and `read_char`: x0 was treated as a read-only register.
- 32-bit ARM and RISC-V ELF files were run as if they were 64-bit programs; they are now refused.
- ELF symbol tables written by the assembler listed local symbols after global ones and put every
  symbol in `.text`. The example binaries are rebuilt.

### Installation
- All four ISAs are assembled by new built-in pure-Python assemblers, so every ISA assembles on
  every platform. The Keystone dependency is gone: it had no prebuilt packages for ARM machines
  such as Apple Silicon Macs, and its PyPI release could not assemble RISC-V at all.
- The example programs are included in the package, so `load riscv/fibonacci` works after
  `pip install`. `mapachespim --copy-examples DIR` copies them somewhere editable.
- Python 3.9 or newer is required.

### Console
- `load` assembles `.s` files directly (with debug info) and loads bundled examples by name.
- New `reload` command re-assembles after editing, keeping breakpoints on their labels.
- New `examples` command lists the bundled programs.
- `step` now performs syscalls (it used to skip them) and stops at program exit.
- `reset` reloads the program, so it can be run again.
- Errors explain what went wrong and where, e.g.
  `Read from unmapped address 0x0 (at PC=0x80000004)` with the source line.
- `disasm` walks x86-64 instructions by their real length and marks the PC.
- `mem`, `disasm`, and `delete` accept labels; `regs decimal` is signed; the first `regs` after
  loading marks registers changed since the start; `set show-changes off` works.
- `mapachespim --version`; `-e` returns the program's exit code (124 on hitting `--max-steps`) and
  accepts `.s` files and example names.

### Simulator
- `read_char` returned the second line of input; `print_int` printed negative MIPS values as
  large unsigned numbers; unknown syscall numbers are now reported as errors; new SPIM `exit2` (17).
- Address 0 is no longer mapped on ARM64, so null-pointer accesses fault.
- The RISC-V sign-extended address alias now shares memory with the real address.
- Loading a program starts from a fresh machine state and may switch ISA.

### Assembler
- The built-in assemblers produce byte-for-byte the same code as GNU `as` for all four ISAs,
  verified by randomized differential tests against GNU binutils (run in CI). This changed some
  pseudo-instruction expansions to GNU's: RISC-V `call`/`tail` are always `auipc`+`jalr`, `li` uses
  GNU's algorithm; MIPS `la` is `lui`+`addiu`, and compare-branches, `abs`, `mul`/`div`/`rem` with
  constants follow GNU. Out-of-range RISC-V branches are relaxed like GNU does.
- MIPS `div`/`rem`/`divu`/`remu` with three operands now trap on division by zero and overflow
  (as SPIM and GNU do), reported as "Division by zero"; `.set noreorder` is supported.
- Fixed: `.align n` meant n bytes instead of 2^n on RISC-V/MIPS/ARM; MIPS data was little-endian
  when the ISA came from `--isa`/`load prog.s mips32`; labels in `.word` etc. became 0; `\xNN` in
  strings produced two bytes; custom sections were not written to the ELF; invalid values in data
  directives were silently ignored; MIPS `.half`/`.word` are now auto-aligned like GNU `as`; `break`
  codes were encoded in the wrong field.
- Expressions follow GNU `as` rules (operators, precedence, octal `010`, `'c'` literals); `.`, and
  `name = expression` (e.g. `len = . - msg`) are supported.
- RISC-V `.equ` constants can be used as instruction operands; `add a0, a1, 5` is accepted as `addi`.
- Debug info for big-endian targets (MIPS) was written in the wrong byte order, so source-level
  debugging never worked for MIPS.
- `.isa riscv64  # comment` is recognized.
- ARM64: `ldr x0, =value` uses a literal pool (`.ltorg`/`.pool`) like GNU `as`; logical immediates,
  `mov` aliases, and `//` comments follow GNU. The ARM examples were updated to GNU syntax.
- x86-64: AT&T and Intel syntax (auto-detected, or `.att_syntax`/`.intel_syntax`), GNU's choice of
  encodings, and GNU's jump relaxation (short jumps grow to 32-bit only when needed). `.word` is 2
  bytes on x86, as in GNU `as`.
- Alignment in code is padded with nops the way GNU `as` does on each ISA; the `.p2align`/`.balign`
  maximum-skip argument works; `.fill` is supported; `;` separates statements; numeric local labels
  (`1:` with `1b`/`1f`) work.
- ISA aliases (`mips`, `x64`, `aarch64`) were treated as unknown ISAs by the directive parser, so
  e.g. `--isa mips` produced little-endian data.
