# MapacheSPIM TODO & Roadmap

## Current Status (Oct 2025)

✅ **Project Fully Functional**
- All 123 tests passing (31 API + 38 console + 24 symbol + 30 disasm)
- Documentation streamlined and up-to-date
- Enhanced step display with symbols and register tracking
- Symbol table support with symbolic breakpoints
- Disassembly using Sail formal specification
- Interactive console with SPIM-like commands
- **ELF section inspection** - View sections, use section names in mem command
- **ASCII sidebar in memory dumps** - Educational hex dump format
- **Source code display** - GDB-style `list` command with DWARF debug info

**Recent Completion:** Source Code Display feature (list command with DWARF parsing, 7 new tests)

---

## Core Functionality Comparison vs SPIM

### ✅ Features We Have

| Feature | MapacheSPIM | SPIM | Notes |
|---------|-------------|------|-------|
| Load ELF files | ✅ `load` | ✅ | We load RISC-V ELF, SPIM loads MIPS assembly |
| Single step with display | ✅ `step [n]` | ✅ `step [n]` | **We show: [addr] <symbol> bytes disasm** |
| Register change tracking | ✅ | ❌ | Auto-highlight changes after step |
| Run program | ✅ `run [max]` | ✅ `run` | We support max instruction limit |
| Breakpoints (address) | ✅ `break/delete` | ✅ `breakpoint/delete` | Both address and symbolic |
| Symbolic breakpoints | ✅ `break main` | ✅ | Use function names |
| Continue | ✅ `continue` | ✅ `continue` | Same functionality |
| Register display | ✅ `regs` | ✅ | We show all 32 registers with ABI names |
| PC display | ✅ `pc` | ✅ | Program counter inspection |
| Memory dump | ✅ `mem <addr\|section> [len]` | ✅ | Hex dump with ASCII sidebar |
| Section inspection | ✅ `info sections` | ❌ | List ELF sections (.text, .data, etc.) |
| Disassembly | ✅ `disasm <addr> [n]` | ✅ | Using Sail's formal spec |
| Symbol table | ✅ `info symbols` | ✅ | List all functions/labels |
| Reset | ✅ `reset` | ✅ | Clear state |
| Status | ✅ `status` | ✅ | Show loaded file, breakpoints |
| Interactive console | ✅ | ✅ | cmd.Cmd based |
| Ctrl-C handling | ✅ | ✅ | Interrupt long runs |

**Current step display output:**
```
[0x80000000] 0x9302a000  addi x5, x0, 0xa  <_start>
Register changes:
  x5  (  t0) : 0x0000000000000000 → 0x000000000000000a  ★
```

---

## Next Steps - Prioritized

### 🎯 High Priority (Next Sprint)

#### 1. ✅ **Data Segment Inspection** - COMPLETED
Parse ELF sections and provide smart memory views.

**Completed Implementation:**
- ✅ Parse ELF section headers using pyelftools
- ✅ Added `info sections` - List all ELF sections (.text, .data, .bss, etc.)
- ✅ Enhanced `mem <section>` - Use section names (e.g., `mem .data`)
- ✅ ASCII sidebar for hex dumps - See printable characters alongside hex
- ✅ 7 new tests (31 console tests total)
- ✅ Documentation updated (console-guide.md)

**Result:** Students can now easily inspect program sections and see string data in memory dumps.

---

#### 2. ✅ **Source Code Display** - COMPLETED
Show original assembly source alongside execution.

**Completed Implementation:**
- ✅ Parse DWARF line programs using pyelftools
- ✅ Build address-to-source mapping cache
- ✅ Added `list` command (GDB-style)
  - `list` - Show source around current PC
  - `list <function>` - Show source around function entry
  - `list <line>` - Show source around specific line number
- ✅ Source file caching with smart path search
- ✅ Graceful fallback when no debug info
- ✅ PC marker shows current execution line
- ✅ 7 new tests (38 console tests total)
- ✅ Documentation updated

**Result:** Students can now view source code alongside execution, just like GDB!

---

### 🔧 Medium Priority

#### 3. **Watchpoints**
Monitor memory/register changes:
```
watch mem[0x80001000]    # Break when this address is written
watch x10                # Break when a0 changes
```

**Implementation notes:**
- Track memory writes in step loop
- Track register writes
- Add watch list management
- Check conditions before each instruction

**Estimated effort:** 3-4 days

---

#### 4. **Backtrace / Call Stack**
Show function call history:
```
(mapachespim) bt
#0  fibonacci+24 at 0x80000030
#1  main+16 at 0x80000010
```

**Implementation notes:**
- Track ra register to build call stack
- Parse stack frames (requires ABI knowledge)
- Show function names via symbol table

**Estimated effort:** 2-3 days

---

#### 5. **Multiple Display Formats**
SPIM shows registers in multiple bases (hex, decimal, binary, octal)
```
(mapachespim) regs decimal    # Show in decimal
(mapachespim) regs binary     # Show in binary
```

**Estimated effort:** 1 day (easy)

---

#### 6. **Print Command with Expressions**
SPIM: `print $t0 + $t1`
We could support: `print x5 + x6` or `print [x2+8]` (dereference sp+8)

**Implementation notes:**
- Simple expression parser
- Support: `x5 + x6`, `[x2+8]`, `*addr`, etc.
- Evaluate in current context

**Estimated effort:** 2 days

---

#### 7. **Instruction Statistics**
Count instructions executed by type:
- Branches taken vs not taken
- Memory accesses (load/store)
- ALU operations
- Branch prediction stats

**Implementation notes:**
- Add instruction type categorization
- Maintain counters during execution
- Add `stats` command to display

**Estimated effort:** 2-3 days

---

## Future / Lower Priority

### Multi-ISA Support
- ARM backend (sail-arm)
- CHERI backend (sail-cheri-riscv)
- Auto-detect ISA from ELF

### TUI Interface
- Split-pane interface (code, registers, stack, output)
- Uses: curses/urwid/textual
- Inspired by GDB TUI mode

### Performance Optimizations
- JIT compilation of hot paths
- Caching disassembly results
- Lazy register reads

### Educational Features
- Built-in tutorial mode
- Suggested breakpoints for common patterns
- Explain command (why did this instruction do X?)

---

## Immediate Action Items

**Next session should tackle: Data Segment Inspection (#1)**

Steps:
1. Read ELF sections using ELFIO (already in dependencies)
2. Add `sections` command to list all sections
3. Add `data` command with smart string/array detection
4. Add `stack` command to show SP-relative memory
5. Write tests for new commands
6. Update console-guide.md

**Files to modify:**
- `mapachespim/console.py` - Add new commands
- `mapachespim/sail_backend.py` - Add ELF section API if needed
- `tests/test_console_working.py` - Add tests
- `docs/user/console-guide.md` - Document new commands

