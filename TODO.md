# MapacheSPIM vs SPIM: Feature Comparison

## Executive Summary


## Core Functionality Comparison

### ✅ Features We Have

| Feature | MapacheSPIM | SPIM | Notes |
|---------|-------------|------|-------|
| Load ELF files | ✅ `load` | ✅ | We load RISC-V ELF, SPIM loads MIPS assembly |
| Single step | ✅ `step [n]` | ✅ `step [n]` | **BUT: We don't show the instruction!** |
| Run program | ✅ `run [max]` | ✅ `run` | We support max instruction limit |
| Breakpoints | ✅ `break/delete` | ✅ `breakpoint/delete` | We use addresses, SPIM uses labels |
| Continue | ✅ `continue` | ✅ `continue` | Same functionality |
| Register display | ✅ `regs` | ✅ | We show all 32 registers with ABI names |
| PC display | ✅ `pc` | ✅ | Program counter inspection |
| Memory dump | ✅ `mem <addr> [len]` | ✅ | Hex dump format |
| Disassembly | ✅ `disasm <addr> [n]` | ✅ | Using Sail's formal spec |
| Reset | ✅ `reset` | ✅ | Clear state |
| Status | ✅ `status` | ✅ | Show loaded file, breakpoints |
| Interactive console | ✅ | ✅ | cmd.Cmd based |
| Ctrl-C handling | ✅ | ✅ | Interrupt long runs |


STEP 1, 2, and 3 complete!

#### 4. **Source Code Display (if available)**
SPIM can show original assembly source alongside execution.
We could show:
- Line numbers from original .s file
- Current line being executed
- Context (lines before/after)

---

#### 5. **Data Segment Inspection**
SPIM has separate views for:
- `.text` segment (code)
- `.data` segment (initialized data)
- `.bss` segment (uninitialized data)
- Stack

**What we need:**
- Parse ELF section headers
- Commands like `data <addr>` or `stack`
- Smart display of data (strings, arrays, structs)

---

### 🔧 Medium Priority Enhancements

#### 6. **Watchpoints**
Monitor memory/register changes:
```
watch mem[0x80001000]    # Break when this address is written
watch x10                # Break when a0 changes
```

#### 7. **Backtrace / Call Stack**
Show function call history:
```
(mapachespim) bt
#0  fibonacci+24 at 0x80000030
#1  main+16 at 0x80000010
```

#### 8. **Multiple Display Formats**
SPIM shows registers in multiple bases (hex, decimal, binary, octal)
```
(mapachespim) regs decimal    # Show in decimal
(mapachespim) regs binary     # Show in binary
```

#### 9. **Print Command with Expressions**
SPIM: `print $t0 + $t1`
We could support: `print x5 + x6` or `print [x2+8]` (dereference sp+8)

#### 10. **Instruction Statistics**
Count instructions executed by type:
- Branches taken vs not taken
- Memory accesses (load/store)
- ALU operations
- Branch prediction stats

