# MapacheSPIM vs SPIM: Feature Comparison

## Executive Summary

MapacheSPIM aims to provide a SPIM-like debugging experience for RISC-V programs. This document compares our current functionality to SPIM and identifies gaps for student assembly debugging.

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

### ❌ Critical Missing Features (High Priority)

#### 1. **Step Should Show the Instruction** ⭐ MOST IMPORTANT
**Current behavior:**
```
(mapachespim) step
[0x0000000080000000] Executed 1 instruction
```

**SPIM behavior (what students expect):**
```
(spim) step
[0x00400000]  0x34020004  ori $2, $0, 4   ; load 4 into $v0
```

**What's needed:**
- Show the disassembled instruction that was just executed
- Include the instruction bytes (helpful for understanding encoding)
- Format: `[address]  hex_bytes  disassembly  ; optional comment`

**Impact:** This is the #1 feature students use for debugging!

---

#### 2. **Automatic Register Change Highlighting**
SPIM shows which registers changed after each step. Students need to see:
- Which registers were modified by the instruction
- Old value → New value
- Highlight changes in the display

**Example:**
```
(mapachespim) step
[0x80000000]  0x00a00293  addi x5, x0, 0xa
  x5 (  t0) : 0x0000000000000000 → 0x000000000000000a  ★
```

---

#### 3. **Symbol Table / Label Support**
SPIM uses labels for breakpoints: `break main` or `break loop`
We only support addresses: `break 0x80000000`

**What's needed:**
- Parse ELF symbol table to get function names
- Support symbolic breakpoints: `break main`, `break fibonacci`
- Show labels in disassembly: `jal fibonacci` instead of `jal 0x80000050`
- Display function names in step output

**Example:**
```
(mapachespim) break main
Breakpoint set at main (0x80000000)

(mapachespim) step
[main+0]  0x00a00293  addi x5, x0, 0xa
```

---

#### 4. **Source Code Display (if available)**
SPIM can show original assembly source alongside execution.
We could show:
- Line numbers from original .s file
- Current line being executed
- Context (lines before/after)

**Note:** Requires DWARF debug info or separate source file

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

---

### 📊 Low Priority / Nice to Have

#### 11. **GUI Version**
QtSpim provides multiple panes:
- Text segment (code with highlighting)
- Data segment (memory)
- Registers (always visible)
- Console (commands/output)

We could create a TUI (Text UI) with panels using `curses` or `rich`

#### 12. **Instruction History**
Keep log of last N instructions executed:
```
(mapachespim) history 10
Show last 10 instructions executed
```

#### 13. **Performance Counters**
Simulated cycle counts, cache stats (if we add cache model)

#### 14. **Scripting Support**
Run commands from a file:
```
(mapachespim) source debug_script.txt
```

#### 15. **Conditional Breakpoints**
```
break 0x80000010 if x10 == 42
```

#### 16. **Reverse Execution**
Step backwards (requires recording state)

---

## Detailed Feature Requirements

### Feature #1: Enhanced Step Output (HIGH PRIORITY)

**Goal:** Show instruction that was executed when stepping

**Implementation:**
```python
def do_step(self, arg):
    # ... existing setup ...

    for i in range(n_steps):
        pc = self.sim.get_pc()

        # NEW: Disassemble BEFORE executing
        instr_disasm = self.sim.disasm(pc)
        instr_bytes = self.sim.read_mem(pc, 4)
        instr_hex = '0x' + ''.join(f'{b:02x}' for b in instr_bytes)

        # Execute
        result = self.sim.step()

        # NEW: Show what we just executed
        if n_steps == 1:
            print(f'[{pc:#010x}]  {instr_hex}  {instr_disasm}')

        # ... handle errors ...
```

**Output format:**
```
(mapachespim) step
[0x80000000]  0x00a00293  addi x5, x0, 0xa

(mapachespim) step
[0x80000004]  0x01400313  addi x6, x0, 0x14
```

**For multiple steps:**
```
(mapachespim) step 5
[0x80000000]  0x00a00293  addi x5, x0, 0xa
[0x80000004]  0x01400313  addi x6, x0, 0x14
[0x80000008]  0x006283b3  add x7, x5, x6
[0x8000000c]  0x40538433  sub x8, x7, x5
[0x80000010]  0x00229493  slli x9, x5, 0x2
```

---

### Feature #2: Register Change Tracking

**Goal:** Show which registers changed and highlight them

**Implementation approach:**
1. Before step: snapshot all registers
2. Execute step
3. After step: compare registers, show changes

**Data structure:**
```python
class MapacheSPIMConsole:
    def __init__(self):
        # ...
        self.prev_regs = None  # Track previous register state
        self.show_reg_changes = True  # Option to enable/disable
```

**Enhanced step:**
```python
def do_step(self, arg):
    # Snapshot registers before
    if self.show_reg_changes:
        prev_regs = self.sim.get_all_regs()

    # ... execute step ...

    # Show changes
    if self.show_reg_changes and n_steps == 1:
        curr_regs = self.sim.get_all_regs()
        changed = []
        for i in range(32):
            if prev_regs[i] != curr_regs[i]:
                abi = self.RISCV_ABI_NAMES[i]
                changed.append(f'  x{i:<2} ({abi:>4}) : {prev_regs[i]:#018x} → {curr_regs[i]:#018x}  ★')

        if changed:
            print('Register changes:')
            for line in changed:
                print(line)
```

**Output:**
```
(mapachespim) step
[0x80000000]  0x00a00293  addi x5, x0, 0xa
Register changes:
  x5 (  t0) : 0x0000000000000000 → 0x000000000000000a  ★
```

---

### Feature #3: Symbol Table Support

**Goal:** Use function/label names instead of just addresses

**Implementation:**
1. Parse ELF symbol table when loading
2. Build address → name and name → address mappings
3. Support symbolic breakpoints
4. Show labels in disassembly

**ELF parsing:**
```python
from elftools.elf.elffile import ELFFile

class SailSimulator:
    def __init__(self):
        # ...
        self.symbols = {}  # address → name
        self.symbol_addrs = {}  # name → address

    def load_elf(self, path):
        # ... existing load ...

        # Parse symbol table
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC':
                        addr = sym['st_value']
                        name = sym.name
                        self.symbols[addr] = name
                        self.symbol_addrs[name] = addr

    def addr_to_symbol(self, addr):
        """Convert address to symbol+offset"""
        # Find closest symbol before this address
        best_addr = None
        best_name = None
        for sym_addr, name in self.symbols.items():
            if sym_addr <= addr:
                if best_addr is None or sym_addr > best_addr:
                    best_addr = sym_addr
                    best_name = name

        if best_name:
            offset = addr - best_addr
            if offset == 0:
                return best_name
            else:
                return f'{best_name}+{offset}'
        return None
```

**Console usage:**
```python
def do_break(self, arg):
    # Try to parse as symbol first
    if arg in self.sim.symbol_addrs:
        addr = self.sim.symbol_addrs[arg]
        print(f'Breakpoint set at {arg} ({addr:#010x})')
    else:
        # Parse as address
        addr = int(arg, 0)

    self.breakpoints.add(addr)
```

**Example:**
```
(mapachespim) info symbols
Functions:
  main                 0x80000000
  fibonacci            0x80000050
  __start              0x80000000

(mapachespim) break fibonacci
Breakpoint set at fibonacci (0x80000050)

(mapachespim) run
Breakpoint hit at fibonacci (0x80000050)

(mapachespim) step
[fibonacci+0]  0x00a00293  addi x5, x0, 0xa
```

---

## Recommended Implementation Order

### Phase 1: Enhanced Step Display (2-3 hours)
1. ✅ Show instruction in step output (address + hex + disassembly)
2. ✅ Format multi-step output nicely
3. ✅ Add option to enable/disable verbose step

### Phase 2: Register Change Tracking (2-3 hours)
4. ✅ Track previous register state
5. ✅ Show register changes after each step
6. ✅ Add configuration option: `set show-changes on/off`

### Phase 3: Symbol Table Support (4-5 hours)
7. ✅ Parse ELF symbol table
8. ✅ Support symbolic breakpoints (`break main`)
9. ✅ Show function names in step output
10. ✅ Add `info symbols` command
11. ✅ Add `info functions` command

### Phase 4: Enhanced Display (3-4 hours)
12. ✅ Add `print` command for expressions
13. ✅ Multiple register display formats
14. ✅ Better memory display (decode strings, etc.)

### Phase 5: Advanced Debugging (5-6 hours)
15. ⏳ Watchpoints
16. ⏳ Call stack / backtrace
17. ⏳ Instruction history
18. ⏳ Conditional breakpoints

---

## Student Use Cases

### Use Case 1: Debugging a Simple Loop
**Current experience:**
```
(mapachespim) load fibonacci
(mapachespim) break 0x80000020
(mapachespim) run
Breakpoint hit at 0x80000020
(mapachespim) step
[0x0000000080000020] Executed 1 instruction
(mapachespim) regs
... 32 lines of registers ...
```

**Desired experience:**
```
(mapachespim) load fibonacci
(mapachespim) break loop
Breakpoint set at loop (0x80000020)
(mapachespim) run
Breakpoint hit at loop (0x80000020)

(mapachespim) step
[loop+0]  0x00a58593  addi x11, x11, 0xa
Register changes:
  x11 (  a1) : 0x0000000000000000 → 0x000000000000000a  ★

(mapachespim) step
[loop+4]  0xfff50513  addi x10, x10, -1
Register changes:
  x10 (  a0) : 0x0000000000000005 → 0x0000000000000004  ★
```

Much clearer what's happening!

---

### Use Case 2: Understanding Function Calls
**Current:**
```
(mapachespim) step
[0x0000000080000010] Executed 1 instruction
(mapachespim) pc
pc = 0x0000000080000050
```

**Desired:**
```
(mapachespim) step
[main+16]  0x040000ef  jal ra, fibonacci
Register changes:
  x1  (  ra) : 0x0000000000000000 → 0x0000000080000014  ★
Jumped to fibonacci (0x80000050)

(mapachespim) bt
#0  fibonacci at 0x80000050
#1  main+16 at 0x80000014
```

---

## Conclusion

**Priority 1 (Must Have for Students):**
- ⭐ Enhanced step output showing instruction
- ⭐ Register change tracking
- ⭐ Symbol table support

**Priority 2 (Very Useful):**
- Print command with expressions
- Watchpoints
- Call stack

**Priority 3 (Nice to Have):**
- GUI/TUI interface
- Instruction statistics
- Reverse execution

The most critical gap right now is that **step doesn't show what instruction was executed**. This is the primary way students understand what their code is doing!
