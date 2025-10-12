# ARM Sail Source Traceability

This document maps the ARM Sail **source code** (.sail files) to the **generated C code** (aarch64.c) to ensure we understand the authoritative definitions.

## Sail Compilation Process

**Build Command (from arm-v8.5-a/Makefile:22-24):**
```bash
sail -c -O -Oconstant_fold $(AARCH_FLAGS) $(OPTS) $(AARCH_SRCS) > aarch64.c
```

**Compilation Order:**
```
1. model/prelude.sail           # Sail standard library
2. model/no_devices.sail        # Device stubs
3. model/aarch_types.sail       # Type definitions
4. model/aarch_mem.sail         # Memory and register declarations
5. model/aarch64.sail           # AArch64 instruction implementations
6. model/aarch64_float.sail     # Floating point
7. model/aarch64_vector.sail    # SIMD/Vector
8. model/aarch32.sail           # AArch32 (not used for AArch64)
9. model/aarch_decode.sail      # Instruction decoder
10. model/elfmain.sail          # Main execution loop
```

**Sail Naming Convention:**
- Sail function `foo` → C function `zfoo`
- Sail register `_R` → C global `z_R`
- Sail type `exception` → C type `zexception`
- Underscores preserved: `__WriteMemory` → `z__WriteMemory`

## Current Build Status

**Problem:** Sail version mismatch
```
Current Sail: 0.19.1 (via opam)
ARM Sail model: Built with earlier Sail version
Error: pow2 overload conflict between arith.sail and prelude.sail
```

**Solution:** Use pre-generated snapshot in `snapshots/c/aarch64.c`
- File size: 36 MB
- Date: Oct 11, 2024 (from ARM Sail repository)
- Status: Pre-tested and working

## Complete API Mapping

### 1. Register Declarations

**Sail Source (model/aarch_mem.sail:118,128):**
```sail
register _R : vector(31, dec, bits(64))    // Line 118
register _PC : bits(64)                     // Line 128
```

**Generated C (snapshots/c/aarch64.c:3195,3210):**
```c
zvectorz8deczCz0fbitsz864zCz0decz9z9 z_R;   // Line 3195
uint64_t z_PC;                               // Line 3210
```

**Traceability:** ✓ Sail register declarations directly map to C globals

### 2. Register Accessors

**Sail Source (model/aarch64.sail:4485-4491):**
```sail
val aget_X : forall 'width 'n,
  ('n >= 0 & 'n <= 31 & 'width in {8, 16, 32, 64}).
  (implicit('width), int('n)) -> bits('width) effect {rreg}

function aget_X (width, n) = if n != 31 then slice(_R[n], 0, width) else Zeros(width)

overload X = {aget_X}
```

**Generated C (snapshots/c/aarch64.c:128268,128285):**
```c
sbits zaget_X(int64_t, int64_t);             // Line 128268 - Declaration
sbits zaget_X(int64_t zwidth, int64_t zn)    // Line 128285 - Implementation
{
  // ... implementation checks n != 31, returns slice of z_R[n] or zeros
}
```

**Sail Source (model/aarch64.sail:4448-4458):**
```sail
val aset_X : forall ('width : Int) ('n : Int), ('n >= 0 & 'n <= 31).
  (int('n), bits('width)) -> unit effect {escape, wreg}

function aset_X (n, value_name) = {
    assert('width == 32 | 'width == 64);
    if n != 31 then _R[n] = ZeroExtend(value_name, 64)
    else ();
}

overload X = {aset_X}
```

**Generated C (snapshots/c/aarch64.c:127983,128008):**
```c
unit zaset_X(int64_t, lbits);                // Line 127983 - Declaration
unit zaset_X(int64_t zn, lbits zvalue_name)  // Line 128008 - Implementation
{
  // ... implementation checks width, sets z_R[n] if n != 31
}
```

**Traceability:** ✓ Sail functions `aget_X`/`aset_X` → C functions `zaget_X`/`zaset_X`

### 3. Memory Access

**Sail Source (model/aarch_mem.sail:2586-2602):**
```sail
val __WriteMemory : forall ('N : Int).
  (int('N), bits(56), bits(8 * 'N)) -> unit effect {rreg, wmem}

function __WriteMemory (N, address, val_name) = {
    __WriteRAM(56, N, __defaultRAM, address, val_name);
    __TraceMemoryWrite(N, address, val_name);
    return()
}

val __ReadMemory : forall ('N : Int).
  (int('N), bits(56)) -> bits(8 * 'N) effect {rmem, rreg}

function __ReadMemory (N, address) = {
    let r = __ReadRAM(56, N, __defaultRAM, address);
    __TraceMemoryRead(N, address, r);
    r
}
```

**Generated C (snapshots/c/aarch64.c:14541,14607):**
```c
unit z__WriteMemory(sail_int, uint64_t, lbits);      // Line 14541
void z__ReadMemory(lbits *rop, sail_int, uint64_t);  // Line 14607
```

**Traceability:** ✓ Sail `__WriteMemory`/`__ReadMemory` → C `z__WriteMemory`/`z__ReadMemory`

### 4. Execution

**Sail Source (model/elfmain.sail:61-193):**
```sail
val Step_CPU : unit -> unit effect {configuration, escape, undef, wreg, rreg, rmem, wmem}

function Step_CPU() = {
  SEE = -1;
  // Check pending interrupts
  // Fetch instruction: __currentInstr = __fetchA64()
  // Decode and execute: decode64(__currentInstr)
  // Increment PC if not changed
  if ~(__PC_changed) then _PC = _PC + __currentInstrLength else ();
}
```

**Generated C (snapshots/c/aarch64.c:1630356,1630389):**
```c
unit zStep_CPU(unit);                        // Line 1630356
unit zStep_CPU(unit zgsz3195311)             // Line 1630389
{
  // ... full implementation
}
```

**Sail Source (model/elfmain.sail:252-340):**
```sail
val Step_System : unit -> unit effect {configuration, escape, undef, wreg, rreg, rmem, wmem}

function Step_System () = {
    Step_Timers();
    if ~(__Sleeping()) then {
      Step_CPU();
    };
    __EndCycle();
}
```

**Generated C (snapshots/c/aarch64.c:1631918,1631969):**
```c
unit zStep_System(unit);                     // Line 1631918
unit zStep_System(unit zgsz3195548)          // Line 1631969
{
  // ... full implementation
}
```

**Traceability:** ✓ Sail `Step_CPU`/`Step_System` → C `zStep_CPU`/`zStep_System`

### 5. Initialization

**Sail Source (model/elfmain.sail:346-350):**
```sail
val init : unit -> unit effect {escape, undef, rreg, wreg}

function init() = {
  TakeReset(COLD_RESET);
}
```

**Generated C (snapshots/c/aarch64.c:1632491,1632493):**
```c
unit zinit(unit);                            // Line 1632491
unit zinit(unit zgsz3195636)                 // Line 1632493
{
  // ... calls zTakeReset(true)
}
```

**Sail Source (Sail runtime, not in model/):**
```c
void model_init(void);      // Initialize Sail runtime
void model_fini(void);      // Cleanup Sail runtime
```

**Generated C (snapshots/c/aarch64.c:1637283,1638951):**
```c
void model_init(void)       // Line 1637283
void model_fini(void)       // Line 1638951
```

**Traceability:** ✓ Sail `init` → C `zinit`, runtime functions unchanged

## Verification

To verify the snapshot matches the Sail source:

```bash
# Compare function signatures
grep "^val aget_X" model/aarch64.sail
grep "sbits zaget_X" snapshots/c/aarch64.c

# Compare register declarations
grep "^register _R\|^register _PC" model/aarch_mem.sail
grep "// register _R\|// register _PC" snapshots/c/aarch64.c

# Check memory functions
grep "^function __ReadMemory\|^function __WriteMemory" model/aarch_mem.sail
grep "z__ReadMemory\|z__WriteMemory" snapshots/c/aarch64.c | head -5
```

## Conclusion

**The snapshot is trustworthy:**
1. ✓ Generated from official ARM Sail model source
2. ✓ All functions traceable to specific .sail files and line numbers
3. ✓ Naming convention is consistent (prefix `z`)
4. ✓ Building from source currently blocked by Sail version mismatch
5. ✓ Snapshot is the recommended approach (provided by ARM in repo)

**For MapacheSPIM integration:**
- Reference: **Sail source files** (.sail) for understanding semantics
- Build against: **Pre-generated snapshot** (snapshots/c/aarch64.c)
- Document: Both Sail source location AND generated C line numbers

**When to rebuild:**
- Only if we need to modify the ARM Sail model itself
- Requires fixing Sail version compatibility first
- For now, snapshot is the correct choice
