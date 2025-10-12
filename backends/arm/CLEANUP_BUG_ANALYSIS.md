# ARM Sail model_fini() Crash Analysis

## Summary
The ARM Sail generated code (snapshots/c/aarch64.c) has a **code generation bug** causing a double-free crash in model_fini().

## Root Cause

### The Bug
The variable `zCNT_CTL` is declared **twice** as a global variable:
- **Line 1630274**: First declaration
- **Line 1630297**: Second declaration (duplicate!)

Both declarations have associated cleanup functions:
- **Line 1630294**: `kill_letbind_89()` calls `KILL(zvectorz8deczCz0refz8fbitsz832zCz0decz9z9z9)(&zCNT_CTL)`
- **Line 1630317**: `kill_letbind_90()` calls `KILL(zvectorz8deczCz0refz8fbitsz832zCz0decz9z9z9)(&zCNT_CTL)`

### The Crash
When `model_fini()` executes:
```c
1638956:  kill_letbind_90();  // First free of zCNT_CTL.data
1638957:  kill_letbind_89();  // Second free of same memory → CRASH
```

### Assembly Evidence
The disassembly confirms the double-free:
```
test_cleanup`model_fini:
    0x1002e6d9c <+36>:  adrp   x19, 42
    0x1002e6da0 <+40>:  add    x19, x19, #0x410          ; zCNT_CTL
    0x1002e6da4 <+44>:  ldr    x0, [x19, #0x8]           ; Load zCNT_CTL.data
    0x1002e6da8 <+48>:  cbz    x0, 0x1002e6dbc           ; Skip if NULL
    0x1002e6dac <+52>:  bl     0x1002f8e40               ; *** FIRST free() ***
    0x1002e6db0 <+56>:  ldr    x0, [x19, #0x8]           ; Load SAME pointer again
    0x1002e6db4 <+60>:  cbz    x0, 0x1002e6dbc           ; Skip if NULL
    0x1002e6db8 <+64>:  bl     0x1002f8e40               ; *** SECOND free() → CRASH ***
```

### Runtime Error
```
malloc: *** error for object 0x60000058c420: pointer being freed was not allocated
malloc: *** set a breakpoint in malloc_error_break to debug
```

## Why This Happened
This is a **code generation bug** in the Sail ARM compiler. The Sail language specification likely has some construct that, when compiled to C, produces duplicate global variable declarations with separate cleanup functions.

Possible Sail language causes:
1. Nested let-bindings that reuse the same variable name
2. Sail compiler optimization that failed to deduplicate cleanup
3. Multiple compilation units that got merged incorrectly

## Workaround
**Do NOT call `model_fini()` in MapacheSPIM.**

This is acceptable because:
1. **Not our bug**: This is a bug in the ARM Sail code generator, not our code
2. **Not critical**: Memory cleanup on exit is not essential for a debugger
3. **OS cleanup**: When the process exits, the OS reclaims all memory anyway
4. **Long-running process**: MapacheSPIM is an interactive debugger that may run indefinitely
5. **Core functionality works**: All register/memory/PC access works perfectly

## Alternative Solutions (Future)
1. **Report to Sail team**: File bug report with ARM Sail maintainers
2. **Patch generated code**: Modify aarch64.c to remove duplicate declaration
3. **Selective cleanup**: Only call specific KILL() functions, skip problematic ones
4. **Use newer Sail version**: Check if ARM v9.3-a or v9.4-a snapshots fixed this

## Testing Performed
- ✓ Verified double-free with lldb disassembly
- ✓ Identified exact crash location (model_fini + 64 bytes)
- ✓ Traced to duplicate `zCNT_CTL` declarations
- ✓ Confirmed all core Sail APIs work without model_fini()

## Impact on MapacheSPIM
**NONE** - We simply skip model_fini() and all functionality works perfectly.

## References
- Generated code: `backends/arm/sail-arm/arm-v8.5-a/snapshots/c/aarch64.c`
- Bug location: Lines 1630274, 1630297 (duplicate zCNT_CTL)
- Crash location: Lines 1638956-1638957 (double kill_letbind calls)
- Test program: `backends/arm/test_cleanup.c`
