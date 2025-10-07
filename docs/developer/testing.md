# MapacheSPIM Testing Notes

## Test Program Behavior

### Simple Test Program

The `examples/test_simple/simple` program executes exactly 9 instructions:

1-8: Various arithmetic and control flow instructions
9: `ecall` (exit syscall)

### Important Sail Behavior Notes

**ECALL Does Not Return HALT**: The Sail RISC-V simulator does not return `StepResult.HALT` when executing an `ecall` instruction. Instead:

- `ecall` returns `StepResult.OK` (0)
- PC becomes 0x0 after `ecall`
- Subsequent steps continue executing from PC=0 (likely invalid instructions)

This means:
- Programs don't naturally "halt" - they just execute ecall and continue
- Tests should limit step count or detect PC=0 as termination
- The `run` command in the console will continue indefinitely without a breakpoint or max step limit

### Test Strategy

For testing purposes:

1. **Single-step tests**: Execute exact number of steps (works reliably)
2. **Run-to-completion tests**: Use step limits (e.g., `run 20`) or detect PC=0
3. **Breakpoint tests**: Set breakpoints before target addresses

### Expected Register Values

After 9 steps (including ecall), registers should be:

```
x1  (ra) = 0x5d (93)  - syscall number
x5  (t0) = 0x0a (10)
x6  (t1) = 0x14 (20)
x7  (t2) = 0x1e (30)
x8  (s0) = 0x14 (20)
x9  (s1) = 0x28 (40)
x10 (a0) = 0x2a (42)
```

PC will be 0x0 after ecall (step 9).

### Memory Layout

```
0x80000000 - Entry point / .text segment start
0x80000020 - ecall instruction location
0x80000024 - End of program
```

## Console Testing

### Stdout Redirection Issue

The `cmd.Cmd` class expects `self.stdout` to exist. Tests must set:

```python
self.console.stdout = sys.stdout  # or StringIO()
```

### Commands Requiring Loaded File

These commands require a file to be loaded first:
- `step`
- `run`
- `continue`
- `regs`
- `mem`
- `pc`

### Commands Working Without File

These work without a loaded file:
- `load`
- `status`
- `help`
- `quit/exit`
- `break` (can set breakpoints before loading)
- `info breakpoints`
- `clear`
