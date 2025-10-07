# Simple Test Program - Expected Behavior

This program provides predictable cycle-by-cycle behavior for testing the MapacheSail console.

## Program Overview

**Purpose:** Test basic arithmetic and control flow
**Instructions:** 9 total (7 before jump, 2 after)
**Entry Point:** 0x80000000

## Step-by-Step Execution

### Initial State
- All registers = 0
- PC = 0x80000000

### Step 1: `li t0, 10` (addi x5, x0, 10)
- **Address:** 0x80000000
- **Encoding:** 0x00a00293
- **Effect:** x5 (t0) = 10 (0xa)
- **Next PC:** 0x80000004

### Step 2: `li t1, 20` (addi x6, x0, 20)
- **Address:** 0x80000004
- **Encoding:** 0x01400313
- **Effect:** x6 (t1) = 20 (0x14)
- **Next PC:** 0x80000008

### Step 3: `add t2, t0, t1` (add x7, x5, x6)
- **Address:** 0x80000008
- **Encoding:** 0x006283b3
- **Effect:** x7 (t2) = x5 + x6 = 10 + 20 = 30 (0x1e)
- **Next PC:** 0x8000000c

### Step 4: `sub s0, t2, t0` (sub x8, x7, x5)
- **Address:** 0x8000000c
- **Encoding:** 0x40538433
- **Effect:** x8 (s0) = x7 - x5 = 30 - 10 = 20 (0x14)
- **Next PC:** 0x80000010

### Step 5: `slli s1, t0, 2` (slli x9, x5, 2)
- **Address:** 0x80000010
- **Encoding:** 0x00229493
- **Effect:** x9 (s1) = x5 << 2 = 10 << 2 = 40 (0x28)
- **Next PC:** 0x80000014

### Step 6: `li a0, 42` (addi x10, x0, 42)
- **Address:** 0x80000014
- **Encoding:** 0x02a00513
- **Effect:** x10 (a0) = 42 (0x2a)
- **Next PC:** 0x80000018

### Step 7: `j done` (jal x0, 0x8000001c)
- **Address:** 0x80000018
- **Encoding:** 0x0040006f
- **Effect:** PC = 0x8000001c (no register update since rd=x0)
- **Next PC:** 0x8000001c

### Step 8: `li ra, 93` (addi x1, x0, 93)
- **Address:** 0x8000001c
- **Encoding:** 0x05d00093
- **Effect:** x1 (ra) = 93 (0x5d) - exit syscall number
- **Next PC:** 0x80000020

### Step 9: `ecall`
- **Address:** 0x80000020
- **Encoding:** 0x00000073
- **Effect:** System call (simulator should halt)
- **Next PC:** (halted)

## Final Register State (After Step 8, Before ecall)

| Register | ABI Name | Value (hex) | Value (dec) |
|----------|----------|-------------|-------------|
| x0       | zero     | 0x00000000  | 0           |
| x1       | ra       | 0x0000005d  | 93          |
| x2       | sp       | 0x83f00000  | (default)   |
| x3       | gp       | 0x00000000  | 0           |
| x4       | tp       | 0x00000000  | 0           |
| x5       | t0       | 0x0000000a  | 10          |
| x6       | t1       | 0x00000014  | 20          |
| x7       | t2       | 0x0000001e  | 30          |
| x8       | s0       | 0x00000014  | 20          |
| x9       | s1       | 0x00000028  | 40          |
| x10      | a0       | 0x0000002a  | 42          |
| x11-x31  | ...      | 0x00000000  | 0           |

## Memory Contents

### Text Segment (0x80000000 - 0x80000023)

```
0x80000000:  93 02 a0 00  13 03 40 01  b3 83 62 00  33 84 53 40
0x80000010:  93 94 22 00  13 05 a0 02  6f 00 40 00  93 00 d0 05
0x80000020:  73 00 00 00
```

## Test Cases

### Test 1: Single Step Verification
```
load examples/test_simple/simple
step
# Verify x5 = 10, PC = 0x80000004
step
# Verify x6 = 20, PC = 0x80000008
step
# Verify x7 = 30, PC = 0x8000000c
```

### Test 2: Multi-Step
```
load examples/test_simple/simple
step 6
# Verify x10 = 42, PC = 0x80000018
```

### Test 3: Breakpoint
```
load examples/test_simple/simple
break 0x80000010
run
# Should stop at 0x80000010 after 5 instructions
# Verify x8 = 20
```

### Test 4: Memory Read
```
load examples/test_simple/simple
mem 0x80000000 32
# Should show instruction bytes
```

### Test 5: Run to Completion
```
load examples/test_simple/simple
run
# Should execute 9 steps and halt at ecall
```

## Console Command Testing

This program is ideal for testing all console commands because:
1. Short and predictable (9 instructions)
2. Tests arithmetic (add, sub, slli)
3. Tests control flow (jump)
4. Tests immediates (addi/li)
5. Known register values at each step
6. Has natural breakpoint locations
7. Terminates cleanly with ecall
