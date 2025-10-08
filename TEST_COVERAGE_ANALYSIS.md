# MapacheSPIM Test Coverage Analysis & Expansion Plan

**Date:** October 2025
**Current Status:** 123 tests passing (31 API + 38 console + 24 symbol + 30 disasm)

---

## 1. Current Test Coverage Analysis

### ✅ What We Test Well

#### API Layer (31 tests)
- **Basic Operations:** Initialization, context managers, PC access
- **Program Loading:** ELF loading, entry point verification
- **Single Stepping:** PC advancement, instruction execution
- **Register Access:** Read/write all 32 registers, x0 immutability
- **Memory Access:** Read/write operations, byte handling
- **Reset Functionality:** State clearing

#### Console Commands (38 tests)
- **All Basic Commands:** load, step, run, break, continue, regs, pc, mem, status, reset
- **Symbol Support:** info symbols, symbolic breakpoints
- **Section Inspection:** info sections, mem with section names
- **Source Display:** list command with/without debug info
- **Aliases:** All command shortcuts (s, r, b, c, d, l)

#### Symbols (24 tests)
- **Symbol Table API:** get_symbols, lookup_symbol, addr_to_symbol
- **Console Integration:** Symbolic breakpoints, info symbols output
- **Edge Cases:** Missing symbols, sorting, multiple programs

#### Disassembly (30 tests)
- **API Disassembly:** Single instruction disassembly
- **Console disasm Command:** Multiple instructions, different programs
- **Integration:** Symbol integration with disassembly

---

## 2. Critical Gaps Identified

### 🔴 HIGH PRIORITY GAPS

#### 2.1 Program Termination & Exit Codes
**Gap:** We don't test if programs actually complete correctly!

**Missing Tests:**
- Do programs reach their expected halt condition?
- Does the simulator detect program completion?
- Are exit codes preserved/accessible?
- What happens with infinite loops?

**Current Problem:**
```python
# We test "run for N steps" but not "run to completion"
steps_executed = self.sim.run(max_steps=100)
# But we never verify: Did the program FINISH? Or did we just hit the limit?
```

#### 2.2 Input/Output (I/O) Operations
**Gap:** ZERO tests for actual program input/output!

**Missing Tests:**
- Can programs print output?
- Can we capture stdout/console output?
- HTIF (Host-Target Interface) for I/O
- `tohost`/`fromhost` communication
- Syscall handling (if any)

**Current Problem:**
- fibonacci.s writes to `tohost` to exit
- matrix_mult.s writes to `tohost` to exit
- We never verify these writes work!

#### 2.3 Instruction Correctness - Comprehensive ISA Coverage
**Gap:** We test ~3 sample programs, not systematic instruction coverage

**Missing Instruction Categories:**
- **Integer Arithmetic:** Only testing add/sub/addi in simple.s
  - Missing: addw, subw, lui, auipc
- **Logical Operations:** None tested explicitly
  - Missing: and, or, xor, andi, ori, xori
- **Shifts:** Only slli in simple.s
  - Missing: srli, srai, sll, srl, sra, slliw, srliw, sraiw
- **Comparison:** None tested
  - Missing: slt, sltu, slti, sltiu
- **Branches:** Only beqz, blt implied in fibonacci
  - Missing: bne, blt, bge, bltu, bgeu (systematic tests)
- **Jumps:** jal tested, jalr missing
- **Loads/Stores:** lw, sw tested in fibonacci
  - Missing: lb, lh, ld, lbu, lhu, lwu, sb, sh, sd
- **Atomic Operations:** ZERO coverage (if RV64A supported)
- **Floating Point:** ZERO coverage (if RV64F/D supported)
- **Compressed Instructions:** ZERO coverage (if RV64C supported)

#### 2.4 Edge Cases & Error Handling
**Gap:** Limited negative testing

**Missing Tests:**
- Invalid ELF files (corrupted, wrong architecture)
- Memory access violations (unmapped addresses, alignment)
- Invalid instruction encodings
- Stack overflow scenarios
- PC out of bounds
- Division by zero (if applicable)

#### 2.5 End-to-End Workflows
**Gap:** We test individual features, not realistic usage patterns

**Missing Scenarios:**
- Load program → set breakpoint at function → run → hit breakpoint → inspect registers → continue → verify result
- Debug session: step through loop, watch variables change, verify loop counter
- Multi-file programs (if supported)
- Programs with data/bss/rodata sections

#### 2.6 Performance & Correctness
**Gap:** No verification against known-good results

**Missing Tests:**
- Fibonacci(7) should return 13 - do we verify this?
- Matrix multiply should produce correct result matrix - do we verify?
- No golden reference tests
- No comparison with Spike or other RISC-V simulators

---

## 3. Proposed Test Expansion Plan

### Phase 1: Critical Functionality (Week 1)

#### Test 1.1: Program Termination & Results Verification
**File:** `tests/test_program_completion.py`

```python
class TestProgramCompletion(unittest.TestCase):
    """Test that programs actually complete and produce correct results"""

    def test_fibonacci_completes_successfully(self):
        """Verify fibonacci program completes and returns correct result"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        # Run to completion (not just max_steps!)
        result = sim.run(max_steps=10000)  # High limit

        # Verify program completed (not hit limit)
        self.assertLess(result, 10000, "Program should complete before limit")

        # Read result from memory (fib_result address)
        # Fibonacci(7) = 13
        fib_result_addr = sim.lookup_symbol('fib_result')
        result_bytes = sim.read_mem(fib_result_addr, 4)
        result_value = int.from_bytes(result_bytes, 'little')
        self.assertEqual(result_value, 13, "Fibonacci(7) should equal 13")

    def test_matrix_multiply_correct_result(self):
        """Verify matrix multiplication produces correct result"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/matrix_multiply/matrix_mult')

        sim.run(max_steps=100000)

        # Read matrix_c and verify expected values
        # Expected C = A * B = specific known matrix
        matrix_c_addr = sim.lookup_symbol('matrix_c')
        # Verify each element...
```

**Priority:** 🔴 CRITICAL - We need to know our programs work!

---

#### Test 1.2: HTIF & Exit Mechanism
**File:** `tests/test_io_htif.py`

```python
class TestHTIF(unittest.TestCase):
    """Test Host-Target Interface (tohost/fromhost)"""

    def test_tohost_write_detected(self):
        """Verify writes to tohost are detected for program exit"""
        sim = SailSimulator()
        sim.load_elf('examples/riscv/fibonacci/fibonacci')

        # tohost write should signal program completion
        tohost_addr = sim.lookup_symbol('tohost')

        sim.run(max_steps=10000)

        # Check if tohost was written
        tohost_value = sim.read_mem(tohost_addr, 8)
        self.assertNotEqual(tohost_value, b'\x00' * 8, "tohost should be non-zero after exit")

    def test_exit_code_preservation(self):
        """Verify exit codes are preserved in tohost"""
        # Create simple program that writes specific exit code
        # Verify we can read it back
```

**Priority:** 🔴 CRITICAL - Required for correct termination

---

#### Test 1.3: Instruction Set Coverage - RV64I Base
**File:** `tests/test_instructions_rv64i.py`

```python
class TestIntegerArithmetic(unittest.TestCase):
    """Systematic tests for integer arithmetic instructions"""

    def test_add_positive_numbers(self):
        """Test ADD instruction with positive operands"""
        # Small program: add x3, x1, x2 with known values

    def test_add_overflow(self):
        """Test ADD with values that overflow"""

    def test_sub_underflow(self):
        """Test SUB with underflow"""

    # ... test each instruction systematically

class TestLogicalOperations(unittest.TestCase):
    """Test AND, OR, XOR, etc."""

class TestShifts(unittest.TestCase):
    """Test all shift operations"""

class TestBranches(unittest.TestCase):
    """Test all branch conditions"""

class TestLoadsStores(unittest.TestCase):
    """Test all load/store variants (lb, lh, lw, ld, lbu, lhu, lwu, sb, sh, sw, sd)"""
```

**Priority:** 🟡 HIGH - Core correctness validation

---

### Phase 2: Robustness & Edge Cases (Week 2)

#### Test 2.1: Error Handling
**File:** `tests/test_error_handling.py`

```python
class TestInvalidInputs(unittest.TestCase):
    """Test simulator behavior with invalid inputs"""

    def test_load_invalid_elf(self):
        """Loading corrupted ELF should fail gracefully"""

    def test_load_wrong_architecture(self):
        """Loading x86 ELF should fail gracefully"""

    def test_memory_access_unmapped(self):
        """Reading unmapped memory should raise error"""

    def test_unaligned_memory_access(self):
        """Unaligned access should handle correctly"""

    def test_pc_out_of_bounds(self):
        """Setting PC to invalid address should error"""

    def test_invalid_instruction_encoding(self):
        """Invalid opcode should be detected"""
```

**Priority:** 🟡 HIGH - Production readiness

---

#### Test 2.2: End-to-End Debugging Workflows
**File:** `tests/test_e2e_workflows.py`

```python
class TestDebuggingWorkflows(unittest.TestCase):
    """Test realistic debugging scenarios"""

    def test_debug_fibonacci_step_by_step(self):
        """Realistic debug session: step through fibonacci"""
        console = MapacheSPIMConsole()
        console.onecmd('load examples/riscv/fibonacci/fibonacci')
        console.onecmd('break fibonacci')
        console.onecmd('run')
        # Should hit breakpoint

        # Step through base case
        console.onecmd('step')
        console.onecmd('regs')
        # Verify a0 has expected value

    def test_watch_loop_counter(self):
        """Watch a loop counter change through iterations"""
        # Step through loop, verify counter increments

    def test_inspect_data_structures(self):
        """Load program with arrays, inspect memory correctly"""
```

**Priority:** 🟢 MEDIUM - User experience

---

### Phase 3: Performance & Advanced Features (Week 3)

#### Test 3.1: Golden Reference Tests
**File:** `tests/test_golden_reference.py`

```python
class TestAgainstGoldenOutputs(unittest.TestCase):
    """Compare against known-good RISC-V simulator outputs"""

    def test_fibonacci_matches_spike(self):
        """Run fibonacci and compare final state to Spike output"""
        # Could run Spike, capture register dump
        # Run our simulator, compare

    def test_riscv_torture_suite(self):
        """Run against riscv-torture generated tests"""
```

**Priority:** 🟢 MEDIUM - Validation

---

#### Test 3.2: Performance Benchmarks
**File:** `tests/test_performance.py`

```python
class TestPerformance(unittest.TestCase):
    """Performance regression tests"""

    def test_fibonacci_performance(self):
        """Measure time to execute fibonacci"""
        import time
        start = time.time()
        sim.run(max_steps=10000)
        duration = time.time() - start
        # Regression test: should complete in < X seconds
```

**Priority:** 🔵 LOW - Optimization

---

## 4. Test Program Needs

### New Test Programs Required

#### 4.1: Instruction Coverage Programs
Create minimal programs testing each instruction:
- `test_arithmetic.s` - All integer arithmetic
- `test_logical.s` - All logical operations
- `test_shifts.s` - All shift operations
- `test_branches.s` - All branch conditions
- `test_loads_stores.s` - All load/store variants
- `test_jumps.s` - JAL and JALR edge cases

#### 4.2: I/O Test Program
- `test_print.s` - Print "Hello, World!" via HTIF
- `test_exit_codes.s` - Exit with various codes

#### 4.3: Edge Case Programs
- `test_infinite_loop.s` - Infinite loop (for timeout testing)
- `test_stack_usage.s` - Deep recursion
- `test_unaligned.s` - Unaligned memory access

---

## 5. Testing Infrastructure Improvements

### 5.1: Test Helpers
Create utilities for common test patterns:

```python
# tests/test_helpers.py

def assert_program_completes(sim, elf_path, max_steps=10000):
    """Helper: Assert program completes successfully"""
    sim.load_elf(elf_path)
    steps = sim.run(max_steps)
    assert steps < max_steps, f"Program didn't complete in {max_steps} steps"
    return steps

def assert_register_equals(sim, reg_num, expected_value):
    """Helper: Assert register has expected value"""
    actual = sim.get_reg(reg_num)
    assert actual == expected_value, f"x{reg_num}: expected {expected_value:#x}, got {actual:#x}"

def run_and_verify_memory(sim, elf_path, addr, expected_bytes):
    """Helper: Run program and verify memory contents"""
    sim.load_elf(elf_path)
    sim.run()
    actual = sim.read_mem(addr, len(expected_bytes))
    assert actual == expected_bytes
```

### 5.2: Golden Output Framework
```python
# tests/golden_outputs/
#   fibonacci.json
#   matrix_mult.json

{
  "program": "fibonacci",
  "input": 7,
  "expected_steps": 150,
  "expected_registers": {
    "a0": 13,
    "ra": "...",
  },
  "expected_memory": {
    "fib_result": [0x0d, 0x00, 0x00, 0x00]
  }
}
```

---

## 6. Prioritized Implementation Order

### Sprint 1 (Highest Priority) - Days 1-3
1. ✅ **Test Program Completion** - Verify fibonacci/matrix actually finish
2. ✅ **Test Result Verification** - Fibonacci(7)=13, matrix multiply correct
3. ✅ **Test HTIF tohost** - Program exit mechanism works

### Sprint 2 (High Priority) - Days 4-7
4. ✅ **Test Load/Store All Variants** - lb, lh, lw, ld, lbu, lhu, lwu, sb, sh, sw, sd
5. ✅ **Test Branches All Conditions** - beq, bne, blt, bge, bltu, bgeu
6. ✅ **Test Integer Arithmetic** - add, sub, addi, etc.

### Sprint 3 (Medium Priority) - Week 2
7. ✅ **Test Error Handling** - Invalid ELF, bad memory access
8. ✅ **Test E2E Workflows** - Realistic debugging sessions
9. ✅ **Test Logical & Shifts** - Complete RV64I coverage

### Sprint 4 (Future) - Week 3+
10. ⏸️ **Golden Reference Tests** - Compare to Spike
11. ⏸️ **Performance Tests** - Regression detection
12. ⏸️ **Extended ISA** - RV64M, RV64A, RV64F/D if supported

---

## 7. Success Metrics

### Coverage Goals
- **Instruction Coverage:** 100% of RV64I base instructions tested
- **End-to-End:** At least 5 realistic debugging workflows
- **Error Cases:** All major error conditions tested
- **Result Verification:** All example programs verified correct

### Quality Metrics
- All tests pass consistently
- Test suite runs in < 2 minutes
- Each test is independent (can run in isolation)
- Clear failure messages
- No flaky tests

---

## 8. Risks & Mitigation

### Risk 1: HTIF Not Implemented
**Mitigation:** Check if simulator actually supports tohost/fromhost. May need to implement.

### Risk 2: Programs Don't Actually Complete
**Mitigation:** May need to add proper halt detection to simulator first.

### Risk 3: Instruction Coverage Requires Many Programs
**Mitigation:** Start with critical instructions, expand gradually.

---

## Summary

**Current State:** Good coverage of API and console commands, but missing critical functional validation.

**Biggest Gaps:**
1. 🔴 No verification that programs actually complete correctly
2. 🔴 No I/O testing
3. 🔴 Incomplete instruction coverage
4. 🟡 Limited error handling tests
5. 🟡 No end-to-end workflow validation

**Recommendation:** Start with Sprint 1 (program completion & result verification). This is the most critical gap - we need to know our simulator actually produces correct results!
