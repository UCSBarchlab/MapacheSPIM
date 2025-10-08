# MapacheSPIM Test Suite

Comprehensive unit tests for the Sail RISC-V simulator Python API.

## Running Tests

```bash
# Run all tests
python3 tests/test_simulator.py

# Run with verbose output
python3 tests/test_simulator.py -v

# Run specific test class
python3 -m unittest tests.test_simulator.TestFibonacci

# Run specific test
python3 -m unittest tests.test_simulator.TestFibonacci.test_fibonacci_single_step
```

## Test Coverage

### TestSimulatorBasic (3 tests)
- ✅ Initialization without config
- ✅ Context manager support
- ✅ PC access after initialization

### TestFibonacci (5 tests)
Tests using the `fibonacci` example program:
- ✅ ELF loading
- ✅ Entry point verification (0x80000000)
- ✅ Single-step execution
- ✅ Multiple steps (10 instructions)
- ✅ Run with max_steps limit

### TestMatrixMultiply (4 tests)
Tests using the `matrix_multiply` example program:
- ✅ ELF loading
- ✅ Entry point verification (0x80000000)
- ✅ Single-step execution
- ✅ Run with max_steps limit

### TestRegisterAccess (9 tests)
- ✅ Get all 32 registers
- ✅ x0 always reads as 0
- ✅ Read all valid registers (0-31)
- ✅ Invalid register numbers raise ValueError
- ✅ Set register value
- ✅ Cannot set x0 (raises ValueError)
- ✅ 64-bit value overflow handling

### TestMemoryAccess (4 tests)
- ✅ Read memory at PC
- ✅ Read 4-byte instruction
- ✅ Write and read back memory
- ✅ String to bytes conversion

### TestPCAccess (3 tests)
- ✅ Get program counter
- ✅ Set program counter
- ✅ PC advances after step

### TestReset (1 test)
- ✅ Reset clears simulator state

### TestEdgeCases (3 tests)
- ✅ Loading nonexistent file raises error
- ✅ Stepping before loading program
- ✅ Run with max_steps=0 (unlimited)

## Test Statistics

- **Total Tests:** 31
- **Pass Rate:** 100%
- **Test Time:** ~0.05 seconds
- **Programs Tested:** fibonacci, matrix_multiply
- **API Functions Tested:** All 13 core functions

## Tested Programs

### Fibonacci (Recursive)
- **Path:** `examples/riscv/fibonacci/fibonacci`
- **Entry:** 0x80000000
- **Tests:** Single-step, multi-step, run

### Matrix Multiplication (3x3)
- **Path:** `examples/riscv/matrix_multiply/matrix_mult`
- **Entry:** 0x80000000
- **Tests:** Single-step, multi-step, run

## API Functions Tested

| Function | Tested | Test Count |
|----------|--------|------------|
| `SailSimulator()` | ✅ | 3 |
| `load_elf()` | ✅ | 4 |
| `step()` | ✅ | 5 |
| `run()` | ✅ | 4 |
| `get_pc()` | ✅ | 4 |
| `set_pc()` | ✅ | 1 |
| `get_reg()` | ✅ | 4 |
| `set_reg()` | ✅ | 3 |
| `get_all_regs()` | ✅ | 1 |
| `read_mem()` | ✅ | 3 |
| `write_mem()` | ✅ | 2 |
| `reset()` | ✅ | 1 |
| Context manager | ✅ | 1 |

## Adding New Tests

To add tests for a new RISC-V program:

```python
class TestMyProgram(unittest.TestCase):
    """Tests using my_program example"""

    def setUp(self):
        self.sim = SailSimulator()
        self.elf_path = "examples/my_program/my_program"

    def test_load_program(self):
        """Test loading the program"""
        result = self.sim.load_elf(self.elf_path)
        self.assertTrue(result)

    def test_program_behavior(self):
        """Test specific program behavior"""
        self.sim.load_elf(self.elf_path)
        # Execute and verify
        self.sim.run(100)
        # Check results
        result_reg = self.sim.get_reg(10)  # a0 register
        self.assertEqual(result_reg, expected_value)
```

## Continuous Testing

These tests serve as regression tests to ensure:
- API stability across changes
- Correct simulator behavior with different programs
- Error handling works as expected
- Memory safety and bounds checking

Run tests before committing changes to verify nothing broke!

---

## Console Command Tests

### test_console_working.py
**Comprehensive console command test suite** - 38 tests covering all console commands

Status: ✅ **All 38 tests passing**

```bash
# Run console command tests
python3 tests/test_console_working.py
```

#### Coverage

| Command | Tests | Status |
|---------|-------|--------|
| `load` | 3 tests | ✅ Pass |
| `step` | 5 tests | ✅ Pass |
| `run` | 2 tests | ✅ Pass |
| `break` | 3 tests | ✅ Pass |
| `info breakpoints` | 1 test | ✅ Pass |
| `delete` | 1 test | ✅ Pass |
| `clear` | 1 test | ✅ Pass |
| `continue` | 1 test | ✅ Pass |
| `regs` | 1 test | ✅ Pass |
| `pc` | 1 test | ✅ Pass |
| `mem` | 4 tests | ✅ Pass |
| `info sections` | 3 tests | ✅ Pass |
| `list` (source display) | 7 tests | ✅ Pass |
| `status` | 2 tests | ✅ Pass |
| **Aliases** | 3 tests | ✅ Pass |

#### Test Program: examples/riscv/test_simple/simple

A deterministic 9-instruction program with documented cycle-by-cycle behavior.

**Expected final register values:**
```
x1  (ra)  = 93  (0x5d)  - exit syscall number
x5  (t0)  = 10  (0x0a)
x6  (t1)  = 20  (0x14)
x7  (t2)  = 30  (0x1e)
x8  (s0)  = 20  (0x14)
x9  (s1)  = 40  (0x28)
x10 (a0)  = 42  (0x2a)  - exit code
```

**Documentation:** See `examples/riscv/test_simple/EXPECTED_BEHAVIOR.md` for complete step-by-step behavior documentation.

#### Additional Test Files

- **test_simple_basic.py** - Basic simulator functionality test
- **test_run_completion.py** - Detailed program execution through completion
- **TESTING_NOTES.md** - Important notes about Sail behavior and test strategy

## Test Summary

**Total API Tests:** 31 (all passing)
**Total Console Tests:** 38 (all passing)
**Total Symbol Tests:** 24 (all passing)
**Total Disassembly Tests:** 30 (all passing)
**Total Correctness Tests:** 10 (all passing)
**Total:** 133 tests passing

**Programs Tested:**
- fibonacci (recursive calculation)
- matrix_multiply (3x3 matrices)
- test_simple (deterministic 9-instruction program)

---

## Program Correctness Tests

### test_program_correctness.py
**Critical validation tests** - 10 tests verifying programs produce correct results

Status: All 10 tests passing

```bash
# Run program correctness tests
python3 tests/test_program_correctness.py
```

#### Test Classes

| Test Class | Tests | Status | Description |
|------------|-------|--------|-------------|
| `TestFibonacciCorrectness` | 4 tests | Pass | Verifies Fibonacci(7) = 13 |
| `TestToHostMechanism` | 2 tests | Pass | Verifies HTIF exit mechanism |
| `TestMatrixMultiplyCorrectness` | 2 tests | Pass | Verifies matrix result correct |
| `TestProgramCompletion` | 2 tests | Pass | Verifies completion detection |

#### Key Validations

**Fibonacci Correctness:**
- Fibonacci(7) returns 13 (correct result)
- Program completes in ~462 steps (not infinite loop)
- Result written to memory correctly
- tohost mechanism works

**Matrix Multiply Correctness:**
- Computes correct 3x3 result matrix
- All 9 elements verified individually
- Completes in ~663 steps

**Expected Results:**
```
Fibonacci(7) = 13
Matrix C = [[30, 24, 18], [84, 69, 54], [138, 114, 90]]
```

These tests verify the simulator's HTIF (Host-Target Interface) tohost detection
mechanism, which allows programs to signal completion by writing to the tohost
symbol. Without this, programs would run indefinitely in their exit loops.
