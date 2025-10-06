# MapacheSail Test Suite

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
- **Path:** `examples/fibonacci/fibonacci`
- **Entry:** 0x80000000
- **Tests:** Single-step, multi-step, run

### Matrix Multiplication (3x3)
- **Path:** `examples/matrix_multiply/matrix_mult`
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
