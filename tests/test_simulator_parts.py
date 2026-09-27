"""Unit tests for the simulator's building blocks and run_until()."""

from io import StringIO

import pytest

from mapachespim import RunResult, Simulator, StopReason
from mapachespim.disassembler import Disassembler
from mapachespim.isa import ISA_SPECS, get_spec
from mapachespim.symbols import MAX_SYMBOL_DISTANCE, SymbolTable


class TestSymbolTable:
    def test_lookup(self):
        table = SymbolTable({"main": 0x100, "loop": 0x120})
        assert table.lookup("loop") == 0x120
        assert table.lookup("nope") is None
        assert "main" in table and len(table) == 2
        assert table.as_dict() == {"main": 0x100, "loop": 0x120}

    def test_nearest(self):
        table = SymbolTable({"main": 0x100, "loop": 0x120})
        assert table.nearest(0x100) == ("main", 0)
        assert table.nearest(0x11C) == ("main", 0x1C)
        assert table.nearest(0x124) == ("loop", 4)
        assert table.nearest(0xFF) == (None, None)
        assert table.nearest(0x120 + MAX_SYMBOL_DISTANCE + 1) == (None, None)

    def test_same_address_uses_last_defined(self):
        table = SymbolTable({".Llocal": 0x100, "_start": 0x100})
        assert table.nearest(0x104) == ("_start", 4)

    def test_describe(self):
        table = SymbolTable({"main": 0x100})
        assert table.describe(0x100) == "<main>"
        assert table.describe(0x108) == "<main+8>"
        assert table.describe(0x10) == ""
        assert SymbolTable().describe(0) == ""


class TestDisassembler:
    def test_decodes(self):
        riscv = Disassembler(get_spec("riscv64"))
        assert riscv.disassemble((0x00000013).to_bytes(4, "little"), 0) == ("nop", 4)
        x86 = Disassembler(get_spec("x86_64"))
        assert x86.disassemble(b"\x0f\x05\x90", 0) == ("syscall", 2)

    @pytest.mark.parametrize("spec", ISA_SPECS, ids=lambda spec: spec.name)
    def test_undecodable_bytes_still_advance(self, spec):
        disasm = Disassembler(spec)
        text, size = disasm.disassemble(b"\xff" * spec.max_instruction_size, 0x1000)
        assert size >= 1
        text, size = disasm.disassemble(b"", 0x1000)
        assert text == "<invalid address>" and size == spec.min_instruction_size

    def test_undecodable_fixed_width_shown_as_word(self):
        mips = Disassembler(get_spec("mips32"))
        assert mips.disassemble(bytes.fromhex("fc000000"), 0) == (".word 0xfc000000", 4)
        x86 = Disassembler(get_spec("x86_64"))
        assert x86.disassemble(b"\x06", 0) == (".byte 0x06", 1)


FIB = "examples/riscv/fibonacci/fibonacci"


class TestRunUntil:
    def _sim(self):
        sim = Simulator()
        sim.load_elf(FIB)
        return sim

    def test_runs_to_exit(self, capsys):
        sim = self._sim()
        result = sim.run_until()
        assert result.reason == StopReason.EXIT
        assert result.steps > 10

    def test_step_limit(self):
        sim = self._sim()
        result = sim.run_until(5)
        assert result.steps == 5 and result.reason is None

    def test_stop_before_and_resume(self):
        sim = self._sim()
        target = sim.lookup_symbol("fibonacci")
        stop = lambda pc: StopReason.BREAKPOINT if pc == target else None  # noqa: E731
        result = sim.run_until(stop_before=stop)
        assert result.reason == StopReason.BREAKPOINT
        assert result.pc == target == sim.get_pc()
        # Resuming does not stop again at the breakpoint it is on
        result = sim.run_until(1, stop_before=stop)
        assert result.steps == 1 and result.reason is None

    def test_error_reports_faulting_pc(self):
        sim = Simulator(isa=get_spec("riscv64").isa)
        sim.write_mem(sim.get_pc(), (0).to_bytes(4, "little"))  # illegal instruction
        result = sim.run_until(10)
        assert result.reason == StopReason.ERROR
        assert result.pc == sim.get_pc() == get_spec("riscv64").layout.text_base
        assert sim.last_error.endswith(f"(at PC={result.pc:#x})")

    def test_stop_reason_compares_to_strings(self):
        assert StopReason.EXIT == "syscall_exit"
        assert StopReason.ERROR == "error"

    def test_halts_after_exit(self):
        sim = Simulator()
        sim.load_elf("examples/riscv/hello_asm/hello_asm")
        sim.stdout = StringIO()
        assert sim.run_until().reason == StopReason.EXIT
        assert sim.exited and sim.exit_code == 0
        assert sim.run_until() == RunResult(1, StopReason.HALT, sim.get_pc())

    def test_run_returns_step_count(self):
        sim = self._sim()
        assert sim.run(7) == 7
