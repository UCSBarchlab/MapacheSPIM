"""
Tests for loading programs: assembly sources, bundled examples, reload,
and the command-line entry points.
"""

import io
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from mapachespim.console import MapacheSPIMConsole
from mapachespim.examples import copy_examples, find_example, list_examples

HELLO_RISCV = textwrap.dedent(
    """\
    .isa riscv64
    .text
    .globl _start
    _start:
        la a0, msg
        li a7, 4
        ecall
    done:
        li a0, 7
        li a7, 93
        ecall
    .data
    msg: .asciz "hello from source\\n"
    """
)


def run_cli(*args, stdin=""):
    return subprocess.run(
        [sys.executable, "-m", "mapachespim.console", *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestExamples(unittest.TestCase):
    def test_all_isas_listed(self):
        names = {e.short_name for e in list_examples()}
        for isa in ("riscv", "mips", "arm", "x86_64"):
            self.assertIn(f"{isa}/hello_asm", names)
        for example in list_examples():
            self.assertTrue(example.binary.is_file())
            self.assertTrue(example.description, example.short_name)

    def test_find_example_forms(self):
        expected = find_example("riscv/fibonacci")
        self.assertIsNotNone(expected)
        self.assertEqual(find_example("riscv/fibonacci/fibonacci"), expected)
        self.assertEqual(find_example("examples/riscv/fibonacci/fibonacci"), expected)
        self.assertEqual(find_example("riscv/matrix_multiply").name, "matrix_mult")
        self.assertIsNone(find_example("riscv/nope"))
        self.assertIsNone(find_example("../pyproject.toml"))

    def test_copy_examples(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = copy_examples(Path(tmp) / "ex")
            self.assertTrue((dest / "riscv/hello_asm/hello_asm.s").is_file())
            with self.assertRaises(FileExistsError):
                copy_examples(dest)


class TestConsoleLoading(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.console = MapacheSPIMConsole()
        self.out = io.StringIO()
        self.console.stdout = self.out
        self.console.sim.stdout = self.out

    def tearDown(self):
        self.tmp.cleanup()

    def output(self) -> str:
        text = self.out.getvalue()
        self.out.truncate(0)
        self.out.seek(0)
        return text

    def write(self, name: str, text: str) -> Path:
        path = self.dir / name
        path.write_text(text)
        return path

    def test_load_source_and_run(self):
        src = self.write("hello.s", HELLO_RISCV)
        self.console.onecmd(f"load {src}")
        text = self.output()
        self.assertIn("Assembled hello.s", text)
        self.assertIn("Source info: hello.s", text)
        self.console.onecmd("run")
        text = self.output()
        self.assertIn("hello from source", text)
        self.assertIn("exited with code 7", text)

    def test_list_shows_source(self):
        src = self.write("hello.s", HELLO_RISCV)
        self.console.onecmd(f"load {src}")
        self.output()
        self.console.onecmd("list")
        self.assertIn("la a0, msg", self.output())

    def test_source_without_isa(self):
        src = self.write("noisa.s", HELLO_RISCV.replace(".isa riscv64\n", ""))
        self.console.onecmd(f"load {src}")
        self.assertIn("does not say which ISA", self.output())
        self.assertIsNone(self.console.loaded_file)
        self.console.onecmd(f"load {src} riscv64")
        self.assertIn("Assembled", self.output())

    def test_assembly_errors_are_reported(self):
        src = self.write("bad.s", ".isa riscv64\n.text\n_start:\n    addi a0, a0\n")
        self.console.onecmd(f"load {src}")
        text = self.output()
        self.assertIn("could not assemble bad.s", text)
        self.assertIn("Line 4", text)

    def test_reload_picks_up_edits_and_moves_breakpoints(self):
        src = self.write("prog.s", HELLO_RISCV)
        self.console.onecmd(f"load {src}")
        self.console.onecmd("break done")
        old = self.console.sim.lookup_symbol("done")
        # Insert two instructions before 'done' so the label moves
        src.write_text(HELLO_RISCV.replace("done:", "    nop\n    nop\ndone:"))
        self.console.onecmd("reload")
        new = self.console.sim.lookup_symbol("done")
        self.assertEqual(new, old + 8)
        self.assertEqual(self.console.breakpoints, {new})

    def test_load_example_by_name(self):
        self.console.onecmd("load mips/hello_asm")
        self.assertIn("(MIPS)", self.output())
        self.console.onecmd("run")
        self.assertIn("Hello, Assembly!", self.output())

    def test_mips_example_has_source_info(self):
        """MIPS DWARF used to be written little-endian and could not be read"""
        self.console.onecmd("load mips/hello_asm")
        self.assertIn("Source info: hello_asm.s", self.output())

    def test_examples_command(self):
        self.console.onecmd("examples riscv")
        text = self.output()
        self.assertIn("riscv/fibonacci", text)
        self.assertNotIn("mips/", text)

    def test_missing_file_hint(self):
        self.console.onecmd("load no/such/file")
        self.assertIn('Type "examples"', self.output())


class TestCommandLine(unittest.TestCase):
    def test_version(self):
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("mapachespim", result.stdout)

    def test_execute_source_file_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "hello.s"
            src.write_text(HELLO_RISCV)
            result = run_cli("-e", str(src))
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.stdout, "hello from source\n")

    def test_execute_with_isa_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "hello.s"
            src.write_text(HELLO_RISCV.replace(".isa riscv64\n", ""))
            result = run_cli("-e", "--isa", "riscv64", str(src))
        self.assertEqual(result.returncode, 7, result.stderr)

    def test_execute_example_by_name(self):
        result = run_cli("-e", "riscv/hello_asm")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Hello, Assembly!", result.stdout)

    def test_execute_infinite_loop_times_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "loop.s"
            src.write_text(".isa riscv64\n.text\n_start:\n    j _start\n")
            result = run_cli("-e", "--max-steps", "1000", str(src))
        self.assertEqual(result.returncode, 124)
        self.assertIn("did not exit within 1000 instructions", result.stderr)

    def test_execute_fault_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fault.s"
            src.write_text(".isa riscv64\n.text\n_start:\n    ld a0, 0(zero)\n")
            result = run_cli("-e", str(src))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Read from unmapped address 0x0", result.stderr)

    def test_copy_examples_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, "-m", "mapachespim.console", "--copy-examples", "ex"],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(tmp) / "ex/mips/hello_asm/hello_asm.s").is_file())


if __name__ == "__main__":
    unittest.main()
