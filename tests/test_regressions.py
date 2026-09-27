"""
Regression tests for simulator and console bugs.

Programs here are written as raw machine code so the tests do not depend on
the assembler.
"""

import io
import struct
import unittest
from pathlib import Path

from mapachespim import ISA, Simulator, StepResult
from mapachespim.console import MapacheSPIMConsole

EXAMPLES = Path(__file__).parent.parent / "examples"

# RISC-V encodings
RV_ECALL = 0x00000073


def rv_addi(rd: int, rs1: int, imm: int) -> int:
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x13


def load_words(sim: Simulator, words, big_endian: bool = False) -> int:
    """Write instruction words at the current PC and return that address."""
    pc = sim.get_pc()
    fmt = ">I" if big_endian else "<I"
    sim.write_mem(pc, b"".join(struct.pack(fmt, w) for w in words))
    return pc


def run_to_end(sim: Simulator, limit: int = 1000):
    for _ in range(limit):
        done, reason = sim.check_termination(sim.step())
        if done:
            return reason
    return None


class TestSyscalls(unittest.TestCase):
    def test_mips_print_int_negative(self):
        """print_int must sign-extend 32-bit MIPS registers"""
        sim = Simulator(ISA.MIPS)
        sim.stdout = io.StringIO()
        load_words(
            sim,
            [
                0x2404FFFB,  # addiu $a0, $zero, -5
                0x24020001,  # addiu $v0, $zero, 1   (print_int)
                0x0000000C,  # syscall
                0x2402000A,  # addiu $v0, $zero, 10  (exit)
                0x0000000C,  # syscall
            ],
            big_endian=True,
        )
        self.assertEqual(run_to_end(sim), "syscall_exit")
        self.assertEqual(sim.stdout.getvalue(), "-5")

    def test_read_char_reads_one_line_once(self):
        """read_char used to call input() twice and return the second line"""
        sim = Simulator(ISA.RISCV)
        sim.stdin = io.StringIO("AB\nC\n")
        load_words(
            sim,
            [rv_addi(17, 0, 12), RV_ECALL, rv_addi(5, 10, 0)]  # a7=12; ecall; t0=a0
            + [rv_addi(17, 0, 12), RV_ECALL, rv_addi(6, 10, 0)]  # t1=second char
            + [rv_addi(17, 0, 12), RV_ECALL, rv_addi(7, 10, 0)],  # t2=third char
        )
        run_to_end(sim, limit=9)
        self.assertEqual(chr(sim.get_reg(5)), "A")
        self.assertEqual(chr(sim.get_reg(6)), "B")
        self.assertEqual(chr(sim.get_reg(7)), "\n")

    def test_read_int_from_stdin(self):
        sim = Simulator(ISA.RISCV)
        sim.stdin = io.StringIO("-42\n")
        load_words(sim, [rv_addi(17, 0, 5), RV_ECALL])
        run_to_end(sim, limit=2)
        self.assertEqual(sim.get_reg(10), (-42) & 0xFFFFFFFFFFFFFFFF)

    def test_exit_code(self):
        sim = Simulator(ISA.RISCV)
        load_words(sim, [rv_addi(10, 0, 3), rv_addi(17, 0, 93), RV_ECALL])
        self.assertEqual(run_to_end(sim), "syscall_exit")
        self.assertTrue(sim.exited)
        self.assertEqual(sim.exit_code, 3)

    def test_step_after_exit_does_nothing(self):
        sim = Simulator(ISA.RISCV)
        load_words(sim, [rv_addi(17, 0, 10), RV_ECALL, rv_addi(5, 0, 1)])
        run_to_end(sim)
        pc = sim.get_pc()
        self.assertEqual(sim.step(), StepResult.HALT)
        self.assertEqual(sim.get_pc(), pc)
        self.assertEqual(sim.get_reg(5), 0)

    def test_unknown_syscall_is_an_error(self):
        sim = Simulator(ISA.RISCV)
        load_words(sim, [rv_addi(17, 0, 99), RV_ECALL])
        self.assertEqual(run_to_end(sim), "error")
        self.assertIn("Unknown syscall number 99", sim.last_error)
        self.assertIn("a7", sim.last_error)


class TestMemory(unittest.TestCase):
    def test_fault_message_includes_address(self):
        sim = Simulator(ISA.RISCV)
        # lui a0, 0x50000 ; ld a1, 0(a0)
        load_words(sim, [(0x50000 << 12) | (10 << 7) | 0x37, 0x00053583])
        sim.step()
        self.assertEqual(sim.step(), StepResult.ERROR)
        self.assertIn("Read from unmapped address 0x50000000", sim.last_error)

    def test_arm_null_pointer_faults(self):
        """Address 0 used to be mapped on ARM, hiding null dereferences"""
        sim = Simulator(ISA.ARM)
        pc = load_words(sim, [0xF9400001])  # ldr x1, [x0] with x0 = 0
        self.assertEqual(sim.step(), StepResult.ERROR)
        self.assertIn("0x0", sim.last_error)
        self.assertEqual(sim.get_pc(), pc)

    def test_riscv_sign_extended_alias_is_shared(self):
        """lui-built addresses (0xFFFFFFFF8xxxxxxx) must see the same memory"""
        sim = Simulator(ISA.RISCV)
        sim.write_mem(0x80000100, b"\x11")
        self.assertEqual(sim.read_mem(0xFFFFFFFF80000100, 1), b"\x11")
        sim.write_mem(0xFFFFFFFF80000200, b"\x22")
        self.assertEqual(sim.read_mem(0x80000200, 1), b"\x22")

    def test_reset_restores_program(self):
        sim = Simulator()
        sim.stdout = io.StringIO()
        sim.load_elf(str(EXAMPLES / "riscv/hello_asm/hello_asm"))
        entry = sim.get_pc()
        original = sim.read_mem(entry, 64)
        self.assertEqual(run_to_end(sim), "syscall_exit")
        sim.reset()
        self.assertFalse(sim.exited)
        self.assertEqual(sim.get_pc(), entry)
        self.assertEqual(sim.read_mem(entry, 64), original)
        self.assertEqual(run_to_end(sim), "syscall_exit")
        self.assertEqual(sim.stdout.getvalue().count("Hello"), 2)

    def test_load_different_isa(self):
        """A simulator without a fixed ISA can load programs of any ISA"""
        sim = Simulator()
        sim.load_elf(str(EXAMPLES / "riscv/fibonacci/fibonacci"))
        sim.load_elf(str(EXAMPLES / "arm/fibonacci/fibonacci"))
        self.assertEqual(sim.get_isa(), ISA.ARM)


class TestConsole(unittest.TestCase):
    def setUp(self):
        self.console = MapacheSPIMConsole()
        self.out = io.StringIO()
        self.console.stdout = self.out

    def output(self) -> str:
        text = self.out.getvalue()
        self.out.truncate(0)
        self.out.seek(0)
        return text

    def test_step_performs_syscalls(self):
        """step used to skip syscalls, so nothing printed and exit was ignored"""
        self.console.sim.stdout = self.out
        self.console.onecmd(f"load {EXAMPLES / 'riscv/hello_asm/hello_asm'}")
        self.output()
        self.console.onecmd("step 100")
        text = self.output()
        self.assertIn("Hello", text)
        self.assertIn("Program exited with code 0", text)
        self.assertNotIn("Error", text)

        self.console.onecmd("step")
        self.assertIn("has exited", self.output())

    def test_x86_disasm_uses_instruction_sizes(self):
        self.console.onecmd(f"load {EXAMPLES / 'x86_64/hello_asm/hello_asm'}")
        self.output()
        self.console.onecmd("disasm pc 3")
        text = self.output()
        self.assertIn("[0x00400000]> lea", text)
        self.assertIn("[0x00400007]  mov", text)
        self.assertIn("[0x0040000e]  syscall", text)

    def test_reset_command(self):
        self.console.onecmd(f"load {EXAMPLES / 'riscv/fibonacci/fibonacci'}")
        entry = self.console.sim.get_pc()
        self.console.onecmd("step 5")
        self.console.onecmd("reset")
        self.assertEqual(self.console.sim.get_pc(), entry)
        self.assertIn("Reset", self.output())

    def test_run_error_shows_reason(self):
        self.console.onecmd(f"load {EXAMPLES / 'riscv/fibonacci/fibonacci'}")
        self.console.sim.set_pc(0x10)
        self.output()
        self.console.onecmd("run")
        self.assertIn("Instruction fetch from unmapped address 0x10", self.output())

    def test_regs_decimal_is_signed(self):
        self.console.onecmd(f"load {EXAMPLES / 'riscv/fibonacci/fibonacci'}")
        self.console.sim.set_reg(5, (-7) & 0xFFFFFFFFFFFFFFFF)
        self.output()
        self.console.onecmd("regs decimal")
        self.assertIn("..................-7", self.output())

    def test_show_changes_off(self):
        self.console.onecmd(f"load {EXAMPLES / 'riscv/fibonacci/fibonacci'}")
        self.console.onecmd("regs")
        self.console.onecmd("step 3")
        self.console.onecmd("set show-changes off")
        self.output()
        self.console.onecmd("regs")
        self.assertNotIn("★", self.output())

    def test_break_and_delete_by_symbol(self):
        self.console.onecmd(f"load {EXAMPLES / 'riscv/fibonacci/fibonacci'}")
        self.console.onecmd("break fibonacci")
        self.assertEqual(len(self.console.breakpoints), 1)
        self.console.onecmd("delete fibonacci")
        self.assertEqual(len(self.console.breakpoints), 0)

    def test_complete_set_includes_output_spacing(self):
        self.assertIn("output-spacing", self.console.complete_set("out", "set out", 4, 7))


if __name__ == "__main__":
    unittest.main()


class TestAssemblerDirectives(unittest.TestCase):
    """Directive bugs found by comparing against GNU as."""

    def assemble(self, source, isa="riscv64"):
        from mapachespim.toolchain import assemble

        return assemble(source, isa=isa)

    def section(self, result, name):
        from io import BytesIO

        from elftools.elf.elffile import ELFFile

        found = ELFFile(BytesIO(result.elf_bytes)).get_section_by_name(name)
        return found.data() if found is not None else None

    def test_undefined_symbol_in_data_is_an_error(self):
        """Unknown values in .word used to become 0 silently."""
        result = self.assemble(".text\n_start: nop\n.data\nx: .word no_such_label\n")
        self.assertFalse(result.success)
        self.assertIn("Line 4", result.errors[0])
        self.assertIn("no_such_label", result.errors[0])

    def test_bad_directive_values_are_errors(self):
        for line in (".space oops", ".align", ".word 1 +", '.ascii "\\x"', ".word 1/0"):
            with self.subTest(line=line):
                result = self.assemble(f".text\n_start: nop\n.data\n{line}\n")
                self.assertFalse(result.success, line)

    def test_label_in_data(self):
        result = self.assemble(".text\n_start: nop\n.data\na: .word 7\nptr: .word a\n")
        self.assertTrue(result.success, result.errors)
        data = self.section(result, ".data")
        self.assertEqual(int.from_bytes(data[4:8], "little"), result.symbols["a"])

    def test_custom_section_contents_are_kept(self):
        """Custom sections got addresses but were not written to the ELF."""
        result = self.assemble('.text\n_start: nop\n.section .mydata\nv: .word 0x1234\n')
        self.assertTrue(result.success, result.errors)
        self.assertEqual(self.section(result, ".mydata"), (0x1234).to_bytes(4, "little"))

    def test_mips_data_is_big_endian_without_isa_directive(self):
        result = self.assemble(".text\n_start: nop\n.data\nx: .word 0x11223344\n", "mips32")
        self.assertEqual(self.section(result, ".data"), bytes.fromhex("11223344"))

    def test_set_noreorder(self):
        result = self.assemble(
            ".set noreorder\n.text\n_start:\n  b _start\n  addiu $t0, $t0, 1\n", "mips32"
        )
        self.assertTrue(result.success, result.errors)
        self.assertEqual(len(self.section(result, ".text")), 8)  # no delay-slot nop added
