"""
Tests for the built-in pure-Python MIPS32 encoder.

Encodings are checked with Capstone, and pseudo-instructions whose expansion
is easy to get wrong (li, compare-branches, div/rem, abs) are checked by
executing them in Unicorn.
"""

import itertools
import unittest

from capstone import CS_ARCH_MIPS, CS_MODE_BIG_ENDIAN, CS_MODE_MIPS32, Cs

from mapachespim import ISA, Simulator
from mapachespim.toolchain import Assembler
from mapachespim.toolchain.mips import MIPSEncodeError, encode, instruction_size

PC = 0x00400000
LABELS = {"target": PC + 0x40, "back": PC - 0x20, "msg": 0x10000024, "CONST": 42}

_cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)


def disasm(code: bytes, addr: int = PC):
    return [f"{i.mnemonic} {i.op_str}".strip() for i in _cs.disasm(code, addr)]


class TestInstructionForms(unittest.TestCase):
    CASES = [
        # (source, expected Capstone output lines)
        ("add $t0, $t1, $t2", ["add $t0, $t1, $t2"]),
        ("addu $v0, $a0, $a1", ["addu $v0, $a0, $a1"]),
        ("sub $t0, $t1, $t2", ["sub $t0, $t1, $t2"]),
        ("subu $t0, $t1, $t2", ["subu $t0, $t1, $t2"]),
        ("and $t0, $t1, $t2", ["and $t0, $t1, $t2"]),
        ("or $t0, $t1, $t2", ["or $t0, $t1, $t2"]),
        ("xor $t0, $t1, $t2", ["xor $t0, $t1, $t2"]),
        ("nor $t0, $t1, $t2", ["nor $t0, $t1, $t2"]),
        ("slt $t0, $t1, $t2", ["slt $t0, $t1, $t2"]),
        ("sltu $t0, $t1, $t2", ["sltu $t0, $t1, $t2"]),
        ("add $8, $9, $10", ["add $t0, $t1, $t2"]),
        ("add $s8, $fp, $zero", ["add $fp, $fp, $zero"]),
        ("sll $t0, $t1, 4", ["sll $t0, $t1, 4"]),
        ("srl $t0, $t1, 31", ["srl $t0, $t1, 0x1f"]),
        ("sra $t0, $t1, 2", ["sra $t0, $t1, 2"]),
        ("sllv $t0, $t1, $t2", ["sllv $t0, $t1, $t2"]),
        ("srlv $t0, $t1, $t2", ["srlv $t0, $t1, $t2"]),
        ("srav $t0, $t1, $t2", ["srav $t0, $t1, $t2"]),
        ("mult $t0, $t1", ["mult $t0, $t1"]),
        ("multu $t0, $t1", ["multu $t0, $t1"]),
        ("div $t0, $t1", ["div $zero, $t0, $t1"]),
        ("divu $t0, $t1", ["divu $zero, $t0, $t1"]),
        ("mfhi $t0", ["mfhi $t0"]),
        ("mflo $t0", ["mflo $t0"]),
        ("mthi $t0", ["mthi $t0"]),
        ("mtlo $t0", ["mtlo $t0"]),
        ("mul $t0, $t1, $t2", ["mul $t0, $t1, $t2"]),
        ("madd $t0, $t1", ["madd $t0, $t1"]),
        ("clz $t0, $t1", ["clz $t0, $t1"]),
        ("addi $sp, $sp, -4", ["addi $sp, $sp, -4"]),
        ("addiu $t0, $zero, 32767", ["addiu $t0, $zero, 0x7fff"]),
        ("slti $t0, $t1, 5", ["slti $t0, $t1, 5"]),
        ("sltiu $t0, $t1, 5", ["sltiu $t0, $t1, 5"]),
        ("andi $t0, $t1, 0xffff", ["andi $t0, $t1, 0xffff"]),
        ("ori $t0, $t1, 1", ["ori $t0, $t1, 1"]),
        ("xori $t0, $t1, 1", ["xori $t0, $t1, 1"]),
        ("lui $t0, 0x1000", ["lui $t0, 0x1000"]),
        ("addi $t0, $t0, CONST", ["addi $t0, $t0, 0x2a"]),
        ("add $t0, $t1, 5", ["addi $t0, $t1, 5"]),
        ("lw $t0, 0($sp)", ["lw $t0, ($sp)"]),
        ("lw $t0, ($sp)", ["lw $t0, ($sp)"]),
        ("lb $t0, -1($a0)", ["lb $t0, -1($a0)"]),
        ("lbu $t0, 1($a0)", ["lbu $t0, 1($a0)"]),
        ("lh $t0, 2($a0)", ["lh $t0, 2($a0)"]),
        ("lhu $t0, 2($a0)", ["lhu $t0, 2($a0)"]),
        ("sw $ra, 4($sp)", ["sw $ra, 4($sp)"]),
        ("sb $t0, 0($a0)", ["sb $t0, ($a0)"]),
        ("sh $t0, 0($a0)", ["sh $t0, ($a0)"]),
        # Like GNU as, a load uses its own destination as the temporary
        ("lw $t0, msg", ["lui $t0, 0x1000", "lw $t0, 0x24($t0)"]),
        ("sw $t0, msg", ["lui $at, 0x1000", "sw $t0, 0x24($at)"]),
        ("syscall", ["syscall"]),
        ("break", ["break"]),
        ("nop", ["nop"]),
        # Branches and jumps carry a delay-slot nop
        ("beq $t0, $t1, target", ["beq $t0, $t1, 0x400040", "nop"]),
        ("bne $t0, $t1, back", ["bne $t0, $t1, 0x3fffe0", "nop"]),
        ("blez $t0, target", ["blez $t0, 0x400040", "nop"]),
        ("bgtz $t0, target", ["bgtz $t0, 0x400040", "nop"]),
        ("bltz $t0, target", ["bltz $t0, 0x400040", "nop"]),
        ("bgez $t0, target", ["bgez $t0, 0x400040", "nop"]),
        ("beqz $t0, target", ["beqz $t0, 0x400040", "nop"]),
        ("bnez $t0, target", ["bnez $t0, 0x400040", "nop"]),
        ("b target", ["b 0x400040", "nop"]),
        ("j target", ["j 0x400040", "nop"]),
        ("jal target", ["jal 0x400040", "nop"]),
        ("jr $ra", ["jr $ra", "nop"]),
        ("jalr $t9", ["jalr $t9", "nop"]),
        # Pseudo-instructions
        ("move $a0, $s0", ["move $a0, $s0"]),
        ("li $v0, 10", ["addiu $v0, $zero, 0xa"]),
        ("li $t0, -1", ["addiu $t0, $zero, -1"]),
        ("li $t0, 0xffff", ["ori $t0, $zero, 0xffff"]),
        ("li $t0, 0x10000", ["lui $t0, 1"]),
        ("li $t0, 0x12345678", ["lui $t0, 0x1234", "ori $t0, $t0, 0x5678"]),
        ("la $a0, msg", ["lui $a0, 0x1000", "addiu $a0, $a0, 0x24"]),
        ("not $t0, $t1", ["not $t0, $t1"]),
        ("neg $t0, $t1", ["neg $t0, $t1"]),
        ("blt $t0, $t1, target", ["slt $at, $t0, $t1", "bnez $at, 0x400040", "nop"]),
        ("bgt $t0, $t1, target", ["slt $at, $t1, $t0", "bnez $at, 0x400040", "nop"]),
        ("div $t0, $t1", ["div $zero, $t0, $t1"]),  # SPIM: the real instruction
        ("div $zero, $t1, $t2", ["div $zero, $t1, $t2"]),
        ("div $t0, $t1, 1", ["move $t0, $t1"]),
        ("rem $t0, $t1, 1", ["move $t0, $zero"]),
        ("mul $t0, $t1, 7", ["addiu $at, $zero, 7", "mult $t1, $at", "mflo $t0"]),
    ]

    def test_forms(self):
        for source, expected in self.CASES:
            with self.subTest(source=source):
                code = encode(source, PC, LABELS)
                self.assertEqual(disasm(code), expected)
                self.assertEqual(instruction_size(source, LABELS, PC), len(code))


class TestErrors(unittest.TestCase):
    CASES = [
        ("addi $t0, $t1, 40000", "out of range"),
        ("andi $t0, $t1, -1", "out of range"),
        ("add $t0, $t1", "expected"),
        ("add $t0, $t1, $q9", "unknown register"),
        ("add t0, t1, t2", "need a $"),
        ("frob $t0", "unknown instruction"),
        ("beq $t0, $t1, nowhere", "undefined symbol"),
        ("sll $t0, $t1, 32", "out of range"),
    ]

    def test_errors(self):
        for source, message in self.CASES:
            with self.subTest(source=source):
                with self.assertRaises(MIPSEncodeError) as cm:
                    encode(source, PC, LABELS)
                self.assertIn(message, str(cm.exception))


def run_snippet(source: str, regs: dict) -> Simulator:
    """Assemble `source` at PC, set registers, and run until it falls off the end."""
    sim = Simulator(ISA.MIPS)
    code = b""
    labels = {"end": PC + 4 * 64}
    for line in source.strip().splitlines():
        code += encode(line.strip(), PC + len(code), labels)
    labels["end"] = PC + len(code)
    code = b""
    for line in source.strip().splitlines():
        code += encode(line.strip(), PC + len(code), labels)
    sim.write_mem(PC, code)
    sim.set_pc(PC)
    for reg, value in regs.items():
        sim.set_reg(reg, value & 0xFFFFFFFF)
    for _ in range(64):
        if sim.get_pc() == labels["end"]:
            break
        sim.step()
    return sim


class TestExecution(unittest.TestCase):
    T0, T1, T2 = 8, 9, 10

    def test_li_values(self):
        for value in [0, 1, -1, 0x7FFF, -0x8000, 0x8000, 0xFFFF, 0x10000, 0x12345678,
                      0x7FFFFFFF, -0x80000000, 0xFFFFFFFF, 0xFFFF0000]:  # fmt: skip
            with self.subTest(value=hex(value)):
                sim = run_snippet(f"li $t0, {value}", {})
                self.assertEqual(sim.get_reg(self.T0), value & 0xFFFFFFFF)

    def test_compare_branches(self):
        values = [-5, -1, 0, 1, 5, 0x7FFFFFFF, -0x80000000]
        checks = {
            "blt": lambda a, b: a < b,
            "bgt": lambda a, b: a > b,
            "ble": lambda a, b: a <= b,
            "bge": lambda a, b: a >= b,
            "bltu": lambda a, b: (a & 0xFFFFFFFF) < (b & 0xFFFFFFFF),
            "bgtu": lambda a, b: (a & 0xFFFFFFFF) > (b & 0xFFFFFFFF),
            "bleu": lambda a, b: (a & 0xFFFFFFFF) <= (b & 0xFFFFFFFF),
            "bgeu": lambda a, b: (a & 0xFFFFFFFF) >= (b & 0xFFFFFFFF),
        }
        for op, check in checks.items():
            for a, b in itertools.product(values, repeat=2):
                with self.subTest(op=op, a=a, b=b):
                    # $t2 = 1 if the branch was taken, else 0
                    sim = run_snippet(
                        f"""
                        li $t2, 1
                        {op} $t0, $t1, end
                        li $t2, 0
                        """,
                        {self.T0: a, self.T1: b},
                    )
                    self.assertEqual(sim.get_reg(self.T2), int(check(a, b)))

    def test_division_traps(self):
        """div/rem check for division by zero and overflow, as SPIM does."""
        for source, regs, expected in [
            ("div $t2, $t0, $t1", {8: 7, 9: 0}, "Division by zero"),
            ("rem $t2, $t0, $t1", {8: 7, 9: 0}, "Division by zero"),
            ("divu $t2, $t0, $t1", {8: 7, 9: 0}, "Division by zero"),
            ("div $t2, $t0, $t1", {8: -0x80000000, 9: -1}, "overflow"),
        ]:
            with self.subTest(source=source, regs=regs):
                sim = Simulator(ISA.MIPS)
                code = encode(source, PC, {})
                sim.write_mem(PC, code)
                sim.set_pc(PC)
                for reg, value in regs.items():
                    sim.set_reg(reg, value & 0xFFFFFFFF)
                for _ in range(len(code) // 4):
                    if sim.check_termination(sim.step())[0]:
                        break
                self.assertIn(expected, sim.last_error or "")

    def test_div_rem_abs(self):
        sim = run_snippet(
            """
            div $t2, $t0, $t1
            rem $t3, $t0, $t1
            abs $t4, $t0
            """,
            {self.T0: -17, self.T1: 5},
        )
        self.assertEqual(sim.get_reg(10), (-3) & 0xFFFFFFFF)
        self.assertEqual(sim.get_reg(11), (-2) & 0xFFFFFFFF)
        self.assertEqual(sim.get_reg(12), 17)


class TestProgram(unittest.TestCase):
    def test_forward_references(self):
        source = """
        .text
        .globl _start
        _start:
            la $a0, msg
            blt $t0, $t1, skip
            li $t2, 0x12345678
        skip:
            jal func
            li $v0, 10
            syscall
        func:
            jr $ra
        .data
        msg: .asciiz "hi"
        """
        result = Assembler("mips32").assemble(source)
        self.assertTrue(result.success, result.errors)
        # la (lui + addiu) + blt (slt, bnez, nop) + li (lui + ori)
        self.assertEqual(result.symbols["skip"] - result.symbols["_start"], 28)


if __name__ == "__main__":
    unittest.main()
