"""
Tests for the built-in pure-Python RISC-V encoder.

Encodings are checked by disassembling them with Capstone (an independent
implementation), and li sequences are checked by executing them in Unicorn.
"""

import unittest

from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, Cs

from mapachespim import ISA, Simulator
from mapachespim.toolchain import Assembler
from mapachespim.toolchain.riscv import RISCVEncodeError, encode, instruction_size

PC = 0x80000000
LABELS = {
    "target": PC + 0x40,
    "back": PC - 0x20,
    "msg": 0x80100010,
    "CONST": 42,
    "SMALL": 0x12345678,
}

_cs = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)


def disasm(code: bytes, addr: int = PC):
    return [f"{i.mnemonic} {i.op_str}".strip() for i in _cs.disasm(code, addr)]


class TestInstructionForms(unittest.TestCase):
    """Each (source, expected Capstone text) pair round-trips."""

    CASES = [
        # R-type
        ("add a0, a1, a2", "add a0, a1, a2"),
        ("sub t0, t1, t2", "sub t0, t1, t2"),
        ("sll s0, s1, s2", "sll s0, s1, s2"),
        ("slt a0, a1, a2", "slt a0, a1, a2"),
        ("sltu a0, a1, a2", "sltu a0, a1, a2"),
        ("xor a0, a1, a2", "xor a0, a1, a2"),
        ("srl a0, a1, a2", "srl a0, a1, a2"),
        ("sra a0, a1, a2", "sra a0, a1, a2"),
        ("or a0, a1, a2", "or a0, a1, a2"),
        ("and a0, a1, a2", "and a0, a1, a2"),
        ("addw a0, a1, a2", "addw a0, a1, a2"),
        ("subw a0, a1, a2", "subw a0, a1, a2"),
        ("sllw a0, a1, a2", "sllw a0, a1, a2"),
        ("srlw a0, a1, a2", "srlw a0, a1, a2"),
        ("sraw a0, a1, a2", "sraw a0, a1, a2"),
        ("mul a0, a1, a2", "mul a0, a1, a2"),
        ("mulh a0, a1, a2", "mulh a0, a1, a2"),
        ("mulhsu a0, a1, a2", "mulhsu a0, a1, a2"),
        ("mulhu a0, a1, a2", "mulhu a0, a1, a2"),
        ("div a0, a1, a2", "div a0, a1, a2"),
        ("divu a0, a1, a2", "divu a0, a1, a2"),
        ("rem a0, a1, a2", "rem a0, a1, a2"),
        ("remu a0, a1, a2", "remu a0, a1, a2"),
        ("mulw a0, a1, a2", "mulw a0, a1, a2"),
        ("divw a0, a1, a2", "divw a0, a1, a2"),
        ("divuw a0, a1, a2", "divuw a0, a1, a2"),
        ("remw a0, a1, a2", "remw a0, a1, a2"),
        ("remuw a0, a1, a2", "remuw a0, a1, a2"),
        # Register names
        ("add x5, x6, x7", "add t0, t1, t2"),
        ("add fp, s0, zero", "add s0, s0, zero"),
        # I-type
        ("addi a0, a1, -2048", "addi a0, a1, -0x800"),
        ("addi a0, a1, 2047", "addi a0, a1, 0x7ff"),
        ("slti a0, a1, 5", "slti a0, a1, 5"),
        ("sltiu a0, a1, 5", "sltiu a0, a1, 5"),
        ("xori a0, a1, -1", "not a0, a1"),
        ("ori a0, a1, 0xff", "ori a0, a1, 0xff"),
        ("andi a0, a1, 15", "andi a0, a1, 0xf"),
        ("addiw a0, a1, 3", "addiw a0, a1, 3"),
        ("slli a0, a1, 63", "slli a0, a1, 0x3f"),
        ("srli a0, a1, 1", "srli a0, a1, 1"),
        ("srai a0, a1, 40", "srai a0, a1, 0x28"),
        ("slliw a0, a1, 31", "slliw a0, a1, 0x1f"),
        ("srliw a0, a1, 2", "srliw a0, a1, 2"),
        ("sraiw a0, a1, 2", "sraiw a0, a1, 2"),
        ("addi a0, a0, CONST", "addi a0, a0, 0x2a"),
        ("addi a0, a0, 'A'", "addi a0, a0, 0x41"),
        ("add a0, a1, 5", "addi a0, a1, 5"),
        ("sll a0, a1, 3", "slli a0, a1, 3"),
        # Loads / stores
        ("lb a0, 0(sp)", "lb a0, 0(sp)"),
        ("lh a0, -2(sp)", "lh a0, -2(sp)"),
        ("lw a0, 4(a1)", "lw a0, 4(a1)"),
        ("ld a0, 8(a1)", "ld a0, 8(a1)"),
        ("lbu a0, (a1)", "lbu a0, 0(a1)"),
        ("lhu a0, 2(a1)", "lhu a0, 2(a1)"),
        ("lwu a0, 4(a1)", "lwu a0, 4(a1)"),
        ("sb a0, 0(sp)", "sb a0, 0(sp)"),
        ("sh a0, 2(sp)", "sh a0, 2(sp)"),
        ("sw a0, -4(sp)", "sw a0, -4(sp)"),
        ("sd ra, 2040(sp)", "sd ra, 0x7f8(sp)"),
        # Branches and jumps (Capstone prints branch targets as pc-relative offsets)
        ("beq a0, a1, target", "beq a0, a1, 0x40"),
        ("bne a0, a1, back", "bne a0, a1, -0x20"),
        ("blt a0, a1, target", "blt a0, a1, 0x40"),
        ("bge a0, a1, target", "bge a0, a1, 0x40"),
        ("bltu a0, a1, target", "bltu a0, a1, 0x40"),
        ("bgeu a0, a1, target", "bgeu a0, a1, 0x40"),
        ("jal ra, target", "jal 0x40"),
        ("jal target", "jal 0x40"),
        ("jalr ra, t0, 0", "jalr t0"),
        ("jalr t0", "jalr t0"),
        ("jalr ra, 8(t0)", "jalr ra, t0, 8"),
        # Upper immediates
        ("lui a0, 0x12345", "lui a0, 0x12345"),
        ("lui a0, %hi(SMALL)", "lui a0, 0x12345"),
        ("addi a0, a0, %lo(msg)", "addi a0, a0, 0x10"),
        ("auipc a0, 1", "auipc a0, 1"),
        # System
        ("ecall", "ecall"),
        ("ebreak", "ebreak"),
        ("fence", "fence"),
        ("csrrs a0, cycle, zero", "rdcycle a0"),
        ("csrr a0, mhartid", "csrr a0, mhartid"),
        # Pseudo-instructions
        ("nop", "nop"),
        ("mv a0, a1", "mv a0, a1"),
        ("not a0, a1", "not a0, a1"),
        ("neg a0, a1", "neg a0, a1"),
        ("negw a0, a1", "negw a0, a1"),
        ("sext.w a0, a1", "sext.w a0, a1"),
        ("seqz a0, a1", "seqz a0, a1"),
        ("snez a0, a1", "snez a0, a1"),
        ("sltz a0, a1", "sltz a0, a1"),
        ("sgtz a0, a1", "sgtz a0, a1"),
        ("beqz a0, target", "beqz a0, 0x40"),
        ("bnez a0, target", "bnez a0, 0x40"),
        ("bltz a0, target", "bltz a0, 0x40"),
        ("bgez a0, target", "bgez a0, 0x40"),
        ("blez a0, target", "blez a0, 0x40"),
        ("bgtz a0, target", "bgtz a0, 0x40"),
        ("bgt a0, a1, target", "blt a1, a0, 0x40"),
        ("ble a0, a1, target", "bge a1, a0, 0x40"),
        ("bgtu a0, a1, target", "bltu a1, a0, 0x40"),
        ("bleu a0, a1, target", "bgeu a1, a0, 0x40"),
        ("j target", "j 0x40"),
        ("jr ra", "ret"),
        ("ret", "ret"),
    ]

    def test_forms(self):
        for source, expected in self.CASES:
            with self.subTest(source=source):
                code = encode(source, PC, LABELS)
                self.assertEqual(len(code), 4)
                self.assertEqual(disasm(code), [expected])
                self.assertEqual(instruction_size(source, LABELS), 4)

    def test_call_and_tail_use_auipc_jalr(self):
        # Like GNU as: always two instructions, so any address is reachable
        self.assertEqual(disasm(encode("call target", PC, LABELS)), ["auipc ra, 0", "jalr ra, ra, 0x40"])
        self.assertEqual(disasm(encode("tail target", PC, LABELS)), ["auipc t1, 0", "jalr zero, t1, 0x40"])

    def test_far_branch_is_relaxed(self):
        far = {"far": PC + 0x10000}
        self.assertEqual(disasm(encode("beq a0, a1, far", PC, far)), ["bne a0, a1, 8", "j 0xfffc"])

    def test_la_is_pc_relative(self):
        code = encode("la a0, msg", PC, LABELS)
        self.assertEqual(disasm(code), ["auipc a0, 0x100", "addi a0, a0, 0x10"])

    def test_load_from_symbol(self):
        code = encode("lw a0, msg", PC, LABELS)
        self.assertEqual(disasm(code), ["auipc a0, 0x100", "lw a0, 0x10(a0)"])

    def test_store_to_symbol(self):
        code = encode("sw a0, msg, t0", PC, LABELS)
        self.assertEqual(disasm(code), ["auipc t0, 0x100", "sw a0, 0x10(t0)"])

    def test_symbol_arithmetic(self):
        code = encode("la a0, msg+4", PC, LABELS)
        self.assertEqual(disasm(code), ["auipc a0, 0x100", "addi a0, a0, 0x14"])


class TestErrors(unittest.TestCase):
    CASES = [
        ("addi a0, a1, 2048", "out of range"),
        ("addi a0, a1", "expected"),
        ("add a0, a1, q9", "unknown register"),
        ("frob a0", "unknown instruction"),
        ("beq a0, a1, nowhere", "undefined symbol"),
        ("slli a0, a0, 64", "out of range"),
        ("ecall a0", "takes no operands"),
        ("lui a0, %hi(msg)", "out of range"),
    ]

    def test_errors(self):
        for source, message in self.CASES:
            with self.subTest(source=source):
                with self.assertRaises(RISCVEncodeError) as cm:
                    encode(source, PC, LABELS)
                self.assertIn(message, str(cm.exception))

    def test_assembler_reports_line(self):
        result = Assembler("riscv64").assemble(".text\n_start:\n  addi a0, a1, 5000\n")
        self.assertFalse(result.success)
        self.assertIn("Line 3", result.errors[0])


class TestLoadImmediate(unittest.TestCase):
    """li must produce the exact 64-bit value, verified by executing it."""

    VALUES = [
        0, 1, -1, 2047, -2048, 2048, -2049, 0x7FF, 0x800, 0xFFF, 0x1000,
        0x12345, 0x12345678, 0x7FFFFFFF, -0x80000000, 0x80000000, 0xFFFFFFFF,
        0x100000000, 0x123456789, -0x123456789, 0x7FFFFFFFFFFFFFFF,
        -0x8000000000000000, 0xDEADBEEFCAFEBABE, 0x8000000000000000,
        0x0000080000000800, 0x00FF00FF00FF00FF,
    ]  # fmt: skip

    def test_values(self):
        for value in self.VALUES:
            with self.subTest(value=hex(value)):
                code = encode(f"li t0, {value}", PC, {})
                self.assertEqual(len(code), instruction_size(f"li t0, {value}", {}))
                sim = Simulator(ISA.RISCV)
                sim.write_mem(PC, code)
                sim.set_pc(PC)
                for _ in range(len(code) // 4):
                    sim.step()
                self.assertEqual(sim.get_reg(5), value & 0xFFFFFFFFFFFFFFFF)

    def test_small_li_is_one_instruction(self):
        self.assertEqual(disasm(encode("li a0, 42", PC, {})), ["addi a0, zero, 0x2a"])


class TestProgram(unittest.TestCase):
    def test_forward_references_and_constants(self):
        source = """
        .equ BIG, 0x12345678
        .text
        .globl _start
        _start:
            li t0, BIG
            j skip
            li t1, 99
        skip:
            la a0, msg
            call func
            li a7, 10
            ecall
        func:
            ret
        .data
        msg: .asciz "hi"
        """
        result = Assembler("riscv64").assemble(source)
        self.assertTrue(result.success, result.errors)
        # li BIG is lui+addiw, so 'skip' is at +16
        self.assertEqual(result.symbols["skip"] - result.symbols["_start"], 16)


if __name__ == "__main__":
    unittest.main()
