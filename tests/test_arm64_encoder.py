"""
Unit tests for the built-in ARM64 encoder that complement the GNU
differential tests (test_differential_arm64.py), which need binutils.
"""

import unittest

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from mapachespim.toolchain import assemble
from mapachespim.toolchain.arm64 import ARM64EncodeError, encode, encode_bitmask

PC = 0x10000000
_cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def decode_bitmask(n: int, immr: int, imms: int, bits: int):
    """Reference DecodeBitMasks from the Arm Architecture Reference Manual."""
    combined = (n << 6) | (~imms & 0x3F)
    if combined == 0:
        return None
    length = combined.bit_length() - 1
    size = 1 << length
    if size > bits or size < 2:
        return None
    levels = size - 1
    s, r = imms & levels, immr & levels
    if s == levels:
        return None
    elem = (1 << (s + 1)) - 1
    elem = ((elem >> r) | (elem << (size - r))) & ((1 << size) - 1)
    value = 0
    for i in range(bits // size):
        value |= elem << (i * size)
    return value


class TestBitmaskImmediates(unittest.TestCase):
    def test_every_encodable_value_round_trips(self):
        """Decode every (N, immr, imms) and check we choose that encoding back."""
        for bits in (32, 64):
            seen = 0
            for n in (0, 1) if bits == 64 else (0,):
                for immr in range(64):
                    for imms in range(64):
                        value = decode_bitmask(n, immr, imms, bits)
                        if value is None or (bits == 32 and immr >= 32):
                            continue
                        enc = encode_bitmask(value, bits)
                        self.assertIsNotNone(enc, hex(value))
                        self.assertEqual(decode_bitmask(*enc, bits), value)
                        seen += 1
            # There are 5334 distinct 64-bit and 1302 32-bit logical immediates
            self.assertGreater(seen, 1000)

    def test_unencodable_values(self):
        for value in (0, 0xFFFFFFFFFFFFFFFF, 5, 0x123456789):
            self.assertIsNone(encode_bitmask(value, 64))


class TestExamplesOfUse(unittest.TestCase):
    def disasm(self, text):
        code = encode(text, PC, {"label": PC + 0x40})
        return [f"{i.mnemonic} {i.op_str}" for i in _cs.disasm(code, PC)]

    def test_common_student_instructions(self):
        cases = {
            "stp x29, x30, [sp, #-16]!": "stp x29, x30, [sp, #-0x10]!",
            "mov x29, sp": "mov x29, sp",
            "mov x0, #42": "mov x0, #0x2a",
            "add x0, x0, #1": "add x0, x0, #1",
            "cmp x0, #10": "cmp x0, #0xa",
            "b.lt label": "b.lt #0x10000040",
            "ldr w1, [x0, x2, lsl #2]": "ldr w1, [x0, x2, lsl #2]",
            "svc #0": "svc #0",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(self.disasm(source), [expected])

    def test_helpful_errors(self):
        for source, message in {
            "mov x0, #0x123456789": "ldr x0, =0x123456789",
            "add x0, x1, w2": "X registers",
            "adr x0, far": "out of range",
            "ldr x0, [x1, #3]!x": "expected",
        }.items():
            with self.subTest(source=source):
                with self.assertRaises(ARM64EncodeError) as cm:
                    encode(source, PC, {"far": PC + 0x200000})
                self.assertIn(message, str(cm.exception))

    def test_hash_comment_hint(self):
        """'#' after code is not a comment in ARM assembly (use //)."""
        result = assemble(".text\n_start:\n  mov x0, #1  # one\n", isa="arm64")
        self.assertFalse(result.success)


class TestLiteralPool(unittest.TestCase):
    def test_ldr_equals_loads_the_value(self):
        from mapachespim import ISA, Simulator

        result = assemble(
            ".text\n_start:\n  ldr x0, =0x123456789abcdef0\n  ldr w1, =7\n"
            "  ldr x2, =value\n  mov x8, #10\n  svc #0\n.data\nvalue: .word 5\n",
            isa="arm64",
        )
        self.assertTrue(result.success, result.errors)
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(result.elf_bytes)
        try:
            sim = Simulator(ISA.ARM)
            sim.load_elf(f.name)
            for _ in range(5):
                if sim.check_termination(sim.step())[0]:
                    break
            self.assertEqual(sim.get_reg(0), 0x123456789ABCDEF0)
            self.assertEqual(sim.get_reg(1), 7)
            self.assertEqual(sim.get_reg(2), result.symbols["value"])
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
