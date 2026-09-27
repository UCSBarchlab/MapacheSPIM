"""
Differential tests for alignment and data in code: random mixes of
instructions, data directives, and .p2align/.balign (with fill and
max-skip arguments) must assemble to the same bytes as GNU as.

GNU's padding rules differ by ISA: x86-64 pads with multi-byte nops (and a
jump over long runs, and a one-byte nop first after data), ARM64 pads with
zeros up to 4 bytes then nops and aligns an instruction that follows data,
RISC-V pads with nops, and MIPS with zeros.
"""

import random

import pytest

from .gnu_reference import FUZZ_SCALE, gnu_assemble, gnu_available, ours_text, trim_padding

ISAS = [isa for isa in ("x86_64", "arm64", "riscv64", "mips32") if gnu_available(isa)]
pytestmark = pytest.mark.skipif(not ISAS, reason="GNU binutils not installed")

INSTRUCTION = {"x86_64": "ret", "arm64": "nop", "riscv64": "nop", "mips32": "nop"}


def random_program(isa: str, rng: random.Random) -> str:
    # GNU as leaves RISC-V instructions misaligned after odd-sized data, so
    # RISC-V programs only use data in whole words
    unit = 4 if isa == "riscv64" else 1
    lines = ["_start:"]
    for _ in range(rng.randint(1, 8)):
        kind = rng.random()
        if kind < 0.35:
            lines.append(INSTRUCTION[isa])
        elif kind < 0.6:
            values = [str(rng.randint(0, 255)) for _ in range(rng.randint(1, 5) * unit)]
            lines.append(".byte " + ", ".join(values))
        elif kind < 0.7:
            lines.append(f".fill {rng.randint(0, 200 // unit) * unit}, 1, 0xcc")
        else:
            log2 = rng.randint(0, 8)
            directive = rng.choice(["p2align", "balign"])
            value = log2 if directive == "p2align" else 1 << log2
            extra = rng.choice(
                ["", ", 0x90", ", 0", f",, {rng.randint(0, 300)}", f", 0x90, {rng.randint(0, 300)}"]
            )
            lines.append(f".{directive} {value}{extra}")
    lines.append(INSTRUCTION[isa])
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("isa", ISAS)
def test_alignment_and_data_in_code(isa):
    rng = random.Random(1)
    for _ in range(25 * FUZZ_SCALE):
        source = random_program(isa, rng)
        ours, errors, _ = ours_text(isa, source)
        assert not errors, (source, errors)
        gnu = trim_padding(gnu_assemble(isa, source), ours)
        assert ours == gnu, f"\n{source}\nours {ours.hex()}\ngnu  {gnu.hex()}"
