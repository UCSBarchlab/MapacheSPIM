"""Capstone-based disassembly for every registered ISA."""

from __future__ import annotations

from typing import Tuple

from capstone import Cs

from .engines import engine_for
from .isa import ISASpec


class Disassembler:
    """Disassembles one instruction at a time from raw bytes."""

    def __init__(self, spec: ISASpec) -> None:
        engine = engine_for(spec)
        self._spec = spec
        self._cs = Cs(engine.cs_arch, engine.cs_mode)
        self._cs.detail = False  # We don't need detailed instruction info

    @property
    def max_size(self) -> int:
        """Bytes needed to be sure of decoding any one instruction."""
        return self._spec.max_instruction_size

    def disassemble(self, code: bytes, addr: int) -> Tuple[str, int]:
        """
        Disassemble the instruction at the start of ``code`` (located at ``addr``).

        Returns:
            (text, size). Bytes that do not decode are shown as ``.word`` (for
            fixed-width ISAs) or ``.byte`` (for variable-length ones), with the
            size of that unit, so callers walking a range always advance.
        """
        spec = self._spec
        if len(code) < spec.min_instruction_size:
            return ("<invalid address>", spec.min_instruction_size)

        for instr in self._cs.disasm(code, addr, count=1):
            return (f"{instr.mnemonic} {instr.op_str}".strip(), instr.size)

        if spec.fixed_width:
            size = spec.min_instruction_size
            word = int.from_bytes(code[:size], spec.byteorder)
            return (f".word 0x{word:0{2 * size}x}", size)
        return (f".byte 0x{code[0]:02x}", 1)
