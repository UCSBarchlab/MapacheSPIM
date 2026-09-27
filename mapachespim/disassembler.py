"""Capstone-based disassembly for every registered ISA."""

from __future__ import annotations

from typing import Optional, Tuple

from capstone import CS_ARCH_X86, CS_OPT_SYNTAX_ATT, Cs

from .engines import engine_for
from .isa import ISASpec


class Disassembler:
    """Disassembles one instruction at a time from raw bytes."""

    def __init__(self, spec: ISASpec) -> None:
        engine = engine_for(spec)
        self._spec = spec
        self._cs = Cs(engine.cs_arch, engine.cs_mode)
        self._cs.detail = False  # We don't need detailed instruction info
        self._cs_att: Optional[Cs] = None
        if engine.cs_arch == CS_ARCH_X86:
            self._cs_att = Cs(engine.cs_arch, engine.cs_mode)
            self._cs_att.detail = False
            self._cs_att.syntax = CS_OPT_SYNTAX_ATT

    @property
    def max_size(self) -> int:
        """Bytes needed to be sure of decoding any one instruction."""
        return self._spec.max_instruction_size

    def disassemble(self, code: bytes, addr: int, att: bool = False) -> Tuple[str, int]:
        """
        Disassemble the instruction at the start of ``code`` (located at ``addr``).

        On x86-64, ``att`` shows it in AT&T syntax (``movq $5, %rdi``) rather
        than Intel syntax (``mov rdi, 5``); other ISAs ignore it.

        Returns:
            (text, size). Bytes that do not decode are shown as ``.word`` (for
            fixed-width ISAs) or ``.byte`` (for variable-length ones), with the
            size of that unit, so callers walking a range always advance.
        """
        spec = self._spec
        if len(code) < spec.min_instruction_size:
            return ("<invalid address>", spec.min_instruction_size)

        cs = self._cs_att if att and self._cs_att is not None else self._cs
        for instr in cs.disasm(code, addr, count=1):
            return (f"{instr.mnemonic} {instr.op_str}".strip(), instr.size)

        if spec.fixed_width:
            size = spec.min_instruction_size
            word = int.from_bytes(code[:size], spec.byteorder)
            return (f".word 0x{word:0{2 * size}x}", size)
        return (f".byte 0x{code[0]:02x}", 1)
