"""
Unicorn (emulation) and Capstone (disassembly) settings for each ISA.

These are the only emulator-specific facts about an ISA; everything else is
in :mod:`mapachespim.isa`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

try:
    import unicorn
    from unicorn import arm64_const, mips_const, riscv_const, x86_const
except ImportError as e:
    raise ImportError(
        f"Unicorn Engine not installed. Install with: pip install unicorn\nOriginal error: {e}"
    )

try:
    import capstone
except ImportError as e:
    raise ImportError(
        f"Capstone not installed. Install with: pip install capstone\nOriginal error: {e}"
    )

from .isa import ISA, ISASpec, get_spec


@dataclass(frozen=True)
class EngineBinding:
    """How to emulate and disassemble one ISA."""

    uc_arch: int
    uc_mode: int
    pc_reg: int
    sp_reg: int
    gpr_regs: Tuple[int, ...]
    """Unicorn register constant for each general-purpose register, by number.

    Looked up by name: Unicorn's constants are not always consecutive."""

    cs_arch: int
    cs_mode: int


ENGINES: Dict[ISA, EngineBinding] = {
    ISA.RISCV: EngineBinding(
        uc_arch=unicorn.UC_ARCH_RISCV,
        uc_mode=unicorn.UC_MODE_RISCV64,
        pc_reg=riscv_const.UC_RISCV_REG_PC,
        sp_reg=riscv_const.UC_RISCV_REG_SP,
        gpr_regs=tuple(getattr(riscv_const, f"UC_RISCV_REG_X{n}") for n in range(32)),
        cs_arch=capstone.CS_ARCH_RISCV,
        cs_mode=capstone.CS_MODE_RISCV64,
    ),
    ISA.MIPS: EngineBinding(
        uc_arch=unicorn.UC_ARCH_MIPS,
        uc_mode=unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN,
        pc_reg=mips_const.UC_MIPS_REG_PC,
        sp_reg=mips_const.UC_MIPS_REG_SP,
        gpr_regs=tuple(getattr(mips_const, f"UC_MIPS_REG_{n}") for n in range(32)),
        cs_arch=capstone.CS_ARCH_MIPS,
        cs_mode=capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    ISA.ARM: EngineBinding(
        uc_arch=unicorn.UC_ARCH_ARM64,
        uc_mode=unicorn.UC_MODE_ARM,
        pc_reg=arm64_const.UC_ARM64_REG_PC,
        sp_reg=arm64_const.UC_ARM64_REG_SP,
        # Unicorn numbers x0-x28 consecutively but x29 (fp) and x30 (lr)
        # separately, so look each one up by name
        gpr_regs=tuple(getattr(arm64_const, f"UC_ARM64_REG_X{n}") for n in range(31))
        + (arm64_const.UC_ARM64_REG_SP,),
        cs_arch=capstone.CS_ARCH_ARM64,
        cs_mode=capstone.CS_MODE_ARM,
    ),
    ISA.X86_64: EngineBinding(
        uc_arch=unicorn.UC_ARCH_X86,
        uc_mode=unicorn.UC_MODE_64,
        pc_reg=x86_const.UC_X86_REG_RIP,
        sp_reg=x86_const.UC_X86_REG_RSP,
        gpr_regs=tuple(
            getattr(x86_const, f"UC_X86_REG_{name.upper()}")
            for name in get_spec(ISA.X86_64).registers.names
        ),
        cs_arch=capstone.CS_ARCH_X86,
        cs_mode=capstone.CS_MODE_64,
    ),
}


def engine_for(spec: ISASpec) -> EngineBinding:
    """The engine binding for an ISA."""
    try:
        return ENGINES[spec.isa]
    except KeyError:
        raise ValueError(f"No emulator binding for {spec.display_name}")
