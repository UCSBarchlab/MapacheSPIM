"""The ISA registry is complete and consistent, and every layer uses it."""

import pytest

from mapachespim.engines import ENGINES, engine_for
from mapachespim.examples import ISA_DIRS, examples_dir, list_examples
from mapachespim.isa import (
    ISA,
    ISA_SPECS,
    canonical_isa,
    find_spec,
    get_spec,
    isa_names,
    spec_for_elf,
)
from mapachespim.memory_map import get_layout
from mapachespim.toolchain.directives import DirectiveParser, find_isa_directive
from mapachespim.toolchain.targets import TARGETS

SPECS = pytest.mark.parametrize("spec", ISA_SPECS, ids=lambda spec: spec.name)


def test_every_isa_enum_member_has_a_spec():
    members = {isa for isa in ISA if isa != ISA.UNKNOWN}
    assert members == {spec.isa for spec in ISA_SPECS}


def test_names_and_aliases_are_unique():
    names = [name for spec in ISA_SPECS for name in (spec.name, *spec.aliases)]
    assert len(names) == len(set(names))
    assert len({spec.examples_dir for spec in ISA_SPECS}) == len(ISA_SPECS)
    assert len({(spec.elf_machine, spec.word_bits) for spec in ISA_SPECS}) == len(ISA_SPECS)


@SPECS
def test_every_layer_supports_the_isa(spec):
    """Adding an ISA means adding an engine binding, an assembler target, and examples."""
    engine = engine_for(spec)
    assert len(engine.gpr_regs) == spec.registers.count
    assert len(set(engine.gpr_regs)) == spec.registers.count
    assert spec.name in TARGETS
    assert TARGETS[spec.name].isa_name == spec.name
    assert spec.examples_dir in ISA_DIRS
    if examples_dir() is not None:
        assert any(e.isa == spec.examples_dir for e in list_examples())


@SPECS
def test_lookups(spec):
    for name in (spec.name, *spec.aliases, spec.name.upper(), spec.name.replace("_", "-")):
        assert find_spec(name) is spec
        assert canonical_isa(name) == spec.name
        assert get_layout(name) is spec.layout
    assert get_spec(spec.isa) is spec
    assert get_spec(spec) is spec
    assert spec_for_elf(spec.elf_machine_name, spec.layout.is_64bit) is spec
    assert spec_for_elf(spec.elf_machine_name, not spec.layout.is_64bit) is None


@SPECS
def test_spec_facts_are_consistent(spec):
    abi = spec.syscall_abi
    for reg in (abi.number, abi.arg0, abi.result):
        assert 0 <= reg < spec.registers.count
    assert spec.registers.is_writable(abi.result)
    assert spec.min_instruction_size <= spec.syscall_instruction.size <= spec.max_instruction_size
    assert spec.byteorder in ("little", "big")
    assert spec.word_bits in (32, 64)


def test_unknown_isa():
    assert find_spec("vax") is None
    with pytest.raises(ValueError, match="riscv64"):
        get_spec("vax")
    with pytest.raises(ValueError):
        get_layout("vax")
    assert canonical_isa("VAX") == "vax"


def test_signed():
    riscv, mips = get_spec("riscv64"), get_spec("mips32")
    assert riscv.signed(0xFFFFFFFFFFFFFFFF) == -1
    assert riscv.signed(0xFFFFFFFF) == 0xFFFFFFFF
    assert mips.signed(0xFFFFFFFF) == -1
    assert mips.signed(0x7FFFFFFF) == 0x7FFFFFFF


def test_trap_descriptions():
    assert get_spec("mips32").describe_trap(0x0007000D) == "Division by zero"
    assert "overflow" in get_spec("mips32").describe_trap(0x0006000D)
    assert get_spec("mips32").describe_trap(0x0000000C) is None  # syscall
    assert get_spec("riscv64").describe_trap(0x00100073) == "ebreak instruction executed"
    assert get_spec("arm64").describe_trap(0xD4200020) == "brk instruction executed (brk #1)"
    assert get_spec("x86_64").describe_trap(0xCC) is None


@SPECS
def test_isa_directive(spec):
    for name in (spec.name, *spec.aliases):
        assert find_isa_directive(f"# comment\n.isa {name}  // trailing comment\n") == spec.name
        source = f"// comment\n.isa {name}\n.text\nnop\n"
        assert find_isa_directive(source) == spec.name
        parser = DirectiveParser()
        parser.parse(source)
        assert parser.isa == spec.name
        assert parser.errors == []


def test_isa_directive_must_come_first():
    assert find_isa_directive(".text\nnop\n.isa riscv64\n") is None
    assert find_isa_directive("") is None


def test_cli_choices_come_from_the_registry():
    assert isa_names() == tuple(spec.name for spec in ISA_SPECS)
    assert set(ENGINES) == {spec.isa for spec in ISA_SPECS}
