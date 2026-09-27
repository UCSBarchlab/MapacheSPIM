"""The assembler's ELF files are well formed, and the loader checks what it loads."""

from io import BytesIO
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from mapachespim.elf_loader import load_elf_file
from mapachespim.examples import list_examples
from mapachespim.isa import ISA_SPECS
from mapachespim.toolchain import assemble

EXAMPLES = list_examples()


def _program(spec):
    return f"""
        .isa {spec.name}
        .data
        value: .word 1
        table: .word 2, 3
        .text
        .globl _start
        _start:
            nop
        helper:
            nop
        .globl done
        done:
            nop
    """


@pytest.mark.parametrize("spec", ISA_SPECS, ids=lambda spec: spec.name)
def test_symbol_table_is_well_formed(spec):
    result = assemble(_program(spec), isa=spec.name)
    assert result.success, result.errors
    elf = ELFFile(BytesIO(result.elf_bytes))
    assert elf.header["e_machine"] == spec.elf_machine_name
    assert elf.header["e_flags"] == spec.elf_flags
    assert elf.elfclass == spec.word_bits
    assert elf.little_endian == spec.layout.is_little_endian

    symtab = elf.get_section_by_name(".symtab")
    symbols = list(symtab.iter_symbols())
    bindings = [s["st_info"]["bind"] for s in symbols]
    # Locals first; sh_info is the index of the first global
    first_global = bindings.index("STB_GLOBAL")
    assert all(b == "STB_LOCAL" for b in bindings[:first_global])
    assert all(b == "STB_GLOBAL" for b in bindings[first_global:])
    assert symtab["sh_info"] == first_global
    assert {s.name for s in symbols[first_global:]} == {"_start", "done"}

    # Each symbol points at the section that contains it
    for sym in symbols[1:]:
        section = elf.get_section(sym["st_shndx"])
        start = section["sh_addr"]
        assert start <= sym["st_value"] < start + section["sh_size"], sym.name
        expected = ".data" if sym.name in ("value", "table") else ".text"
        assert section.name == expected, sym.name


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda e: e.short_name)
def test_example_binaries_are_up_to_date(example):
    """The bundled binaries are what 'make debug' in examples/ produces.

    If this fails after changing the assembler, rebuild them with
    ``make -B debug`` in the examples directory.
    """
    source = example.source
    result = assemble(
        source.read_text(), isa=_isa_of(source), debug=True, source_filename=source.name
    )
    assert result.success, result.errors
    assert result.elf_bytes == example.binary.read_bytes()


def _isa_of(source: Path) -> str:
    from mapachespim.toolchain.directives import find_isa_directive

    isa = find_isa_directive(source.read_text())
    assert isa is not None
    return isa


def _patched(path, offset, data, tmp_path):
    raw = bytearray(Path(path).read_bytes())
    raw[offset : offset + len(data)] = data
    out = tmp_path / "patched.elf"
    out.write_bytes(bytes(raw))
    return str(out)


@pytest.fixture
def mips_elf():
    elf = Path("examples/mips/hello_asm/hello_asm")
    if not elf.exists():
        pytest.skip("examples not available")
    return elf


def test_loader_rejects_unknown_machines(mips_elf, tmp_path):
    # e_machine is at offset 18; MIPS is big-endian. 40 is 32-bit ARM.
    with pytest.raises(RuntimeError, match="Unsupported ELF machine type"):
        load_elf_file(_patched(mips_elf, 18, (40).to_bytes(2, "big"), tmp_path))


def test_loader_rejects_wrong_word_size(mips_elf, tmp_path):
    # A 32-bit RISC-V file must not be run as RV64
    with pytest.raises(RuntimeError, match="32-bit"):
        load_elf_file(_patched(mips_elf, 18, (243).to_bytes(2, "big"), tmp_path))


def test_loader_reports_sections(mips_elf):
    info = load_elf_file(str(mips_elf))
    text = next(s for s in info.sections if s.name == ".text")
    assert text.loaded and text.flag_letters == "AX"
    assert text.address == info.spec.layout.text_base
    debug = next(s for s in info.sections if s.name == ".debug_line")
    assert not debug.loaded and debug.flag_letters == ""


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        load_elf_file("no/such/file")
