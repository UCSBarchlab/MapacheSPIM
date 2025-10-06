/* ============================================================================
 * RISC-V Linker Script for Bare-Metal Programs (Sail Emulator)
 * ============================================================================
 */

OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 64M
}

SECTIONS
{
    . = 0x80000000;

    .text : {
        *(.text._start)
        *(.text*)
    } > RAM

    .rodata : {
        *(.rodata*)
    } > RAM

    .data : {
        *(.data*)
    } > RAM

    .bss : {
        *(.bss*)
        *(COMMON)
    } > RAM

    /* HTIF at fixed address - critical for Sail emulator */
    . = 0x80001000;
    .tohost ALIGN(64) : {
        *(.tohost)
    } > RAM

    /* Stack at end of memory */
    . = ORIGIN(RAM) + LENGTH(RAM) - 1M;
    _stack_start = .;
}
