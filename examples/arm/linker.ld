/* ============================================================================
 * ARM64 Linker Script for Bare-Metal Programs (Sail Emulator)
 * ============================================================================
 */

OUTPUT_ARCH("aarch64")
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x10000000, LENGTH = 64M
}

SECTIONS
{
    . = 0x10000000;

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

    /* Stack at end of memory */
    . = ORIGIN(RAM) + LENGTH(RAM) - 1M;
    _stack_start = .;
}
