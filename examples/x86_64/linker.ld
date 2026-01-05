/* ============================================================================
 * x86-64 Linker Script for Bare-Metal Programs
 * ============================================================================
 */

OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x400000, LENGTH = 64M
}

SECTIONS
{
    . = 0x400000;

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
}
