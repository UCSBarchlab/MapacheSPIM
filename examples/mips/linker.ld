/* ============================================================================
 * MIPS Linker Script for Bare-Metal Programs (Unicorn Emulator)
 * ============================================================================
 *
 * Uses traditional MIPS user-space memory layout:
 *   .text at 0x00400000 (kuseg)
 *   .data at 0x10000000 (kuseg)
 *   stack near 0x7FFFFFFF
 *
 * Note: 0x80000000+ is kernel space (kseg0/kseg1) and requires special handling
 * ============================================================================
 */

OUTPUT_ARCH("mips")
ENTRY(_start)

MEMORY
{
    TEXT (rx)  : ORIGIN = 0x00400000, LENGTH = 4M
    DATA (rw)  : ORIGIN = 0x10000000, LENGTH = 4M
    STACK (rw) : ORIGIN = 0x7FE00000, LENGTH = 2M
}

SECTIONS
{
    . = 0x00400000;

    .text : {
        *(.text._start)
        *(.text*)
    } > TEXT

    .rodata : {
        *(.rodata*)
    } > DATA

    .data : {
        *(.data*)
    } > DATA

    .bss : {
        *(.bss*)
        *(COMMON)
    } > DATA

    /* Stack at end of user space */
    _stack_start = ORIGIN(STACK) + LENGTH(STACK);
}
