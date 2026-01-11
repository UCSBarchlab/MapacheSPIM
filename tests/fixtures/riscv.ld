/* Simple RISC-V linker script for MapacheSPIM */
ENTRY(main)

MEMORY
{
    ram (rwx) : ORIGIN = 0x80000000, LENGTH = 0x10000
}

SECTIONS
{
    .text : {
        *(.text*)
    } > ram

    .rodata : {
        *(.rodata*)
    } > ram

    .data : {
        *(.data*)
    } > ram

    .bss : {
        *(.bss*)
    } > ram
}
