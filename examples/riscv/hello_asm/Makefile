# Makefile for hello_asm
# Builds a bare-metal RISC-V executable for use with MapacheSPIM

# Cross-compiler prefix (adjust if your toolchain is different)
CROSS = riscv64-unknown-elf-

AS = $(CROSS)as
LD = $(CROSS)ld

# Target name
TARGET = hello_asm

# Default target
all: $(TARGET)

$(TARGET): $(TARGET).o
	$(LD) -T ../linker.ld -o $@ $<

$(TARGET).o: $(TARGET).s
	$(AS) -march=rv64i -mabi=lp64 -o $@ $<

clean:
	rm -f $(TARGET) $(TARGET).o

.PHONY: all clean
