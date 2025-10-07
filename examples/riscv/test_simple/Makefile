# Makefile for simple test program

CC = riscv64-unknown-elf-gcc
AS = riscv64-unknown-elf-as
LD = riscv64-unknown-elf-ld
OBJDUMP = riscv64-unknown-elf-objdump

CFLAGS = -march=rv64i -mabi=lp64 -nostdlib -nostartfiles
LDFLAGS = -T ../linker.ld

TARGET = simple
SRC = simple.s

all: $(TARGET)

$(TARGET): $(SRC) ../linker.ld
	$(AS) -march=rv64i $(SRC) -o $(TARGET).o
	$(LD) $(LDFLAGS) $(TARGET).o -o $(TARGET)
	$(OBJDUMP) -d $(TARGET) > $(TARGET).dis

clean:
	rm -f $(TARGET) $(TARGET).o $(TARGET).dis

.PHONY: all clean
