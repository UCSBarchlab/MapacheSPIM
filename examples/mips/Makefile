# ============================================================================
# Makefile for MIPS Assembly Examples
# ============================================================================
#
# This Makefile builds MIPS32 assembly programs for execution on the Unicorn
# CPU emulator via MapacheSPIM.
#
# Prerequisites:
#   macOS: brew install mips64-elf-binutils mips64-elf-gcc
#          (or use mips-linux-gnu-* from Linux toolchain)
#   Linux: apt install binutils-mips-linux-gnu gcc-mips-linux-gnu
#
# Usage:
#   make                 # Build all examples
#   make hello_asm       # Build hello_asm example
#   make guess_game      # Build guess_game example
#   make fibonacci       # Build fibonacci example
#   make array_stats     # Build array_stats example
#   make matrix_multiply # Build matrix_multiply example
#   make clean           # Remove all build artifacts
#   make check-tools     # Verify toolchain is installed
#
# ============================================================================

# Toolchain configuration
# Common prefixes: mips-linux-gnu-, mips64-elf-, mips-unknown-elf-
# You can override this: make PREFIX=mips-linux-gnu-
PREFIX ?= mips-linux-gnu-

AS = $(PREFIX)as
LD = $(PREFIX)ld
OBJDUMP = $(PREFIX)objdump
OBJCOPY = $(PREFIX)objcopy

# Assembler flags
# -mips32: MIPS32 architecture
# -EB: Big endian
ASFLAGS = -mips32 -EB

# Linker flags
LDFLAGS = -T linker.ld -EB

# ============================================================================
# Targets
# ============================================================================

# Default target: build all examples
all: hello_asm/hello_asm guess_game/guess_game fibonacci/fibonacci \
     array_stats/array_stats matrix_multiply/matrix_mult

# Hello Assembly Tutorial example
hello_asm/hello_asm: hello_asm/hello_asm.o linker.ld
	@echo "Linking hello_asm program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for hello_asm..."
	$(OBJDUMP) -d $@ > hello_asm/hello_asm.dis
	@echo "Hello Assembly build complete!"

hello_asm/hello_asm.o: hello_asm/hello_asm.s
	@echo "Assembling hello_asm program..."
	$(AS) $(ASFLAGS) -o $@ $<

# Guess Game example
guess_game/guess_game: guess_game/guess_game.o linker.ld
	@echo "Linking guess_game program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for guess_game..."
	$(OBJDUMP) -d $@ > guess_game/guess_game.dis
	@echo "Guess Game build complete!"

guess_game/guess_game.o: guess_game/guess_game.s
	@echo "Assembling guess_game program..."
	$(AS) $(ASFLAGS) -o $@ $<

# Fibonacci example
fibonacci/fibonacci: fibonacci/fibonacci.o linker.ld
	@echo "Linking fibonacci program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for fibonacci..."
	$(OBJDUMP) -d $@ > fibonacci/fibonacci.dis
	@echo "Fibonacci build complete!"

fibonacci/fibonacci.o: fibonacci/fibonacci.s
	@echo "Assembling fibonacci program..."
	$(AS) $(ASFLAGS) -o $@ $<

# Array Statistics example
array_stats/array_stats: array_stats/array_stats.o linker.ld
	@echo "Linking array_stats program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for array_stats..."
	$(OBJDUMP) -d $@ > array_stats/array_stats.dis
	@echo "Array Stats build complete!"

array_stats/array_stats.o: array_stats/array_stats.s
	@echo "Assembling array_stats program..."
	$(AS) $(ASFLAGS) -o $@ $<

# Matrix Multiplication example
matrix_multiply/matrix_mult: matrix_multiply/matrix_mult.o linker.ld
	@echo "Linking matrix multiplication program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for matrix multiplication..."
	$(OBJDUMP) -d $@ > matrix_multiply/matrix_mult.dis
	@echo "Matrix multiplication build complete!"

matrix_multiply/matrix_mult.o: matrix_multiply/matrix_mult.s
	@echo "Assembling matrix multiplication program..."
	$(AS) $(ASFLAGS) -o $@ $<

# ============================================================================
# Utility targets
# ============================================================================

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f hello_asm/*.o hello_asm/hello_asm hello_asm/*.dis
	rm -f guess_game/*.o guess_game/guess_game guess_game/*.dis
	rm -f fibonacci/*.o fibonacci/fibonacci fibonacci/*.dis
	rm -f array_stats/*.o array_stats/array_stats array_stats/*.dis
	rm -f matrix_multiply/*.o matrix_multiply/matrix_mult matrix_multiply/*.dis
	@echo "Clean complete!"

# Check if toolchain is installed
check-tools:
	@echo "Checking for MIPS toolchain..."
	@which $(AS) > /dev/null || (echo "ERROR: $(AS) not found. Please install MIPS toolchain."; exit 1)
	@which $(LD) > /dev/null || (echo "ERROR: $(LD) not found. Please install MIPS toolchain."; exit 1)
	@echo "MIPS toolchain found: $(shell $(AS) --version | head -1)"
	@echo "All tools ready!"

.PHONY: all clean check-tools
