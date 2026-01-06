# ============================================================================
# Makefile for x86-64 Assembly Examples
# ============================================================================
#
# This Makefile builds x86-64 assembly programs for execution on the Unicorn
# CPU emulator via MapacheSPIM.
#
# Prerequisites:
#   macOS: brew install x86_64-elf-binutils x86_64-elf-gcc
#   Linux: x86-64 GNU toolchain (gcc, as, ld) - usually pre-installed
#
# Usage:
#   make                 # Build all examples
#   make clean           # Remove all build artifacts
#
# ============================================================================

# Use x86_64-elf cross-compiler for ELF output
AS = x86_64-elf-as
ASFLAGS = --64
LD = x86_64-elf-ld
LDFLAGS = -T linker.ld -nostdlib -static

# ============================================================================
# Targets
# ============================================================================

# Default target: build all examples
all: test_simple/simple matrix_multiply/matrix_mult fibonacci/fibonacci

# Simple test example
test_simple/simple: test_simple/simple.o linker.ld
	@echo "Linking simple test program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly..."
	objdump -d $@ > test_simple/simple.dis
	@echo "Simple test build complete!"

test_simple/simple.o: test_simple/simple.S
	@echo "Assembling simple test program..."
	$(AS) $(ASFLAGS) -o $@ $<

# Matrix multiply example
matrix_multiply/matrix_mult: matrix_multiply/matrix_mult.o linker.ld
	@echo "Linking matrix multiply program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly..."
	objdump -d $@ > matrix_multiply/matrix_mult.dis
	@echo "Matrix multiply build complete!"

matrix_multiply/matrix_mult.o: matrix_multiply/matrix_mult.S
	@echo "Assembling matrix multiply program..."
	$(AS) $(ASFLAGS) -o $@ $<

# Fibonacci example
fibonacci/fibonacci: fibonacci/fibonacci.o linker.ld
	@echo "Linking fibonacci program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly..."
	objdump -d $@ > fibonacci/fibonacci.dis
	@echo "Fibonacci build complete!"

fibonacci/fibonacci.o: fibonacci/fibonacci.S
	@echo "Assembling fibonacci program..."
	$(AS) $(ASFLAGS) -o $@ $<

# ============================================================================
# Utility targets
# ============================================================================

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f test_simple/*.o test_simple/simple test_simple/*.dis
	rm -f matrix_multiply/*.o matrix_multiply/matrix_mult matrix_multiply/*.dis
	rm -f fibonacci/*.o fibonacci/fibonacci fibonacci/*.dis
	@echo "Clean complete!"

# Show disassembly
dis-simple: test_simple/simple
	@echo "Disassembly of simple test:"
	@echo "============================"
	objdump -d $<

dis-matrix: matrix_multiply/matrix_mult
	@echo "Disassembly of matrix multiply:"
	@echo "==============================="
	objdump -d $<

dis-fibonacci: fibonacci/fibonacci
	@echo "Disassembly of fibonacci:"
	@echo "========================="
	objdump -d $<

.PHONY: all clean dis-simple dis-matrix dis-fibonacci
