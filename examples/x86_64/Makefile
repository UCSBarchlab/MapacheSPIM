# ============================================================================
# Makefile for x86-64 Assembly Examples
# ============================================================================
#
# This Makefile builds x86-64 assembly programs for execution on the Unicorn
# CPU emulator via MapacheSPIM.
#
# Prerequisites:
#   - x86-64 GNU toolchain (gcc, as, ld)
#
# Usage:
#   make                 # Build all examples
#   make simple          # Build simple test program
#   make clean           # Remove all build artifacts
#
# ============================================================================

# Platform detection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    # macOS uses clang
    AS = clang
    ASFLAGS = -c -arch x86_64
    LD = ld
    LDFLAGS = -T linker.ld -static -arch x86_64 -e _start
else
    # Linux uses GNU as/ld
    AS = as
    ASFLAGS = --64
    LD = ld
    LDFLAGS = -T linker.ld -nostdlib -static
endif

# ============================================================================
# Targets
# ============================================================================

# Default target: build all examples
all: test_simple/simple matrix_multiply/matrix_mult

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

# ============================================================================
# Utility targets
# ============================================================================

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f test_simple/*.o test_simple/simple test_simple/*.dis
	rm -f matrix_multiply/*.o matrix_multiply/matrix_mult matrix_multiply/*.dis
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

.PHONY: all clean dis-simple dis-matrix
