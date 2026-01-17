# ============================================================================
# Makefile for RISC-V Assembly Examples
# ============================================================================
#
# This Makefile builds RISC-V assembly programs for execution with MapacheSPIM.
#
# Prerequisites:
#   - RISC-V GNU toolchain (riscv64-unknown-elf-*)
#   - MapacheSPIM (pip install -e . from repo root)
#
# Usage:
#   make                 # Build all examples
#   make matrix          # Build matrix multiplication example
#   make fibonacci       # Build fibonacci example
#   make clean           # Remove all build artifacts
#   make run-matrix      # Build and run matrix multiplication
#   make run-fibonacci   # Build and run fibonacci
#
# ============================================================================

# Toolchain configuration
# Change PREFIX if your toolchain has a different prefix
PREFIX = riscv64-unknown-elf-

AS = $(PREFIX)as
LD = $(PREFIX)ld
OBJDUMP = $(PREFIX)objdump
OBJCOPY = $(PREFIX)objcopy

# Assembler flags
# -march=rv64g: RISC-V 64-bit with general extensions (IMAFD)
# -mabi=lp64: 64-bit ABI with long and pointer as 64-bit
ASFLAGS = -march=rv64g -mabi=lp64

# Linker flags
LDFLAGS = -T linker.ld

# ============================================================================
# Targets
# ============================================================================

# Default target: build all examples
all: hello_asm/hello_asm guess_game/guess_game fibonacci/fibonacci \
     array_stats/array_stats matrix_multiply/matrix_mult

# Matrix multiplication example
matrix_multiply/matrix_mult: matrix_multiply/matrix_mult.o linker.ld
	@echo "Linking matrix multiplication program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for matrix multiplication..."
	$(OBJDUMP) -d $@ > matrix_multiply/matrix_mult.dis
	@echo "Matrix multiplication build complete!"

matrix_multiply/matrix_mult.o: matrix_multiply/matrix_mult.s
	@echo "Assembling matrix multiplication program..."
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

# ============================================================================
# Run targets - execute programs with MapacheSPIM
# ============================================================================

run-matrix: matrix_multiply/matrix_mult
	@echo "=========================================="
	@echo "Running Matrix Multiplication"
	@echo "=========================================="
	mapachespim -x $<

run-fibonacci: fibonacci/fibonacci
	@echo "=========================================="
	@echo "Running Fibonacci Calculator"
	@echo "=========================================="
	mapachespim -x $<

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

# Show disassembly for matrix multiplication
dis-matrix: matrix_multiply/matrix_mult
	@echo "Disassembly of matrix multiplication:"
	@echo "======================================"
	$(OBJDUMP) -d $<

# Show disassembly for fibonacci
dis-fibonacci: fibonacci/fibonacci
	@echo "Disassembly of fibonacci:"
	@echo "========================="
	$(OBJDUMP) -d $<

# Check if toolchain is installed
check-tools:
	@echo "Checking for RISC-V toolchain..."
	@which $(AS) > /dev/null || (echo "ERROR: $(AS) not found. Please install RISC-V toolchain."; exit 1)
	@which $(LD) > /dev/null || (echo "ERROR: $(LD) not found. Please install RISC-V toolchain."; exit 1)
	@echo "RISC-V toolchain found: $(shell $(AS) --version | head -1)"
	@echo "All tools ready!"

.PHONY: all clean run-matrix run-fibonacci dis-matrix dis-fibonacci check-tools
