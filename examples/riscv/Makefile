# ============================================================================
# Makefile for RISC-V Assembly Examples
# ============================================================================
#
# This Makefile builds RISC-V assembly programs for execution on the Sail
# RISC-V emulator.
#
# Prerequisites:
#   - RISC-V GNU toolchain (riscv64-unknown-elf-*)
#   - Sail RISC-V emulator
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

# Sail emulator path
# Adjust this path to your Sail RISC-V simulator location
SAIL_SIM = ../sail-riscv/build/c_emulator/sail_riscv_sim

# ============================================================================
# Targets
# ============================================================================

# Default target: build all examples
all: matrix_multiply/matrix_mult fibonacci/fibonacci

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

# ============================================================================
# Run targets - execute programs with trace enabled
# ============================================================================

run-matrix: matrix_multiply/matrix_mult
	@echo "=========================================="
	@echo "Running Matrix Multiplication"
	@echo "=========================================="
	$(SAIL_SIM) --trace-instr $<

run-fibonacci: fibonacci/fibonacci
	@echo "=========================================="
	@echo "Running Fibonacci Calculator"
	@echo "=========================================="
	$(SAIL_SIM) --trace-instr $<

# Run with memory trace to see data accesses
run-matrix-mem: matrix_multiply/matrix_mult
	@echo "Running Matrix Multiplication with memory trace..."
	$(SAIL_SIM) --trace-instr --trace-mem $<

run-fibonacci-mem: fibonacci/fibonacci
	@echo "Running Fibonacci with memory trace..."
	$(SAIL_SIM) --trace-instr --trace-mem $<

# ============================================================================
# Utility targets
# ============================================================================

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f matrix_multiply/*.o matrix_multiply/matrix_mult matrix_multiply/*.dis
	rm -f fibonacci/*.o fibonacci/fibonacci fibonacci/*.dis
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
	@echo "Checking for Sail emulator..."
	@test -f $(SAIL_SIM) || (echo "ERROR: Sail emulator not found at $(SAIL_SIM)"; exit 1)
	@echo "Sail emulator found: $(SAIL_SIM)"
	@echo "All tools ready!"

.PHONY: all clean run-matrix run-fibonacci run-matrix-mem run-fibonacci-mem \
        dis-matrix dis-fibonacci check-tools
