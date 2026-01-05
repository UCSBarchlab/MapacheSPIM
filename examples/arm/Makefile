# ============================================================================
# Makefile for ARM64 Assembly Examples
# ============================================================================
#
# This Makefile builds ARM64 (AArch64) assembly programs for execution on the
# Sail ARM emulator.
#
# Prerequisites:
#   - ARM64 GNU toolchain (aarch64-linux-gnu-* or aarch64-unknown-elf-*)
#   - Sail ARM emulator (via MapacheSPIM)
#
# Usage:
#   make                 # Build all examples
#   make test_simple     # Build simple test example
#   make fibonacci       # Build fibonacci example
#   make hello_world     # Build hello world example
#   make clean           # Remove all build artifacts
#   make run-simple      # Build and run simple test
#   make run-fibonacci   # Build and run fibonacci
#   make run-hello       # Build and run hello world
#
# ============================================================================

# Toolchain configuration
# Uses aarch64-elf toolchain (install via: brew install aarch64-elf-gcc)
# You can override this: make PREFIX=aarch64-linux-gnu-
PREFIX ?= aarch64-elf-

AS = $(PREFIX)as
LD = $(PREFIX)ld
OBJDUMP = $(PREFIX)objdump
OBJCOPY = $(PREFIX)objcopy

# Assembler flags
# -march=armv8-a: ARM v8 architecture
ASFLAGS = -march=armv8-a

# Linker flags
LDFLAGS = -T linker.ld

# Python test runner
TEST_RUNNER = ../../tests/run_arm_example.py

# ============================================================================
# Targets
# ============================================================================

# Default target: build all examples
all: test_simple/simple hello_world/hello fibonacci/fibonacci

# Simple test example
test_simple/simple: test_simple/simple.o linker.ld
	@echo "Linking simple test program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for simple test..."
	$(OBJDUMP) -d $@ > test_simple/simple.dis
	@echo "Simple test build complete!"

test_simple/simple.o: test_simple/simple.s
	@echo "Assembling simple test program..."
	$(AS) $(ASFLAGS) -o $@ $<

# Hello World example
hello_world/hello: hello_world/hello.o linker.ld
	@echo "Linking hello world program..."
	$(LD) $(LDFLAGS) -o $@ $<
	@echo "Generating disassembly for hello world..."
	$(OBJDUMP) -d $@ > hello_world/hello.dis
	@echo "Hello world build complete!"

hello_world/hello.o: hello_world/hello.s
	@echo "Assembling hello world program..."
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
# Run targets - execute programs with MapacheSPIM
# ============================================================================

run-simple: test_simple/simple
	@echo "=========================================="
	@echo "Running Simple Test"
	@echo "=========================================="
	python3 $(TEST_RUNNER) $<

run-hello: hello_world/hello
	@echo "=========================================="
	@echo "Running Hello World"
	@echo "=========================================="
	python3 $(TEST_RUNNER) $<

run-fibonacci: fibonacci/fibonacci
	@echo "=========================================="
	@echo "Running Fibonacci Calculator"
	@echo "=========================================="
	python3 $(TEST_RUNNER) $<

# ============================================================================
# Utility targets
# ============================================================================

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f test_simple/*.o test_simple/simple test_simple/*.dis
	rm -f hello_world/*.o hello_world/hello hello_world/*.dis
	rm -f fibonacci/*.o fibonacci/fibonacci fibonacci/*.dis
	@echo "Clean complete!"

# Show disassembly for simple test
dis-simple: test_simple/simple
	@echo "Disassembly of simple test:"
	@echo "==========================="
	$(OBJDUMP) -d $<

# Show disassembly for hello world
dis-hello: hello_world/hello
	@echo "Disassembly of hello world:"
	@echo "==========================="
	$(OBJDUMP) -d $<

# Show disassembly for fibonacci
dis-fibonacci: fibonacci/fibonacci
	@echo "Disassembly of fibonacci:"
	@echo "========================="
	$(OBJDUMP) -d $<

# Check if toolchain is installed
check-tools:
	@echo "Checking for ARM64 toolchain..."
	@which $(AS) > /dev/null || (echo "ERROR: $(AS) not found. Please install ARM64 toolchain."; exit 1)
	@which $(LD) > /dev/null || (echo "ERROR: $(LD) not found. Please install ARM64 toolchain."; exit 1)
	@echo "ARM64 toolchain found: $(shell $(AS) --version | head -1)"
	@echo "All tools ready!"

.PHONY: all clean run-simple run-hello run-fibonacci \
        dis-simple dis-hello dis-fibonacci check-tools
