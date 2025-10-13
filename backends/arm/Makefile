.PHONY: all build clean test help

# Detect Sail installation
SAIL_DIR := $(shell opam var sail:share 2>/dev/null)
ifeq ($(SAIL_DIR),)
    $(error Sail not found. Install with: opam install sail)
endif

# Detect GMP
GMP_CFLAGS := $(shell pkg-config --cflags gmp 2>/dev/null || echo "-I/opt/homebrew/include -I/usr/local/include")
GMP_LDFLAGS := $(shell pkg-config --libs gmp 2>/dev/null || echo "-L/opt/homebrew/lib -L/usr/local/lib -lgmp")

# Compiler flags (ARM v9.4 needs deep bracket nesting)
CFLAGS := -O2 -I$(SAIL_DIR)/lib/ -DHAVE_SETCONFIG -fbracket-depth=512 $(GMP_CFLAGS)
LDFLAGS := $(GMP_LDFLAGS) -lz

# Source files
ARM_MODEL_SRC := sail-arm/arm-v8.5-a/snapshots/c/aarch64.c
SAIL_RUNTIME_SRCS := $(SAIL_DIR)/lib/sail.c $(SAIL_DIR)/lib/rts.c $(SAIL_DIR)/lib/elf.c $(SAIL_DIR)/lib/sail_failure.c
TEST_SRC := test_arm_sail.c

# Object files
OBJECTS := aarch64.o sail.o rts.o elf.o sail_failure.o

# Output
TARGET := test_arm_sail

# Build directory for library
BUILD_DIR := build

all: build

# Build the test executable
build: $(TARGET)
	@echo "✓ Build complete"
	@echo "Run with: ./$(TARGET)"

$(TARGET): $(OBJECTS) $(TEST_SRC)
	@echo "Linking $(TARGET)..."
	@gcc $(CFLAGS) $(TEST_SRC) $(OBJECTS) $(LDFLAGS) -o $@

# Compile ARM model (with patching)
aarch64.o: $(ARM_MODEL_SRC)
	@echo "Compiling ARM v8.5-a model (this takes ~1 minute)..."
	@sed -e 's/unit z__SetConfig(sail_string/unit z__SetConfig(const_sail_string/g' \
	     -e '/^int main(int argc, char \*argv\[\])/,/^}/d' \
	     $(ARM_MODEL_SRC) > aarch64_patched.c
	@gcc -c $(CFLAGS) -Wno-everything aarch64_patched.c -o $@
	@rm -f aarch64_patched.c
	@echo "✓ ARM model compiled"

# Compile Sail runtime
sail.o: $(SAIL_DIR)/lib/sail.c
	@echo "Compiling Sail runtime..."
	@gcc -c $(CFLAGS) $< -o $@

rts.o: $(SAIL_DIR)/lib/rts.c
	@gcc -c $(CFLAGS) $< -o $@

elf.o: $(SAIL_DIR)/lib/elf.c
	@gcc -c $(CFLAGS) $< -o $@

sail_failure.o: $(SAIL_DIR)/lib/sail_failure.c
	@gcc -c $(CFLAGS) $< -o $@

# Build library version for use with libsailsim
lib: aarch64.o sail.o rts.o elf.o sail_failure.o
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)/sail_runtime
	@mkdir -p $(BUILD_DIR)/gmp/lib
	@mkdir -p $(BUILD_DIR)/gmp/include
	@echo "Creating ARM Sail library..."
	@ar rcs $(BUILD_DIR)/libarm_sail_model.a aarch64.o
	@ar rcs $(BUILD_DIR)/sail_runtime/libsail_runtime.a sail.o rts.o elf.o sail_failure.o
	@echo "Finding GMP library..."
	@find /opt/homebrew/lib /usr/local/lib -name "libgmp.a" -o -name "libgmp.dylib" 2>/dev/null | head -1 | xargs -I {} cp {} $(BUILD_DIR)/gmp/lib/ || true
	@find /opt/homebrew/include /usr/local/include -name "gmp.h" 2>/dev/null | head -1 | xargs -I {} cp {} $(BUILD_DIR)/gmp/include/ || true
	@echo "✓ Library built in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/libarm_sail_model.a

# Run tests
test: $(TARGET)
	@./$(TARGET)

# Clean build artifacts
clean:
	@rm -f $(OBJECTS) $(TARGET) aarch64_patched.c
	@rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"

# Show help
help:
	@echo "Available targets:"
	@echo "  all (default) - Build test executable"
	@echo "  build         - Build test executable"
	@echo "  lib           - Build library for use with libsailsim"
	@echo "  test          - Run test executable"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help message"
