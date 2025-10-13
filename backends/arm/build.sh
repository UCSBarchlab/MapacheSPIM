#!/bin/bash
# Build script for ARM Sail standalone test

set -e  # Exit on error

echo "Building ARM Sail standalone test..."

# Check for required dependencies
if ! command -v sail &> /dev/null; then
    echo "Warning: sail command not found. Attempting to use opam sail installation..."
fi

# Get Sail library directory
SAIL_DIR=$(opam var sail:share 2>/dev/null || echo "")

if [ -z "$SAIL_DIR" ]; then
    echo "Error: Could not find Sail installation directory"
    echo "Please install Sail via opam: opam install sail"
    exit 1
fi

echo "Using Sail directory: $SAIL_DIR"

# Find GMP library (usually via homebrew on macOS)
GMP_CFLAGS=$(pkg-config --cflags gmp 2>/dev/null || echo "-I/opt/homebrew/include -I/usr/local/include")
GMP_LDFLAGS=$(pkg-config --libs gmp 2>/dev/null || echo "-L/opt/homebrew/lib -L/usr/local/lib -lgmp")

# Compiler flags (ARM v9.4 needs deep bracket nesting)
CFLAGS="-O2 -I$SAIL_DIR/lib/ -DHAVE_SETCONFIG -fbracket-depth=512 $GMP_CFLAGS"
LDFLAGS="$GMP_LDFLAGS -lz"

# Source files
SAIL_RUNTIME="$SAIL_DIR/lib/sail.c $SAIL_DIR/lib/rts.c $SAIL_DIR/lib/elf.c"
ARM_MODEL="sail-arm/arm-v9.4-a/snapshots/c/armv9.c"
TEST_PROGRAM="test_arm_sail.c"

# Build in steps to avoid conflicts

echo "Step 1/3: Patching and compiling ARM Sail model..."
# The snapshot was generated with older Sail expecting sail_string,
# but current Sail 0.19.1 expects const_sail_string for z__SetConfig
# Also need to remove the main() function from ARM model to avoid conflicts
echo "   Patching SetConfig signature and removing main()..."
sed -e 's/unit z__SetConfig(sail_string/unit z__SetConfig(const_sail_string/g' \
    -e '/^int main(int argc, char \*argv\[\])/,/^}/d' \
    $ARM_MODEL > armv9_patched.c

gcc -c $CFLAGS -Wno-everything armv9_patched.c -o armv9.o
if [ $? -ne 0 ]; then
    echo "✗ ARM model compilation failed"
    rm -f armv9_patched.c
    exit 1
fi
echo "   ✓ armv9.o created"
rm -f armv9_patched.c

echo "Step 2/3: Compiling Sail runtime..."
gcc -c $CFLAGS $SAIL_DIR/lib/sail.c -o sail.o
gcc -c $CFLAGS $SAIL_DIR/lib/rts.c -o rts.o
gcc -c $CFLAGS $SAIL_DIR/lib/elf.c -o elf.o
gcc -c $CFLAGS $SAIL_DIR/lib/sail_failure.c -o sail_failure.o
if [ $? -ne 0 ]; then
    echo "✗ Sail runtime compilation failed"
    exit 1
fi
echo "   ✓ Sail runtime objects created"

echo "Step 3/3: Compiling test program and linking..."
gcc $CFLAGS $TEST_PROGRAM armv9.o sail.o rts.o elf.o sail_failure.o $LDFLAGS -o test_arm_sail

if [ $? -eq 0 ]; then
    echo "✓ Build succeeded"
    echo ""
    echo "Run the test with: ./test_arm_sail"
    echo ""
    echo "Generated files:"
    ls -lh test_arm_sail armv9.o
else
    echo "✗ Build failed"
    exit 1
fi
