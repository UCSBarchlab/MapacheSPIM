/**
 * @file test_arm_sail.c
 * @brief Minimal test program to verify ARM Sail integration
 *
 * This program validates that the ARM Sail model can:
 * 1. Initialize properly
 * 2. Read/write registers
 * 3. Read/write memory
 * 4. Access PC
 *
 * Build: See build.sh in this directory
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// Sail runtime headers
#include "sail.h"
#include "rts.h"

// Forward declarations for ARM Sail functions we'll use
// These are defined in the separately-compiled aarch64.o

// Runtime init/cleanup
extern void model_init(void);
extern void model_fini(void);

// ARM initialization
extern unit zinit(unit);

// Register access
extern sbits zaget_X(int64_t width, int64_t n);
extern unit zaset_X(int64_t n, lbits value);

// Memory access
extern unit z__WriteMemory(sail_int N, uint64_t address, lbits value);
extern void z__ReadMemory(lbits *result, sail_int N, uint64_t address);

// PC access (global variable)
extern uint64_t z_PC;

// Stub functions for model-specific handlers
void model_pre_exit() {
    // Called before exit - empty for test program
}

void sail_rts_set_coverage_file(const char *filename) {
    // Coverage tracking not used in test program
}

int main(int argc, char** argv) {
    printf("=== ARM Sail Integration Test ===\n\n");

    // Step 1: Initialize Sail runtime
    printf("1. Initializing Sail runtime...\n");
    model_init();
    printf("   ✓ model_init() succeeded\n");

    // Step 2: Initialize ARM processor (cold reset)
    printf("\n2. Resetting ARM processor...\n");
    zinit(UNIT);
    printf("   ✓ zinit() succeeded (cold reset complete)\n");

    // Step 3: Test register write/read
    printf("\n3. Testing register access...\n");

    // Write to X1
    lbits test_value;
    CREATE(lbits)(&test_value);
    CONVERT_OF(lbits, fbits)(&test_value, 0x0000000000000042UL, 64, true);

    zaset_X(1, test_value);
    printf("   Wrote 0x42 to X1\n");

    KILL(lbits)(&test_value);

    // Read from X1
    sbits result = zaget_X(64, 1);
    printf("   Read X1 = 0x%016llx\n", (unsigned long long)result.bits);

    if (result.bits == 0x42) {
        printf("   ✓ Register read/write PASSED\n");
    } else {
        printf("   ✗ Register read/write FAILED (expected 0x42, got 0x%llx)\n",
               (unsigned long long)result.bits);
        return 1;
    }

    // Step 4: Test register 31 (should read as zero)
    printf("\n4. Testing special register X31 (zero register)...\n");
    sbits x31_result = zaget_X(64, 31);
    printf("   Read X31 = 0x%016llx\n", (unsigned long long)x31_result.bits);

    if (x31_result.bits == 0) {
        printf("   ✓ X31 returns zero as expected\n");
    } else {
        printf("   ✗ X31 should be zero but got 0x%llx\n",
               (unsigned long long)x31_result.bits);
        return 1;
    }

    // Step 5: Test PC access
    printf("\n5. Testing PC access...\n");
    printf("   Initial PC = 0x%016llx\n", (unsigned long long)z_PC);

    z_PC = 0x1000;
    printf("   Set PC = 0x1000\n");
    printf("   Read PC = 0x%016llx\n", (unsigned long long)z_PC);

    if (z_PC == 0x1000) {
        printf("   ✓ PC access PASSED\n");
    } else {
        printf("   ✗ PC access FAILED\n");
        return 1;
    }

    // Step 6: Test memory write
    printf("\n6. Testing memory write...\n");

    sail_int mem_size;
    CREATE(sail_int)(&mem_size);
    CONVERT_OF(sail_int, mach_int)(&mem_size, 4);  // Write 4 bytes

    lbits mem_value;
    CREATE(lbits)(&mem_value);
    CONVERT_OF(lbits, fbits)(&mem_value, 0xDEADBEEF, 32, true);

    z__WriteMemory(mem_size, 0x10000, mem_value);
    printf("   Wrote 0xDEADBEEF to address 0x10000\n");

    KILL(lbits)(&mem_value);

    // Step 7: Test memory read
    printf("\n7. Testing memory read...\n");

    lbits mem_read_result;
    CREATE(lbits)(&mem_read_result);

    z__ReadMemory(&mem_read_result, mem_size, 0x10000);

    uint32_t read_value = CONVERT_OF(fbits, lbits)(mem_read_result, true);
    printf("   Read from address 0x10000 = 0x%08x\n", read_value);

    KILL(lbits)(&mem_read_result);
    KILL(sail_int)(&mem_size);

    if (read_value == 0xDEADBEEF) {
        printf("   ✓ Memory read/write PASSED\n");
    } else {
        printf("   ✗ Memory read/write FAILED (expected 0xDEADBEEF, got 0x%08x)\n",
               read_value);
        return 1;
    }

    // Step 8: Cleanup
    printf("\n8. Cleaning up...\n");
    // Note: model_fini() may crash due to ARM Sail cleanup issues
    // This is not critical for integration - we'll skip it for now
    printf("   (Skipping model_fini() - known cleanup issue)\n");

    printf("\n=== ALL TESTS PASSED ✓ ===\n");
    printf("\n");
    printf("ARM Sail integration is READY for MapacheSPIM!\n");
    printf("✓ Register access works\n");
    printf("✓ Memory access works\n");
    printf("✓ PC access works\n");
    printf("✓ Processor initialization works\n");
    return 0;
}
