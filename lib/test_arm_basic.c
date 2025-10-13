/**
 * @file test_arm_basic.c
 * @brief Basic test for ARM library initialization
 */

#include "include/sailsim.h"
#include <stdio.h>

int main() {
    printf("=== Testing libsailsim_arm ===\n\n");

    // Test 1: Initialize ARM simulator
    printf("Test 1: Initializing ARM simulator...\n");
    sailsim_context_t* ctx = sailsim_init(NULL);
    if (!ctx) {
        fprintf(stderr, "FAILED: Could not initialize simulator\n");
        return 1;
    }
    printf("SUCCESS: Simulator initialized\n");

    // Test 2: Check ISA type
    printf("\nTest 2: Checking ISA type...\n");
    sailsim_isa_t isa = sailsim_get_isa(ctx);
    if (isa != SAILSIM_ISA_ARM) {
        fprintf(stderr, "FAILED: Expected ISA_ARM, got %d\n", isa);
        sailsim_destroy(ctx);
        return 1;
    }
    printf("SUCCESS: ISA is ARM\n");

    // Test 3: Read initial PC
    printf("\nTest 3: Reading initial PC...\n");
    uint64_t pc = sailsim_get_pc(ctx);
    printf("SUCCESS: PC = 0x%llx\n", pc);

    // Test 4: Read/write registers
    printf("\nTest 4: Testing register access...\n");
    sailsim_set_reg(ctx, 1, 0x1234567890ABCDEFULL);
    uint64_t val = sailsim_get_reg(ctx, 1);
    if (val != 0x1234567890ABCDEFULL) {
        fprintf(stderr, "FAILED: Register write/read mismatch (got 0x%llx)\n", val);
        sailsim_destroy(ctx);
        return 1;
    }
    printf("SUCCESS: Register read/write works\n");

    // Test 5: Memory write/read
    printf("\nTest 5: Testing memory access...\n");
    uint64_t test_addr = 0x80000000;
    uint32_t test_data = 0xDEADBEEF;
    if (!sailsim_write_mem(ctx, test_addr, &test_data, sizeof(test_data))) {
        fprintf(stderr, "FAILED: Memory write failed\n");
        sailsim_destroy(ctx);
        return 1;
    }

    uint32_t read_data = 0;
    if (!sailsim_read_mem(ctx, test_addr, &read_data, sizeof(read_data))) {
        fprintf(stderr, "FAILED: Memory read failed\n");
        sailsim_destroy(ctx);
        return 1;
    }

    if (read_data != test_data) {
        fprintf(stderr, "FAILED: Memory data mismatch (wrote 0x%x, read 0x%x)\n",
                test_data, read_data);
        sailsim_destroy(ctx);
        return 1;
    }
    printf("SUCCESS: Memory read/write works\n");

    // Test 6: Cleanup
    printf("\nTest 6: Destroying simulator...\n");
    sailsim_destroy(ctx);
    printf("SUCCESS: Simulator destroyed\n");

    printf("\n=== All tests passed! ===\n");
    return 0;
}
