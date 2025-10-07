/**
 * @file test_sailsim.c
 * @brief Simple test program for libsailsim
 */

#include "sailsim.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf_file>\n", argv[0]);
        return 1;
    }

    const char* elf_file = argv[1];

    printf("Initializing Sail RISC-V simulator...\n");
    fflush(stdout);
    sailsim_context_t* ctx = sailsim_init(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize simulator\n");
        return 1;
    }
    printf("Simulator initialized successfully!\n");
    fflush(stdout);

    printf("Loading ELF file: %s\n", elf_file);
    if (!sailsim_load_elf(ctx, elf_file)) {
        fprintf(stderr, "Failed to load ELF: %s\n", sailsim_get_error(ctx));
        sailsim_destroy(ctx);
        return 1;
    }

    printf("Entry PC: 0x%lx\n", sailsim_get_pc(ctx));

    printf("\nSingle-stepping first 10 instructions:\n");
    printf("========================================\n");

    for (int i = 0; i < 10; i++) {
        uint64_t pc = sailsim_get_pc(ctx);
        printf("[%d] PC = 0x%016lx\n", i, pc);

        sailsim_step_result_t result = sailsim_step(ctx);

        if (result == SAILSIM_STEP_ERROR) {
            fprintf(stderr, "Step error: %s\n", sailsim_get_error(ctx));
            break;
        }

        if (result == SAILSIM_STEP_HALT) {
            printf("Execution halted\n");
            break;
        }
    }

    printf("\nRegister state:\n");
    printf("===============\n");
    for (int i = 0; i < 32; i += 4) {
        printf("x%-2d = 0x%016lx  x%-2d = 0x%016lx  x%-2d = 0x%016lx  x%-2d = 0x%016lx\n",
               i, sailsim_get_reg(ctx, i),
               i+1, sailsim_get_reg(ctx, i+1),
               i+2, sailsim_get_reg(ctx, i+2),
               i+3, sailsim_get_reg(ctx, i+3));
    }

    printf("\nCleaning up...\n");
    sailsim_destroy(ctx);

    printf("Done!\n");
    return 0;
}
