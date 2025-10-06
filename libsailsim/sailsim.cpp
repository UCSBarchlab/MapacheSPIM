/**
 * @file sailsim.cpp
 * @brief Implementation of Sail RISC-V Simulator C API
 */

#include "sailsim.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// Include Sail headers (NOT in extern "C" - sail.h includes gmp.h with C++ linkage)
#include "sail.h"
#include "rts.h"
#include "sail_riscv_model.h"
#include "riscv_platform_impl.h"
#include "riscv_sail.h"
#include "elf_loader.h"
#include "config_utils.h"

// Global configuration variables expected by Sail RISC-V model
bool config_print_instr = false;
bool config_print_reg = false;
bool config_print_mem_access = false;
bool config_print_platform = false;
bool config_print_rvfi = false;
bool config_print_step = false;
bool config_use_abi_names = false;
bool config_enable_rvfi = false;
FILE *trace_log = stdout;

// Helper functions for sbits conversion
static inline sbits make_sbits(uint64_t value) {
    sbits result;
    result.bits = value;
    result.len = 64;
    return result;
}

static inline uint64_t get_sbits_value(sbits s) {
    return s.bits;
}

/**
 * Simulator context structure
 */
struct sailsim_context {
    bool initialized;
    uint64_t step_count;
    bool htif_done;
    int64_t htif_exit_code;
    std::string last_error;
    char* config_str;
};

// Global flag to track if Sail library is initialized
static bool g_sail_library_initialized = false;

/**
 * Initialize Sail library (call once)
 */
static void ensure_sail_library_initialized() {
    if (!g_sail_library_initialized) {
        setup_library();
        g_sail_library_initialized = true;
    }
}

extern "C" {

sailsim_context_t* sailsim_init(const char* config_file) {
    sailsim_context_t* ctx = new sailsim_context_t();
    if (!ctx) {
        return nullptr;
    }

    ctx->initialized = false;
    ctx->step_count = 0;
    ctx->htif_done = false;
    ctx->htif_exit_code = 0;
    ctx->config_str = nullptr;

    try {
        // Initialize Sail library (once)
        ensure_sail_library_initialized();

        // Load configuration into Sail's global config system
        if (config_file && config_file[0] != '\0') {
            ctx->config_str = strdup(config_file);
            sail_config_set_file(config_file);
        } else {
            // No config file - use the built-in default config JSON string
            const char* default_cfg = get_default_config();
            ctx->config_str = strdup(default_cfg);
            sail_config_set_string(default_cfg);
        }

        // Set configured types from loaded config (BEFORE model_init)
        init_sail_configured_types();

        // Initialize the Sail model (GMP variables, registers, etc.)
        model_init();

        // Set initial PC (must be BEFORE zinit_model because reset happens inside)
        zset_pc_reset_address(0x80000000);

        // Initialize model with config (loads config string and resets)
        zinit_model(ctx->config_str);

        // Boot requirements
        zinit_boot_requirements(UNIT);

        ctx->initialized = true;
        return ctx;

    } catch (const std::exception& e) {
        ctx->last_error = std::string("Initialization failed: ") + e.what();
        delete ctx;
        return nullptr;
    }
}

void sailsim_destroy(sailsim_context_t* ctx) {
    if (!ctx) return;

    if (ctx->initialized) {
        model_fini();
    }

    if (ctx->config_str) {
        free(ctx->config_str);
    }

    delete ctx;
}

bool sailsim_load_elf(sailsim_context_t* ctx, const char* elf_path) {
    if (!ctx || !ctx->initialized || !elf_path) {
        if (ctx) ctx->last_error = "Invalid context or ELF path";
        return false;
    }

    try {
        // Load ELF file using ELF class from elf_loader.h
        ELF elf = ELF::open(elf_path);

        // Load segments into memory
        elf.load([](uint64_t addr, const uint8_t* data, uint64_t len) {
            for (uint64_t i = 0; i < len; i++) {
                write_mem(addr + i, data[i]);
            }
        });

        // Get entry point and set PC
        uint64_t entry_point = elf.entry();
        zPC = make_sbits(entry_point);
        znextPC = make_sbits(entry_point);

        return true;

    } catch (const std::exception& e) {
        ctx->last_error = std::string("ELF load failed: ") + e.what();
        return false;
    }
}

void sailsim_reset(sailsim_context_t* ctx) {
    if (!ctx || !ctx->initialized) return;

    // Reset registers (Sail function)
    zinitializze_registers(UNIT);

    ctx->step_count = 0;
    ctx->htif_done = false;
    ctx->htif_exit_code = 0;
}

sailsim_step_result_t sailsim_step(sailsim_context_t* ctx) {
    if (!ctx || !ctx->initialized) {
        return SAILSIM_STEP_ERROR;
    }

    if (ctx->htif_done) {
        return SAILSIM_STEP_HALT;
    }

    try {
        // Create Sail integer for step number
        sail_int step_num;
        CREATE(sail_int)(&step_num);
        CONVERT_OF(sail_int, mach_int)(&step_num, ctx->step_count);

        // Execute one step
        bool is_waiting = ztry_step(step_num, true);

        KILL(sail_int)(&step_num);

        if (!is_waiting) {
            ctx->step_count++;
        }

        // Check if HTIF signaled done
        if (zhtif_done) {
            ctx->htif_done = true;
            ctx->htif_exit_code = zhtif_exit_code;
            return SAILSIM_STEP_HALT;
        }

        return is_waiting ? SAILSIM_STEP_WAITING : SAILSIM_STEP_OK;

    } catch (const std::exception& e) {
        ctx->last_error = std::string("Step failed: ") + e.what();
        return SAILSIM_STEP_ERROR;
    }
}

uint64_t sailsim_run(sailsim_context_t* ctx, uint64_t max_steps) {
    if (!ctx || !ctx->initialized) {
        return 0;
    }

    uint64_t steps_executed = 0;

    while (!ctx->htif_done && (max_steps == 0 || steps_executed < max_steps)) {
        sailsim_step_result_t result = sailsim_step(ctx);

        if (result == SAILSIM_STEP_ERROR) {
            break;
        }

        if (result == SAILSIM_STEP_OK) {
            steps_executed++;
        }

        if (result == SAILSIM_STEP_HALT) {
            break;
        }
    }

    return steps_executed;
}

uint64_t sailsim_get_pc(sailsim_context_t* ctx) {
    if (!ctx || !ctx->initialized) {
        return 0;
    }

    return get_sbits_value(zPC);
}

void sailsim_set_pc(sailsim_context_t* ctx, uint64_t pc) {
    if (!ctx || !ctx->initialized) return;

    zPC = make_sbits(pc);
    znextPC = make_sbits(pc);
}

uint64_t sailsim_get_reg(sailsim_context_t* ctx, int reg_num) {
    if (!ctx || !ctx->initialized || reg_num < 0 || reg_num > 31) {
        return 0;
    }

    // x0 is always 0
    if (reg_num == 0) {
        return 0;
    }

    // Use Sail's rX function to read register
    sbits reg_value = zrX(reg_num);
    return get_sbits_value(reg_value);
}

void sailsim_set_reg(sailsim_context_t* ctx, int reg_num, uint64_t value) {
    if (!ctx || !ctx->initialized || reg_num <= 0 || reg_num > 31) {
        return;
    }

    // Setting x0 is a no-op
    if (reg_num == 0) {
        return;
    }

    // Use Sail's wX function to write register
    zwX(reg_num, make_sbits(value));
}

bool sailsim_read_mem(sailsim_context_t* ctx, uint64_t addr, void* buf, size_t len) {
    if (!ctx || !ctx->initialized || !buf || len == 0) {
        if (ctx) ctx->last_error = "Invalid parameters for memory read";
        return false;
    }

    try {
        uint8_t* byte_buf = (uint8_t*)buf;

        for (size_t i = 0; i < len; i++) {
            // Use Sail's read_mem platform function (takes uint64_t)
            mach_bits byte_val = read_mem(addr + i);
            byte_buf[i] = (uint8_t)(byte_val & 0xFF);
        }

        return true;

    } catch (const std::exception& e) {
        ctx->last_error = std::string("Memory read failed: ") + e.what();
        return false;
    }
}

bool sailsim_write_mem(sailsim_context_t* ctx, uint64_t addr, const void* buf, size_t len) {
    if (!ctx || !ctx->initialized || !buf || len == 0) {
        if (ctx) ctx->last_error = "Invalid parameters for memory write";
        return false;
    }

    try {
        const uint8_t* byte_buf = (const uint8_t*)buf;

        for (size_t i = 0; i < len; i++) {
            // Use Sail's write_mem platform function (takes uint64_t)
            write_mem(addr + i, byte_buf[i]);
        }

        return true;

    } catch (const std::exception& e) {
        ctx->last_error = std::string("Memory write failed: ") + e.what();
        return false;
    }
}

bool sailsim_disasm(sailsim_context_t* ctx, uint64_t addr, char* buf, size_t bufsize) {
    if (!ctx || !ctx->initialized || !buf || bufsize == 0) {
        if (ctx) ctx->last_error = "Invalid parameters for disassembly";
        return false;
    }

    // TODO: Implement using Sail's disassembly functions
    // For now, just return a placeholder
    snprintf(buf, bufsize, "<disasm at 0x%lx not yet implemented>", addr);
    return false;
}

const char* sailsim_get_error(sailsim_context_t* ctx) {
    if (!ctx) {
        return "Invalid context";
    }
    return ctx->last_error.c_str();
}

} // extern "C"
