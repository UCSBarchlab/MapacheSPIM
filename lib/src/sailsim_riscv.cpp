/**
 * @file sailsim_riscv.cpp
 * @brief RISC-V implementation of Sail Simulator C API
 */

#include "sailsim.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// Include Sail headers (NOT in extern "C" - sail.h includes gmp.h with C++ linkage)
#include "sail.h"
#include "rts.h"

// RISC-V Sail headers
#include "sail_riscv_model.h"
#include "riscv_platform_impl.h"
#include "riscv_sail.h"
#include "config_utils.h"

// ELF loader
#include "elf_loader.h"

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
 * Simulator context structure (RISC-V specific)
 */
struct sailsim_context {
    bool initialized;
    sailsim_isa_t isa;  // Always SAILSIM_ISA_RISCV for this implementation
    uint64_t step_count;
    bool htif_done;
    int64_t htif_exit_code;
    std::string last_error;
    char* config_str;
    std::map<std::string, uint64_t> symbols;  // Symbol name → address
    std::map<uint64_t, std::string> addr_to_symbol;  // Address → symbol name
};

// Global flags to track initialization
static bool g_sail_library_initialized = false;
static bool g_sail_model_initialized = false;
static int g_simulator_instance_count = 0;

/**
 * Initialize Sail library (call once)
 */
static void ensure_sail_library_initialized() {
    if (!g_sail_library_initialized) {
        setup_library();
        g_sail_library_initialized = true;
    }
}

/**
 * Initialize Sail model (call once for all simulators)
 */
static void ensure_sail_model_initialized() {
    if (!g_sail_model_initialized) {
        model_init();
        g_sail_model_initialized = true;
    }
    g_simulator_instance_count++;
}

/**
 * Cleanup Sail model when last simulator is destroyed
 */
static void cleanup_sail_model_if_last() {
    g_simulator_instance_count--;
    if (g_simulator_instance_count == 0 && g_sail_model_initialized) {
        model_fini();
        g_sail_model_initialized = false;
    }
}

extern "C" {

sailsim_isa_t sailsim_detect_elf_isa(const char* elf_path) {
    if (!elf_path) {
        return SAILSIM_ISA_UNKNOWN;
    }

    try {
        ELF elf = ELF::open(elf_path);
        ISA elf_isa = elf.isa();

        switch (elf_isa) {
            case ISA::RISCV:
                return SAILSIM_ISA_RISCV;
            case ISA::ARM:
                return SAILSIM_ISA_ARM;
            default:
                return SAILSIM_ISA_UNKNOWN;
        }
    } catch (const std::exception& e) {
        return SAILSIM_ISA_UNKNOWN;
    }
}

sailsim_context_t* sailsim_init(const char* config_file) {
    sailsim_context_t* ctx = new sailsim_context_t();
    if (!ctx) {
        return nullptr;
    }

    ctx->initialized = false;
    ctx->isa = SAILSIM_ISA_RISCV;  // This is the RISC-V implementation
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

        // Initialize the Sail model ONCE globally (reference counted)
        ensure_sail_model_initialized();

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
        // Only call model_fini when the last simulator is destroyed
        cleanup_sail_model_if_last();
    }

    if (ctx->config_str) {
        free(ctx->config_str);
    }

    delete ctx;
}

sailsim_isa_t sailsim_get_isa(sailsim_context_t* ctx) {
    if (!ctx) {
        return SAILSIM_ISA_UNKNOWN;
    }
    return ctx->isa;
}

bool sailsim_load_elf(sailsim_context_t* ctx, const char* elf_path) {
    if (!ctx || !ctx->initialized || !elf_path) {
        if (ctx) ctx->last_error = "Invalid context or ELF path";
        return false;
    }

    try {
        // Load ELF file using ELF class from elf_loader.h
        ELF elf = ELF::open(elf_path);

        // Validate this is a RISC-V ELF file
        ISA elf_isa = elf.isa();
        if (elf_isa != ISA::RISCV) {
            ctx->last_error = "ELF file is not RISC-V (this library only supports RISC-V)";
            return false;
        }

        // Load segments into memory using RISC-V write_mem
        elf.load([](uint64_t addr, const uint8_t* data, uint64_t len) {
            for (uint64_t i = 0; i < len; i++) {
                write_mem(addr + i, data[i]);
            }
        });

        // Get entry point and set PC
        uint64_t entry_point = elf.entry();
        zPC = make_sbits(entry_point);
        znextPC = make_sbits(entry_point);

        // Load symbol table
        ctx->symbols = elf.symbols();
        ctx->addr_to_symbol.clear();
        for (const auto& [name, addr] : ctx->symbols) {
            ctx->addr_to_symbol[addr] = name;
        }

        return true;

    } catch (const std::exception& e) {
        ctx->last_error = std::string("ELF load failed: ") + e.what();
        return false;
    }
}

void sailsim_reset(sailsim_context_t* ctx) {
    if (!ctx || !ctx->initialized) return;

    // Reset RISC-V processor
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
        // Check for ecall (RISC-V syscall)
        bool is_syscall = false;
        uint64_t pc = get_sbits_value(zPC);
        uint32_t instr_word = 0;
        if (sailsim_read_mem(ctx, pc, &instr_word, 4)) {
            is_syscall = (instr_word == 0x00000073);  // ecall encoding
        }

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

        // Handle syscall detection
        if (is_syscall && !is_waiting) {
            uint64_t return_pc = pc + 4;
            sailsim_set_pc(ctx, return_pc);
            return SAILSIM_STEP_SYSCALL;
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

    // RISC-V PC access
    return get_sbits_value(zPC);
}

void sailsim_set_pc(sailsim_context_t* ctx, uint64_t pc) {
    if (!ctx || !ctx->initialized) return;

    // RISC-V PC write
    zPC = make_sbits(pc);
    znextPC = make_sbits(pc);
}

uint64_t sailsim_get_reg(sailsim_context_t* ctx, int reg_num) {
    if (!ctx || !ctx->initialized || reg_num < 0 || reg_num > 31) {
        return 0;
    }

    // RISC-V: x0 is always 0
    if (reg_num == 0) {
        return 0;
    }
    sbits reg_value = zrX(reg_num);
    return get_sbits_value(reg_value);
}

void sailsim_set_reg(sailsim_context_t* ctx, int reg_num, uint64_t value) {
    if (!ctx || !ctx->initialized || reg_num < 0 || reg_num > 31) {
        return;
    }

    // RISC-V: Setting x0 is a no-op
    if (reg_num == 0) {
        return;
    }
    zwX(reg_num, make_sbits(value));
}

bool sailsim_read_mem(sailsim_context_t* ctx, uint64_t addr, void* buf, size_t len) {
    if (!ctx || !ctx->initialized || !buf || len == 0) {
        if (ctx) ctx->last_error = "Invalid parameters for memory read";
        return false;
    }

    try {
        uint8_t* byte_buf = (uint8_t*)buf;

        // RISC-V memory read
        for (size_t i = 0; i < len; i++) {
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

        // RISC-V memory write
        for (size_t i = 0; i < len; i++) {
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

    try {
        // Read instruction word from memory
        uint32_t instr_word = 0;
        if (!sailsim_read_mem(ctx, addr, &instr_word, 4)) {
            snprintf(buf, bufsize, "<invalid address>");
            return false;
        }

        // Decode the instruction using Sail's decoder
        zinstruction decoded_instr;
        zencdec_backwards(&decoded_instr, instr_word);

        // Convert instruction to assembly string using Sail's formatter
        sail_string asm_str;
        CREATE(sail_string)(&asm_str);

        // zassembly_forwards converts instruction struct to assembly string
        zassembly_forwards(&asm_str, decoded_instr);

        // Copy to output buffer
        if (asm_str != NULL && *asm_str != '\0') {
            snprintf(buf, bufsize, "%s", asm_str);
        } else {
            // Fallback to hex if assembly failed
            snprintf(buf, bufsize, ".word 0x%08x", instr_word);
        }

        // Clean up Sail data structures
        KILL(sail_string)(&asm_str);

        return true;

    } catch (const std::exception& e) {
        ctx->last_error = std::string("Disassembly error: ") + e.what();
        snprintf(buf, bufsize, "<error>");
        return false;
    } catch (...) {
        ctx->last_error = "Unknown disassembly error";
        snprintf(buf, bufsize, "<error>");
        return false;
    }
}

const char* sailsim_get_error(sailsim_context_t* ctx) {
    if (!ctx) {
        return "Invalid context";
    }
    return ctx->last_error.c_str();
}

// Symbol table API
size_t sailsim_get_symbol_count(sailsim_context_t* ctx) {
    if (!ctx || !ctx->initialized) {
        return 0;
    }
    return ctx->symbols.size();
}

bool sailsim_get_symbol_by_index(sailsim_context_t* ctx, size_t index,
                                  char* name_buf, size_t name_bufsize,
                                  uint64_t* addr) {
    if (!ctx || !ctx->initialized || !name_buf || !addr) {
        return false;
    }

    if (index >= ctx->symbols.size()) {
        return false;
    }

    auto it = ctx->symbols.begin();
    std::advance(it, index);

    snprintf(name_buf, name_bufsize, "%s", it->first.c_str());
    *addr = it->second;
    return true;
}

bool sailsim_lookup_symbol(sailsim_context_t* ctx, const char* name, uint64_t* addr) {
    if (!ctx || !ctx->initialized || !name || !addr) {
        return false;
    }

    auto it = ctx->symbols.find(name);
    if (it == ctx->symbols.end()) {
        return false;
    }

    *addr = it->second;
    return true;
}

bool sailsim_addr_to_symbol(sailsim_context_t* ctx, uint64_t addr,
                             char* name_buf, size_t name_bufsize,
                             uint64_t* offset) {
    if (!ctx || !ctx->initialized || !name_buf) {
        return false;
    }

    // Find the symbol at or before this address
    auto it = ctx->addr_to_symbol.upper_bound(addr);
    if (it != ctx->addr_to_symbol.begin()) {
        --it;
        uint64_t symbol_addr = it->first;
        const std::string& symbol_name = it->second;

        // Check if address is reasonably close (within 4KB of symbol)
        if (addr - symbol_addr < 4096) {
            snprintf(name_buf, name_bufsize, "%s", symbol_name.c_str());
            if (offset) {
                *offset = addr - symbol_addr;
            }
            return true;
        }
    }

    return false;
}

} // extern "C"
