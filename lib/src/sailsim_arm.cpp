/**
 * @file sailsim_arm.cpp
 * @brief ARM (AArch64) implementation of Sail Simulator C API
 */

#include "sailsim.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// Include Sail headers
#include "sail.h"
#include "rts.h"

// ARM Sail functions (from ARM Sail generated C code)
extern "C" {
    // ARM Sail runtime
    void model_init(void);
    void zinit(unit);       // ARM processor cold reset

    // ARM register access
    sbits zaget_X(int64_t width, int64_t n);
    unit zaset_X(int64_t n, lbits value);

    // ARM memory access
    unit z__WriteMemory(sail_int N, uint64_t address, lbits value);
    void z__ReadMemory(lbits *result, sail_int N, uint64_t address);

    // ARM PC (global variable)
    extern uint64_t z_PC;

    // ARM execution
    unit zStep_CPU(unit);

    // Stub functions required by Sail runtime
    void model_pre_exit() {
        // Called before exit - no cleanup needed for ARM model
    }

    void sail_rts_set_coverage_file(const char *filename) {
        // Coverage tracking not used
        (void)filename;
    }
}

// ELF loader
#include "elf_loader.h"

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
 * Simulator context structure (ARM specific)
 */
struct sailsim_context {
    bool initialized;
    sailsim_isa_t isa;  // Always SAILSIM_ISA_ARM for this implementation
    uint64_t step_count;
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
        // ARM model does not have model_fini() - no cleanup needed
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
    ctx->isa = SAILSIM_ISA_ARM;  // This is the ARM implementation
    ctx->step_count = 0;
    ctx->config_str = nullptr;

    try {
        // Initialize Sail library (once)
        ensure_sail_library_initialized();

        // Initialize the Sail model ONCE globally (reference counted)
        ensure_sail_model_initialized();

        // ARM processor cold reset
        zinit(UNIT);

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

        // Validate this is an ARM ELF file
        ISA elf_isa = elf.isa();
        if (elf_isa != ISA::ARM) {
            ctx->last_error = "ELF file is not ARM (this library only supports ARM)";
            return false;
        }

        // Load segments into memory using ARM z__WriteMemory
        elf.load([](uint64_t addr, const uint8_t* data, uint64_t len) {
            for (uint64_t i = 0; i < len; i++) {
                // Create Sail types for memory write
                sail_int N;
                CREATE(sail_int)(&N);
                CONVERT_OF(sail_int, mach_int)(&N, 1);  // 1 byte

                lbits value;
                CREATE(lbits)(&value);
                CONVERT_OF(lbits, fbits)(&value, data[i], 8, true);

                z__WriteMemory(N, addr + i, value);

                KILL(lbits)(&value);
                KILL(sail_int)(&N);
            }
        });

        // Get entry point and set PC
        uint64_t entry_point = elf.entry();
        z_PC = entry_point;

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

    // ARM cold reset
    zinit(UNIT);

    ctx->step_count = 0;
}

sailsim_step_result_t sailsim_step(sailsim_context_t* ctx) {
    if (!ctx || !ctx->initialized) {
        return SAILSIM_STEP_ERROR;
    }

    try {
        // ARM: Check for SVC (supervisor call - ARM syscall)
        bool is_syscall = false;
        uint64_t pc = z_PC;
        uint32_t instr_word = 0;
        if (sailsim_read_mem(ctx, pc, &instr_word, 4)) {
            // SVC immediate encoding: 1101 0100 000i iiii iiii iiii iii0 0001
            // Check for SVC #0 specifically (common syscall pattern)
            is_syscall = ((instr_word & 0xFFE0001F) == 0xD4000001);
        }

        // Execute one ARM instruction
        zStep_CPU(UNIT);
        ctx->step_count++;

        // Handle syscall detection
        if (is_syscall) {
            // ARM: SVC is always 4 bytes
            uint64_t return_pc = pc + 4;
            sailsim_set_pc(ctx, return_pc);
            return SAILSIM_STEP_SYSCALL;
        }

        return SAILSIM_STEP_OK;

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

    while (max_steps == 0 || steps_executed < max_steps) {
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

    // ARM PC access
    return z_PC;
}

void sailsim_set_pc(sailsim_context_t* ctx, uint64_t pc) {
    if (!ctx || !ctx->initialized) return;

    // ARM PC write
    z_PC = pc;
}

uint64_t sailsim_get_reg(sailsim_context_t* ctx, int reg_num) {
    if (!ctx || !ctx->initialized || reg_num < 0 || reg_num > 31) {
        return 0;
    }

    // ARM: X31 is special (zero register or SP depending on context)
    // zaget_X handles this correctly
    sbits reg_value = zaget_X(64, reg_num);
    return get_sbits_value(reg_value);
}

void sailsim_set_reg(sailsim_context_t* ctx, int reg_num, uint64_t value) {
    if (!ctx || !ctx->initialized || reg_num < 0 || reg_num > 31) {
        return;
    }

    // ARM: zaset_X handles X31 (zero register) correctly
    lbits lvalue;
    CREATE(lbits)(&lvalue);
    CONVERT_OF(lbits, fbits)(&lvalue, value, 64, true);
    zaset_X(reg_num, lvalue);
    KILL(lbits)(&lvalue);
}

bool sailsim_read_mem(sailsim_context_t* ctx, uint64_t addr, void* buf, size_t len) {
    if (!ctx || !ctx->initialized || !buf || len == 0) {
        if (ctx) ctx->last_error = "Invalid parameters for memory read";
        return false;
    }

    try {
        uint8_t* byte_buf = (uint8_t*)buf;

        // ARM memory read
        for (size_t i = 0; i < len; i++) {
            sail_int N;
            CREATE(sail_int)(&N);
            CONVERT_OF(sail_int, mach_int)(&N, 1);  // 1 byte

            lbits result;
            CREATE(lbits)(&result);

            z__ReadMemory(&result, N, addr + i);
            byte_buf[i] = (uint8_t)(CONVERT_OF(fbits, lbits)(result, true) & 0xFF);

            KILL(lbits)(&result);
            KILL(sail_int)(&N);
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

        // ARM memory write
        for (size_t i = 0; i < len; i++) {
            sail_int N;
            CREATE(sail_int)(&N);
            CONVERT_OF(sail_int, mach_int)(&N, 1);  // 1 byte

            lbits value;
            CREATE(lbits)(&value);
            CONVERT_OF(lbits, fbits)(&value, byte_buf[i], 8, true);

            z__WriteMemory(N, addr + i, value);

            KILL(lbits)(&value);
            KILL(sail_int)(&N);
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
        // ARM disassembly not yet implemented
        // For now, just show the instruction word as hex
        uint32_t instr_word = 0;
        if (!sailsim_read_mem(ctx, addr, &instr_word, 4)) {
            snprintf(buf, bufsize, "<invalid address>");
            return false;
        }
        snprintf(buf, bufsize, ".word 0x%08x", instr_word);
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
