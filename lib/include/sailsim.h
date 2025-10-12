/**
 * @file sailsim.h
 * @brief C API for Sail RISC-V Simulator
 *
 * This header provides a simple C API for controlling the Sail RISC-V
 * formal specification emulator. It wraps the Sail-generated C code
 * to provide a clean interface for Python bindings and other tools.
 */

#ifndef SAILSIM_H
#define SAILSIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Supported ISAs
 */
typedef enum {
    SAILSIM_ISA_RISCV = 0,
    SAILSIM_ISA_ARM = 1,
    SAILSIM_ISA_UNKNOWN = -1
} sailsim_isa_t;

/**
 * Opaque simulator context handle
 */
typedef struct sailsim_context sailsim_context_t;

/**
 * Step result codes
 */
typedef enum {
    SAILSIM_STEP_OK = 0,           /**< Step completed successfully */
    SAILSIM_STEP_HALT = 1,         /**< Execution halted (HTIF done) */
    SAILSIM_STEP_WAITING = 2,      /**< Processor is waiting */
    SAILSIM_STEP_SYSCALL = 3,      /**< Syscall instruction executed */
    SAILSIM_STEP_ERROR = -1        /**< Error occurred during step */
} sailsim_step_result_t;

/**
 * Initialize the simulator
 *
 * @param config_file Optional JSON configuration file path (can be NULL for default)
 * @return Simulator context handle, or NULL on failure
 */
sailsim_context_t* sailsim_init(const char* config_file);

/**
 * Clean up and destroy simulator context
 *
 * @param ctx Simulator context to destroy
 */
void sailsim_destroy(sailsim_context_t* ctx);

/**
 * Get ISA type of loaded ELF
 *
 * @param ctx Simulator context
 * @return ISA type (SAILSIM_ISA_UNKNOWN if no ELF loaded)
 */
sailsim_isa_t sailsim_get_isa(sailsim_context_t* ctx);

/**
 * Load an ELF file into simulator memory
 *
 * @param ctx Simulator context
 * @param elf_path Path to RISC-V or ARM ELF file
 * @return true on success, false on failure
 */
bool sailsim_load_elf(sailsim_context_t* ctx, const char* elf_path);

/**
 * Reset processor state
 *
 * @param ctx Simulator context
 */
void sailsim_reset(sailsim_context_t* ctx);

/**
 * Execute one instruction
 *
 * @param ctx Simulator context
 * @return Step result code
 */
sailsim_step_result_t sailsim_step(sailsim_context_t* ctx);

/**
 * Run until halt or instruction limit
 *
 * @param ctx Simulator context
 * @param max_steps Maximum number of instructions to execute (0 = unlimited)
 * @return Number of instructions executed
 */
uint64_t sailsim_run(sailsim_context_t* ctx, uint64_t max_steps);

/**
 * Get current program counter
 *
 * @param ctx Simulator context
 * @return Current PC value
 */
uint64_t sailsim_get_pc(sailsim_context_t* ctx);

/**
 * Set program counter
 *
 * @param ctx Simulator context
 * @param pc New PC value
 */
void sailsim_set_pc(sailsim_context_t* ctx, uint64_t pc);

/**
 * Get general-purpose register value
 *
 * @param ctx Simulator context
 * @param reg_num Register number (0-31)
 * @return Register value (0 for x0, actual value for x1-x31)
 */
uint64_t sailsim_get_reg(sailsim_context_t* ctx, int reg_num);

/**
 * Set general-purpose register value
 *
 * @param ctx Simulator context
 * @param reg_num Register number (1-31, setting x0 is a no-op)
 * @param value New register value
 */
void sailsim_set_reg(sailsim_context_t* ctx, int reg_num, uint64_t value);

/**
 * Read memory
 *
 * @param ctx Simulator context
 * @param addr Memory address
 * @param buf Buffer to store read data
 * @param len Number of bytes to read
 * @return true on success, false on failure (invalid address, etc.)
 */
bool sailsim_read_mem(sailsim_context_t* ctx, uint64_t addr, void* buf, size_t len);

/**
 * Write memory
 *
 * @param ctx Simulator context
 * @param addr Memory address
 * @param buf Data to write
 * @param len Number of bytes to write
 * @return true on success, false on failure (invalid address, etc.)
 */
bool sailsim_write_mem(sailsim_context_t* ctx, uint64_t addr, const void* buf, size_t len);

/**
 * Disassemble instruction at given address
 *
 * @param ctx Simulator context
 * @param addr Address of instruction
 * @param buf Buffer to store disassembly string
 * @param bufsize Size of buffer
 * @return true on success, false on failure
 */
bool sailsim_disasm(sailsim_context_t* ctx, uint64_t addr, char* buf, size_t bufsize);

/**
 * Get last error message
 *
 * @param ctx Simulator context
 * @return Error message string (valid until next API call)
 */
const char* sailsim_get_error(sailsim_context_t* ctx);

/**
 * Get number of symbols in symbol table
 *
 * @param ctx Simulator context
 * @return Number of symbols (0 if no ELF loaded or no symbols)
 */
size_t sailsim_get_symbol_count(sailsim_context_t* ctx);

/**
 * Get symbol by index
 *
 * @param ctx Simulator context
 * @param index Symbol index (0 to count-1)
 * @param name_buf Buffer to store symbol name
 * @param name_bufsize Size of name buffer
 * @param addr Pointer to store symbol address
 * @return true on success, false if index out of range
 */
bool sailsim_get_symbol_by_index(sailsim_context_t* ctx, size_t index,
                                  char* name_buf, size_t name_bufsize,
                                  uint64_t* addr);

/**
 * Look up symbol address by name
 *
 * @param ctx Simulator context
 * @param name Symbol name to look up
 * @param addr Pointer to store symbol address
 * @return true if found, false if not found
 */
bool sailsim_lookup_symbol(sailsim_context_t* ctx, const char* name, uint64_t* addr);

/**
 * Convert address to symbol name
 *
 * @param ctx Simulator context
 * @param addr Address to look up
 * @param name_buf Buffer to store symbol name
 * @param name_bufsize Size of name buffer
 * @param offset Pointer to store offset from symbol (can be NULL)
 * @return true if symbol found near address, false otherwise
 */
bool sailsim_addr_to_symbol(sailsim_context_t* ctx, uint64_t addr,
                             char* name_buf, size_t name_bufsize,
                             uint64_t* offset);

#ifdef __cplusplus
}
#endif

#endif /* SAILSIM_H */
