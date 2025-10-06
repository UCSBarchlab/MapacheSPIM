# RISC-V Assembly Examples for Sail Emulator

Educational RISC-V assembly programs for second-year CS students.

## Contents

1. Matrix Multiplication (matrix_multiply/) - 3x3 matrix multiply with nested loops
2. Fibonacci Calculator (fibonacci/) - Recursive Fibonacci implementation

## Prerequisites

RISC-V GNU Toolchain:
  macOS:    brew tap riscv-software-src/riscv && brew install riscv-tools
  Ubuntu:   sudo apt-get install gcc-riscv64-unknown-elf

Sail RISC-V Emulator should be at: ../sail-riscv/build/c_emulator/sail_riscv_sim

## Building

Build all examples:
  make

Build individual programs:
  make matrix
  make fibonacci

Check your environment:
  make check-tools

## Running

Run with instruction trace:
  make run-matrix
  make run-fibonacci

Run with memory trace:
  make run-matrix-mem
  make run-fibonacci-mem

Manual execution:
  ../sail-riscv/build/c_emulator/sail_riscv_sim --trace-instr matrix_multiply/matrix_mult

## Understanding Output

Trace format: [N] [M]: 0xADDRESS (0xENCODING) instruction  label+offset

Example:
  [5] [M]: 0x80000060 (0x00000293) addi x5, x0, 0x0  reset_vector+16

Where:
  [N]         = instruction number
  [M]         = privilege mode (M=Machine, S=Supervisor, U=User)
  0xADDRESS   = program counter
  0xENCODING  = instruction encoding
  instruction = disassembled instruction

## Program Details

Matrix Multiplication:
  Input:  A = [1 2 3; 4 5 6; 7 8 9]  B = [9 8 7; 6 5 4; 3 2 1]
  Output: C = [30 24 18; 84 69 54; 138 114 90]

  Demonstrates: nested loops, memory addressing, multiply-accumulate

Fibonacci:
  Input:  n = 7
  Output: F(7) = 13

  Demonstrates: recursion, stack frames, calling convention, register save/restore

## Viewing Disassembly

  make dis-matrix
  make dis-fibonacci

Or:
  riscv64-unknown-elf-objdump -d matrix_multiply/matrix_mult

## Debugging

Limit instruction count:
  sail_riscv_sim --inst-limit 1000 program.elf

Enable all traces:
  sail_riscv_sim --trace-instr --trace-mem --trace-reg program.elf

## Cleaning Up

  make clean
