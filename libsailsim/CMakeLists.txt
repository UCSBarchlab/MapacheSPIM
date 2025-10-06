cmake_minimum_required(VERSION 3.15)
project(libsailsim VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Path to Sail RISC-V build directory
set(SAIL_RISCV_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../sail-riscv/build"
    CACHE PATH "Path to Sail RISC-V build directory")

# Find required libraries from Sail build
find_library(RISCV_MODEL_LIB riscv_model
    HINTS "${SAIL_RISCV_BUILD_DIR}/c_emulator"
    REQUIRED)

find_library(SAIL_RUNTIME_LIB sail_runtime
    HINTS "${SAIL_RISCV_BUILD_DIR}/sail_runtime"
    REQUIRED)

find_library(SOFTFLOAT_LIB softfloat
    HINTS "${SAIL_RISCV_BUILD_DIR}/dependencies/softfloat"
    REQUIRED)

find_library(GMP_LIB gmp
    HINTS "${SAIL_RISCV_BUILD_DIR}/gmp/lib"
    REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SAIL_RISCV_BUILD_DIR}
    ${SAIL_RISCV_BUILD_DIR}/c_emulator
    ${CMAKE_CURRENT_SOURCE_DIR}/../sail-riscv/c_emulator
    ${SAIL_RISCV_BUILD_DIR}/sail_runtime
    ${SAIL_RISCV_BUILD_DIR}/dependencies/softfloat
    ${SAIL_RISCV_BUILD_DIR}/gmp/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../sail-riscv/dependencies/elfio
    ${SAIL_RISCV_BUILD_DIR}/_deps/jsoncons-src/include
)

# Get Sail library directory from opam
execute_process(
    COMMAND opam var share
    OUTPUT_VARIABLE OPAM_SHARE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(SAIL_LIB_DIR "${OPAM_SHARE_DIR}/sail/lib")

include_directories(${SAIL_LIB_DIR})

# Source files
set(LIBSAILSIM_SOURCES
    sailsim.cpp
)

# Create shared library
add_library(sailsim SHARED ${LIBSAILSIM_SOURCES})

# Link against required libraries
target_link_libraries(sailsim
    ${RISCV_MODEL_LIB}
    ${SAIL_RUNTIME_LIB}
    ${SOFTFLOAT_LIB}
    ${GMP_LIB}
)

# Set output name
set_target_properties(sailsim PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    OUTPUT_NAME "sailsim"
)

# Install targets
install(TARGETS sailsim
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES sailsim.h DESTINATION include)

# Test executable (optional)
add_executable(test_sailsim test_sailsim.c)
target_link_libraries(test_sailsim sailsim)
