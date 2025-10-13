cmake_minimum_required(VERSION 3.15)
project(libsailsim VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Get Sail library directory from opam
execute_process(
    COMMAND opam var share
    OUTPUT_VARIABLE OPAM_SHARE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(SAIL_LIB_DIR "${OPAM_SHARE_DIR}/sail/lib")

#==============================================================================
# RISC-V Library Configuration
#==============================================================================

# Path to Sail RISC-V build directory
set(SAIL_RISCV_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../backends/riscv/sail-riscv/build"
    CACHE PATH "Path to Sail RISC-V build directory")

# Find RISC-V required libraries
find_library(RISCV_MODEL_LIB riscv_model
    HINTS "${SAIL_RISCV_BUILD_DIR}/c_emulator"
    REQUIRED)

find_library(RISCV_SAIL_RUNTIME_LIB sail_runtime
    HINTS "${SAIL_RISCV_BUILD_DIR}/sail_runtime"
    REQUIRED)

find_library(RISCV_SOFTFLOAT_LIB softfloat
    HINTS "${SAIL_RISCV_BUILD_DIR}/dependencies/softfloat"
    REQUIRED)

find_library(RISCV_GMP_LIB gmp
    HINTS "${SAIL_RISCV_BUILD_DIR}/gmp/lib"
    REQUIRED)

# Create RISC-V shared library (include ELF loader)
add_library(sailsim_riscv SHARED
    src/sailsim_riscv.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../backends/riscv/sail-riscv/c_emulator/elf_loader.cpp
)

# RISC-V include directories
target_include_directories(sailsim_riscv PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SAIL_RISCV_BUILD_DIR}
    ${SAIL_RISCV_BUILD_DIR}/c_emulator
    ${CMAKE_CURRENT_SOURCE_DIR}/../backends/riscv/sail-riscv/c_emulator
    ${SAIL_RISCV_BUILD_DIR}/sail_runtime
    ${SAIL_RISCV_BUILD_DIR}/dependencies/softfloat
    ${SAIL_RISCV_BUILD_DIR}/gmp/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../backends/riscv/sail-riscv/dependencies/elfio
    ${SAIL_RISCV_BUILD_DIR}/_deps/jsoncons-src/include
    ${SAIL_LIB_DIR}
)

# Link RISC-V library
target_link_libraries(sailsim_riscv
    ${RISCV_MODEL_LIB}
    ${RISCV_SAIL_RUNTIME_LIB}
    ${RISCV_SOFTFLOAT_LIB}
    ${RISCV_GMP_LIB}
)

# Set RISC-V library properties
set_target_properties(sailsim_riscv PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    OUTPUT_NAME "sailsim_riscv"
    INSTALL_RPATH_USE_LINK_PATH TRUE
    BUILD_RPATH "${CMAKE_CURRENT_BINARY_DIR}"
)

#==============================================================================
# ARM Library Configuration (OPTIONAL)
#==============================================================================

# Path to ARM Sail build directory
set(SAIL_ARM_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../backends/arm/build"
    CACHE PATH "Path to ARM Sail build directory")

# Find ARM required libraries (optional)
find_library(ARM_MODEL_LIB arm_sail_model
    HINTS "${SAIL_ARM_BUILD_DIR}")

find_library(ARM_SAIL_RUNTIME_LIB sail_runtime
    HINTS "${SAIL_ARM_BUILD_DIR}/sail_runtime")

find_library(ARM_GMP_LIB gmp
    HINTS "${SAIL_ARM_BUILD_DIR}/gmp/lib")

# Only build ARM library if all dependencies are found
if(ARM_MODEL_LIB AND ARM_SAIL_RUNTIME_LIB AND ARM_GMP_LIB)
    message(STATUS "ARM Sail model found - building sailsim_arm library")

    # Create ARM shared library (include ELF loader)
    add_library(sailsim_arm SHARED
        src/sailsim_arm.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../backends/riscv/sail-riscv/c_emulator/elf_loader.cpp
    )

    # ARM include directories
    target_include_directories(sailsim_arm PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${SAIL_ARM_BUILD_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../backends/riscv/sail-riscv/c_emulator
        ${CMAKE_CURRENT_SOURCE_DIR}/../backends/riscv/sail-riscv/dependencies/elfio
        ${SAIL_ARM_BUILD_DIR}/sail_runtime
        ${SAIL_ARM_BUILD_DIR}/gmp/include
        ${SAIL_LIB_DIR}
    )

    # Link ARM library
    target_link_libraries(sailsim_arm
        ${ARM_MODEL_LIB}
        ${ARM_SAIL_RUNTIME_LIB}
        ${ARM_GMP_LIB}
    )

    # Set ARM library properties
    set_target_properties(sailsim_arm PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 0
        OUTPUT_NAME "sailsim_arm"
        INSTALL_RPATH_USE_LINK_PATH TRUE
        BUILD_RPATH "${CMAKE_CURRENT_BINARY_DIR}"
    )

    set(BUILD_ARM_LIBRARY TRUE)
else()
    message(STATUS "ARM Sail model not found - skipping sailsim_arm library")
    set(BUILD_ARM_LIBRARY FALSE)
endif()

#==============================================================================
# Installation
#==============================================================================

if(BUILD_ARM_LIBRARY)
    install(TARGETS sailsim_riscv sailsim_arm
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
    )
else()
    install(TARGETS sailsim_riscv
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
    )
endif()

install(FILES include/sailsim.h DESTINATION include)

#==============================================================================
# Test Executables (optional)
#==============================================================================

# Test RISC-V library
add_executable(test_sailsim_riscv src/test_sailsim.c)
target_include_directories(test_sailsim_riscv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_sailsim_riscv sailsim_riscv)
set_target_properties(test_sailsim_riscv PROPERTIES
    INSTALL_RPATH_USE_LINK_PATH TRUE
    BUILD_RPATH "${CMAKE_CURRENT_BINARY_DIR}"
)

# Test ARM library (if built)
if(BUILD_ARM_LIBRARY)
    add_executable(test_sailsim_arm src/test_sailsim.c)
    target_include_directories(test_sailsim_arm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(test_sailsim_arm sailsim_arm)
    set_target_properties(test_sailsim_arm PROPERTIES
        INSTALL_RPATH_USE_LINK_PATH TRUE
        BUILD_RPATH "${CMAKE_CURRENT_BINARY_DIR}"
    )
endif()
