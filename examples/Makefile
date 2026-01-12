# Makefile for building MapacheSPIM example programs
#
# Usage:
#   make          - build all examples
#   make debug    - build all examples with debug info (-g flag)
#   make clean    - remove generated binaries
#   make riscv    - build only RISC-V examples
#   make mips     - build only MIPS examples
#   make arm      - build only ARM64 examples
#   make x86_64   - build only x86-64 examples
#
# For debug builds:
#   make debug            - build all with debug info
#   make DEBUG=1          - same as 'make debug'
#   make DEBUG=1 riscv    - build RISC-V with debug info

AS = mapachespim-as
ASFLAGS =

# Add -g flag for debug builds
ifdef DEBUG
ASFLAGS += -g
endif

# Find all assembly source files
RISCV_SRCS   := $(wildcard riscv/*/*.s)
MIPS_SRCS    := $(wildcard mips/*/*.s)
ARM_SRCS     := $(wildcard arm/*/*.s)
X86_64_SRCS  := $(wildcard x86_64/*/*.s) $(wildcard x86_64/*/*.S)

# Generate binary names (strip .s or .S extension)
RISCV_BINS   := $(RISCV_SRCS:.s=)
MIPS_BINS    := $(MIPS_SRCS:.s=)
ARM_BINS     := $(ARM_SRCS:.s=)
X86_64_BINS  := $(patsubst %.S,%,$(patsubst %.s,%,$(X86_64_SRCS)))

ALL_BINS     := $(RISCV_BINS) $(MIPS_BINS) $(ARM_BINS) $(X86_64_BINS)

.PHONY: all clean riscv mips arm x86_64 debug

all: $(ALL_BINS)
	@echo "Built $(words $(ALL_BINS)) example programs"

debug: ASFLAGS += -g
debug: all

riscv: $(RISCV_BINS)
	@echo "Built $(words $(RISCV_BINS)) RISC-V examples"

mips: $(MIPS_BINS)
	@echo "Built $(words $(MIPS_BINS)) MIPS examples"

arm: $(ARM_BINS)
	@echo "Built $(words $(ARM_BINS)) ARM64 examples"

x86_64: $(X86_64_BINS)
	@echo "Built $(words $(X86_64_BINS)) x86-64 examples"

# Pattern rules for each ISA
riscv/%: riscv/%.s
	@$(AS) $(ASFLAGS) $< -o $@ && echo "  $@"

mips/%: mips/%.s
	@$(AS) $(ASFLAGS) $< -o $@ && echo "  $@"

arm/%: arm/%.s
	@$(AS) $(ASFLAGS) $< -o $@ && echo "  $@"

x86_64/%: x86_64/%.s
	@$(AS) $(ASFLAGS) $< -o $@ && echo "  $@"

x86_64/%: x86_64/%.S
	@$(AS) $(ASFLAGS) $< -o $@ && echo "  $@"

clean:
	@echo "Cleaning generated binaries..."
	@rm -f $(ALL_BINS)
	@echo "Removed $(words $(ALL_BINS)) files"
