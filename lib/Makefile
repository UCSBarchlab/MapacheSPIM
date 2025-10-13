.PHONY: all build clean configure rebuild install test help

# Build directory
BUILD_DIR := build

# Default target
all: build

# Configure the build with CMake
configure:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake ..

# Build the libraries
build: configure
	@cd $(BUILD_DIR) && $(MAKE)

# Clean the build directory
clean:
	@rm -rf $(BUILD_DIR)

# Rebuild from scratch (clean + build)
rebuild: clean build

# Install the libraries
install: build
	@cd $(BUILD_DIR) && $(MAKE) install

# Run tests
test: build
	@cd $(BUILD_DIR) && ctest

# Show help
help:
	@echo "Available targets:"
	@echo "  all (default) - Build the libraries"
	@echo "  configure     - Run CMake configuration"
	@echo "  build         - Build the libraries"
	@echo "  clean         - Remove build directory"
	@echo "  rebuild       - Clean and rebuild from scratch"
	@echo "  install       - Install the libraries"
	@echo "  test          - Run tests"
	@echo "  help          - Show this help message"
