# Get the latest tag or use v0.0.0 if no tag exists
GIT_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")

# Remove 'v' prefix from the tag
VERSION_TAG := $(shell echo $(GIT_TAG) | sed 's/^v//')

# Get the latest commit hash
LAST_COMMIT := $(shell git rev-parse --short HEAD)

# Determine version
VERSION := $(shell if [ "$(VERSION_TAG)" = "0.0.0" ]; then echo "$(VERSION_TAG)-$(LAST_COMMIT)"; else echo "$(VERSION_TAG)"; fi)

# Variables
BINARY_NAME = tls-cert-chain-resolver
BUILD_DIR = ./bin

# Default target
all: build-linux build-macos build-windows

# Build the binary for Linux
build-linux:
	@echo "Building $(BINARY_NAME) for Linux version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/linux
	@GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/linux/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/linux/$(BINARY_NAME)"

# Build the binary for macOS
build-macos:
	@echo "Building $(BINARY_NAME) for macOS version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/macos
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/macos/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/macos/$(BINARY_NAME)"

# Build the binary for Windows
build-windows:
	@echo "Building $(BINARY_NAME) for Windows version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/windows
	@GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/windows/$(BINARY_NAME).exe ./cmd
	@echo "Build complete: $(BUILD_DIR)/windows/$(BINARY_NAME).exe"

# Run tests
test:
	@echo "Running tests..."
	@go test ./...
	@echo "Tests completed."

# Clean up build artifacts
clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

# PHONY targets
.PHONY: all build-linux build-macos build-windows test clean
