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

# Checkout the latest tag or commit
checkout:
	@if [ "$(GIT_TAG)" != "v0.0.0" ]; then \
		echo "Checking out latest tag: $(GIT_TAG)"; \
		git checkout $(GIT_TAG); \
	else \
		echo "No tags found, using latest commit: $(LAST_COMMIT)"; \
		git checkout $(LAST_COMMIT); \
	fi

# Return to the previous branch or commit
return:
	@git switch -
	@echo "Returned to the previous branch or commit."

# Build the binary for Linux
build-linux: checkout
	@echo "Building $(BINARY_NAME) for Linux version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/linux
	@GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/linux/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/linux/$(BINARY_NAME)"
	@$(MAKE) return

# Build the binary for macOS (amd64)
build-macos-amd64: checkout
	@echo "Building $(BINARY_NAME) for macOS (amd64) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/macos/amd64
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/macos/amd64/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/macos/amd64/$(BINARY_NAME)"
	@$(MAKE) return

# Build the binary for macOS (arm64)
build-macos-arm64: checkout
	@echo "Building $(BINARY_NAME) for macOS (arm64) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/macos/arm64
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/macos/arm64/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/macos/arm64/$(BINARY_NAME)"
	@$(MAKE) return

# Build the binary for macOS (both architectures)
build-macos: build-macos-amd64 build-macos-arm64

# Build the binary for Windows
build-windows: checkout
	@echo "Building $(BINARY_NAME) for Windows version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/windows
	@GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/windows/$(BINARY_NAME).exe ./cmd
	@echo "Build complete: $(BUILD_DIR)/windows/$(BINARY_NAME).exe"
	@$(MAKE) return

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
.PHONY: all checkout return build-linux build-macos build-macos-amd64 build-macos-arm64 build-windows test clean
