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
all: build

# Build the binary with version information
build:
	@echo "Building $(BINARY_NAME) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Install the binary
install:
	@echo "Installing $(BINARY_NAME)..."
	@go install -ldflags="-X main.version=$(VERSION)" ./cmd
	@echo "Installation complete."

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
.PHONY: all build install test clean
