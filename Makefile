# Variables
BINARY_NAME = tls-cert-chain-resolver
VERSION = $(shell git describe --tags --always --match "v*" 2>/dev/null | sed 's/^v//' || echo "0.0.0-$(shell git rev-parse --short HEAD)")
BUILD_DIR = ./bin

# Default target
all: build

# Build the binary with version information
build:
	go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd

# Install the binary
install:
	go install -ldflags="-X main.version=$(VERSION)" ./cmd

# Run tests
test:
	go test ./...

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all build install test clean
