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
