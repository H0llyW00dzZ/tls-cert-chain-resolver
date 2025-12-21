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
MCP_BINARY_NAME = x509-cert-chain-resolver
BUILD_DIR = ./bin

# Detect architecture for native builds using Go
GOARCH_DETECTED := $(shell go env GOARCH)

# Default target
all: build-linux build-macos build-windows build-mcp-linux build-mcp-macos build-mcp-windows

# Checkout the latest tag or commit (fail if uncommitted changes exist)
checkout:
	@if git diff --quiet && git diff --staged --quiet; then \
		git checkout -q $$( [ "$(GIT_TAG)" != "v0.0.0" ] && echo "$(GIT_TAG)" || echo "$(LAST_COMMIT)" ) 2>/dev/null; \
	else \
		echo "Error: Uncommitted changes detected. Please commit or stash changes before building."; \
		exit 1; \
	fi

# Return to the previous branch or commit (only if checkout was performed)
return:
	@if git diff --quiet && git diff --staged --quiet; then \
		git switch -q - 2>/dev/null; \
		echo "Returned to the previous branch or commit."; \
	else \
		echo "Skipped return due to uncommitted changes."; \
	fi

# Build the binary for Linux
build-linux: checkout
	@echo "Building $(BINARY_NAME) for Linux ($(GOARCH_DETECTED)) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/linux/$(GOARCH_DETECTED)
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH_DETECTED) go build -ldflags="-X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/linux/$(GOARCH_DETECTED)/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/linux/$(GOARCH_DETECTED)/$(BINARY_NAME)"
	@$(MAKE) --no-print-directory return

# Build the binary for macOS (amd64)
build-macos-amd64: checkout
	@echo "Building $(BINARY_NAME) for macOS (amd64) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/macos/amd64
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/macos/amd64/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/macos/amd64/$(BINARY_NAME)"
	@$(MAKE) --no-print-directory return

# Build the binary for macOS (arm64)
build-macos-arm64: checkout
	@echo "Building $(BINARY_NAME) for macOS (arm64) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/macos/arm64
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/macos/arm64/$(BINARY_NAME) ./cmd
	@echo "Build complete: $(BUILD_DIR)/macos/arm64/$(BINARY_NAME)"
	@$(MAKE) --no-print-directory return

# Build the binary for macOS (both architectures)
build-macos: build-macos-amd64 build-macos-arm64

# Build the binary for Windows
build-windows: checkout
	@echo "Building $(BINARY_NAME) for Windows version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/windows
	@GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/windows/$(BINARY_NAME).exe ./cmd
	@echo "Build complete: $(BUILD_DIR)/windows/$(BINARY_NAME).exe"
	@$(MAKE) --no-print-directory return

# Build the MCP server binary for Linux
build-mcp-linux: checkout
	@echo "Building $(MCP_BINARY_NAME) for Linux ($(GOARCH_DETECTED)) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/linux/$(GOARCH_DETECTED)
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH_DETECTED) go build -ldflags="-X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/linux/$(GOARCH_DETECTED)/$(MCP_BINARY_NAME) ./cmd/mcp-server
	@echo "Build complete: $(BUILD_DIR)/linux/$(GOARCH_DETECTED)/$(MCP_BINARY_NAME)"
	@$(MAKE) --no-print-directory return

# Build the MCP server binary for macOS (amd64)
build-mcp-macos-amd64: checkout
	@echo "Building $(MCP_BINARY_NAME) for macOS (amd64) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/macos/amd64
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/macos/amd64/$(MCP_BINARY_NAME) ./cmd/mcp-server
	@echo "Build complete: $(BUILD_DIR)/macos/amd64/$(MCP_BINARY_NAME)"
	@$(MAKE) --no-print-directory return

# Build the MCP server binary for macOS (arm64)
build-mcp-macos-arm64: checkout
	@echo "Building $(MCP_BINARY_NAME) for macOS (arm64) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/macos/arm64
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/macos/arm64/$(MCP_BINARY_NAME) ./cmd/mcp-server
	@echo "Build complete: $(BUILD_DIR)/macos/arm64/$(MCP_BINARY_NAME)"
	@$(MAKE) --no-print-directory return

# Build the MCP server binary for macOS (both architectures)
build-mcp-macos: build-mcp-macos-amd64 build-mcp-macos-arm64

# Build the MCP server binary for Windows
build-mcp-windows: checkout
	@echo "Building $(MCP_BINARY_NAME) for Windows version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/windows
	@GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/windows/$(MCP_BINARY_NAME).exe ./cmd/mcp-server
	@echo "Build complete: $(BUILD_DIR)/windows/$(MCP_BINARY_NAME).exe"
	@$(MAKE) --no-print-directory return

# Build all MCP server binaries
build-mcp: build-mcp-linux build-mcp-macos build-mcp-windows

# Run tests
test:
	@echo "Running tests (with race detector and coverage)..."
	@go test -race -cover ./...
	@echo "Tests completed."

# Clean up build artifacts
clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

# PHONY targets
.PHONY: all checkout return build-linux build-macos build-macos-amd64 build-macos-arm64 build-windows build-mcp-linux build-mcp-macos-amd64 build-mcp-macos-arm64 build-mcp-macos build-mcp-windows build-mcp test clean
