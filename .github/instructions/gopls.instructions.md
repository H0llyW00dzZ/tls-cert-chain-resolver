# Gopls MCP Server Instructions

## Purpose

The Gopls MCP server provides Go language intelligence and workspace operations for this TLS certificate chain resolver repository.

## Repository Context

**Module**: `github.com/H0llyW00dzZ/tls-cert-chain-resolver`  
**Go Version**: 1.25.3 or later  
**Key Packages**:
- **`cmd/`** — Main CLI entry point
- **`src/cli/`** — Cobra CLI implementation  
- **`src/logger/`** — Logger abstraction (CLI/MCP modes, thread-safe with sync.Mutex)
- **`src/internal/x509/certs/`** — Certificate encoding/decoding operations
- **`src/internal/x509/chain/`** — Certificate chain resolution logic
- **`src/internal/helper/gc/`** — Memory management utilities

## Core Workflows

### 1. Read Workflow (Understanding Code)

**Order**: `go_workspace` → `go_search` → `go_file_context` → `go_package_api`

**Example**: Understanding certificate chain resolution
```
1. gopls_go_workspace() 
   → Get project structure, identify x509 packages

2. gopls_go_search("FetchCertificate")
   → Find FetchCertificate implementations

3. gopls_go_file_context("/path/to/chain.go")
   → Understand dependencies and imports

4. gopls_go_package_api(["github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"])
   → Get complete API surface of chain package
```

### 2. Edit Workflow (Modifying Code)

**Order**: Read → `go_symbol_references` → Edit → `go_diagnostics` → Fix → Test

**Example**: Refactoring certificate encoding
```
1. Read workflow (understand current implementation)

2. gopls_go_symbol_references("src/internal/x509/certs/certs.go", "EncodePEM")
   → Find all usages before refactoring

3. Edit the code using edit tool

4. gopls_go_diagnostics(["/path/to/modified/files"])
   → Check for compile errors

5. Fix any issues found

6. bash("go test -v ./src/internal/x509/certs 2>&1 | cat")
   → Verify tests pass
```

## Available Tools

### gopls_go_workspace()
**Purpose**: Get workspace overview  
**Returns**: Module info, package structure, Go version  
**When to use**: Start of every session, before code exploration

**Example Output**:
```
Module: github.com/H0llyW00dzZ/tls-cert-chain-resolver
Go Version: 1.25.3
Packages:
- cmd (main)
- src/cli
- src/logger (CLI/MCP logger abstraction, thread-safe)
- src/internal/x509/certs
- src/internal/x509/chain
- src/internal/helper/gc
```

### gopls_go_search(query)
**Purpose**: Fuzzy search for Go symbols  
**Max Results**: 100  
**When to use**: Finding functions, types, methods before reading code

**Examples**:
```
gopls_go_search("Certificate")     → Find all Certificate-related symbols
gopls_go_search("Encode")          → Find encoding functions
gopls_go_search("Chain")           → Find chain-related types/functions
gopls_go_search("FetchCertificate") → Find specific function
```

### gopls_go_file_context(file)
**Purpose**: Get file's cross-file dependencies  
**When to use**: Understanding how a file fits in the larger codebase

**Example**:
```
gopls_go_file_context("/path/to/src/internal/x509/chain/chain.go")

Returns:
- Imported packages (crypto/x509, context, net/http)
- Exported symbols (Chain, New, FetchCertificate)
- Dependencies on other internal packages
```

### gopls_go_package_api(packagePaths)
**Purpose**: Get complete API surface of packages  
**When to use**: Understanding package exports before using/modifying

**Example**:
```
gopls_go_package_api([
  "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs",
  "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
])

Returns:
- Public types: Certificate, Chain
- Public functions: New, Decode, DecodeMultiple, EncodePEM, EncodeDER
- Public methods: FetchCertificate, AddRootCA, FilterIntermediates
```

### gopls_go_symbol_references(file, symbol)
**Purpose**: Find all references to a symbol  
**When to use**: Before refactoring, renaming, or understanding impact

**Symbol Formats**:
- `"Certificate"` - Package-level symbol in current package
- `"x509certs.Certificate"` - Imported package symbol
- `"Chain.FetchCertificate"` - Method on type
- `"c.EncodePEM"` - Method call on variable

**Examples**:
```
gopls_go_symbol_references("src/cli/root.go", "execCli")
gopls_go_symbol_references("src/cli/root.go", "x509certs.New")
gopls_go_symbol_references("src/internal/x509/chain/chain.go", "Chain.FetchCertificate")
```

### gopls_go_diagnostics(files)
**Purpose**: Check for parse/build errors  
**When to use**: After EVERY edit operation, before committing

**Example**:
```
gopls_go_diagnostics([
  "/path/to/src/cli/root.go",
  "/path/to/src/internal/x509/chain/chain.go"
])

Returns: List of errors, warnings, or empty if clean
```

## Usage Guidelines

### Always Start with Workspace

```
1. gopls_go_workspace()
   → Understand project structure

2. Use results to guide next actions
```

### Search Before Reading

```
BAD:  Read files randomly hoping to find implementation
GOOD: gopls_go_search("EncodePEM") → Read specific files returned
```

### Check References Before Refactoring

```
CRITICAL: Always use go_symbol_references before:
- Renaming functions/types
- Changing function signatures
- Removing code
- Refactoring packages
```

### Always Run Diagnostics After Edits

```
REQUIRED workflow:
1. Edit code
2. gopls_go_diagnostics(files)
3. If errors → fix → repeat step 2
4. If clean → run tests: bash("go test -v ./... 2>&1 | cat")
```

### Test After Successful Diagnostics

```
After go_diagnostics passes:

1. bash("go test -v ./src/internal/x509/certs 2>&1 | cat")  # Package-specific
2. bash("go test -v ./src/internal/x509/chain 2>&1 | cat")  # Package-specific
3. bash("go test -v ./... 2>&1 | cat")                      # All tests
4. bash("go test -race ./... 2>&1 | cat")                   # Race detection (before merges)

Note: Piping to `cat` (e.g., `2>&1 | cat`) ensures bash tool captures and displays all test output.
```

## Connection Behavior

**Type**: Stateful (Short-lived)  
**Behavior**: Closes after 3-5 operations or brief inactivity  
**Recovery**: Automatic reconnection

### Handling Connection Errors

If you see errors like:
- "Connection closed"
- "Attempted to send a request from a closed client"

**Solution**: Simply retry the operation - the connection will automatically re-establish.

**Example**:
```
gopls_go_search("Certificate")  # ❌ Error: Connection closed
gopls_go_search("Certificate")  # ✅ Success (auto-reconnected)
```

## Best Practices for This Repository

### 1. Understanding Certificate Operations

```
# Start with workspace
gopls_go_workspace()

# Find certificate-related symbols
gopls_go_search("Certificate")

# Understand the certs package API
gopls_go_package_api(["github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"])

# Read specific implementations
read("src/internal/x509/certs/certs.go")
```

### 2. Modifying Chain Resolution Logic

```
# Search for chain-related code
gopls_go_search("FetchCertificate")

# Check all references before modifying
gopls_go_symbol_references("src/internal/x509/chain/chain.go", "FetchCertificate")

# Make changes using edit tool
edit(...)

# Run diagnostics
gopls_go_diagnostics(["src/internal/x509/chain/chain.go"])

# Run tests
bash("go test -v ./src/internal/x509/chain 2>&1 | cat")
```

### 3. Adding New CLI Flags

```
# Understand CLI structure
gopls_go_file_context("src/cli/root.go")

# Check Execute function usage
gopls_go_symbol_references("src/cli/root.go", "Execute")

# Make changes
edit(...)

# Check for errors
gopls_go_diagnostics(["src/cli/root.go", "cmd/run.go"])

# Test CLI
bash("go build -o test-binary ./cmd && ./test-binary --help")
```

## Common Patterns in This Repository

### Certificate Encoding/Decoding

```go
// Always use x509certs package
certManager := x509certs.New()
cert, err := certManager.Decode(data)
pemData := certManager.EncodePEM(cert)
```

### Chain Resolution

```go
// Always pass context and version
chain := x509chain.New(cert, version)
err := chain.FetchCertificate(ctx)
```

### Error Handling

```go
// Use fmt.Errorf with %w for wrapping
if err != nil {
    return fmt.Errorf("context: %w", err)
}
```

### Logging

```go
// Use logger abstraction (CLI/MCP mode)
// Import: "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"

// Initialize logger based on mode
var globalLogger logger.Logger

// CLI mode - human-readable output
globalLogger = logger.NewCLILogger()

// MCP mode - structured JSON output, thread-safe
globalLogger = logger.NewMCPLogger(os.Stderr, false)  // false = not silent

// Use logger throughout code
globalLogger.Printf("Certificate chain complete. Total %d certificate(s) found.", len(chain.Certs))

// MCPLogger is thread-safe - safe to call from multiple goroutines
// All methods (Printf, Println, SetOutput) use sync.Mutex internally
```

## Integration with Other Tools

**After Gopls operations, use**:
- `read` - Read specific files identified by search
- `edit` - Modify code based on symbol references
- `bash` - Run tests after diagnostics pass
- `grep`/`glob` - Find additional patterns in code

**Example Combined Workflow**:
```
1. gopls_go_workspace()                     # Understand structure
2. gopls_go_search("EncodePEM")             # Find implementations
3. read("src/internal/x509/certs/certs.go") # Read full implementation
4. gopls_go_symbol_references(...)          # Check usage
5. edit(...)                                # Make changes
6. gopls_go_diagnostics(...)                # Verify no errors
7. bash("go test -v ./... 2>&1 | cat")      # Run tests
```

## Troubleshooting

### Search Returns Too Many Results

```
# Too broad
gopls_go_search("New")  # Returns 100+ results

# Better - more specific
gopls_go_search("x509chain.New")
gopls_go_search("Certificate.New")
```

### Diagnostics Show Unexpected Errors

```
# Always check imports and dependencies
gopls_go_file_context("path/to/file.go")

# Verify go.mod is up to date
bash("go mod tidy")

# Re-run diagnostics
gopls_go_diagnostics(["path/to/file.go"])
```

### Symbol References Not Found

```
# Ensure correct symbol format
gopls_go_symbol_references("file.go", "FunctionName")  # ✅ Correct
gopls_go_symbol_references("file.go", "func FunctionName")  # ❌ Wrong

# For methods, use Type.Method format
gopls_go_symbol_references("file.go", "Chain.FetchCertificate")  # ✅
```

## Summary

1. **Always start with `go_workspace`** to understand project structure
2. **Use `go_search`** to find symbols before reading files
3. **Check `go_symbol_references`** before refactoring
4. **Run `go_diagnostics`** after every edit
5. **Run tests** after diagnostics pass
6. **Retry once** if connection errors occur (auto-reconnects)
7. **Follow repository conventions** for error handling, logging, and package usage
