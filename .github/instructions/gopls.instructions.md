# Gopls MCP Server Instructions

## Purpose

The Gopls MCP server provides Go language intelligence and workspace operations for this X509 certificate chain resolver repository.

## Repository Context

**Module**: `github.com/H0llyW00dzZ/tls-cert-chain-resolver`  
**Go Version**: 1.25.4+  
**Key Packages**:
- **`cmd/`** — Main CLI entry point, MCP server binaries, and ADK example runner (`adk-go/`)
- **`src/cli/`** — Cobra CLI implementation  
- **`src/logger/`** — Logger abstraction (CLI/MCP modes, thread-safe with sync.Mutex and gc.Pool)
 - **`src/mcp-server/`** — MCP server implementation with X509 certificate tools and AI integration
  - **`adk.go`** — Google ADK integration support with transport builder pattern
  - **`adk_test.go`** — Comprehensive ADK transport builder tests with JSON-RPC cycle testing
  - **`analysis_coverage_test.go`** — Analysis coverage tests
  - **`transport.go`** — In-memory transport implementation bridging ADK SDK and mark3labs/mcp-go with JSON-RPC normalization, concurrent message processing, semaphore-based rate limiting, and internal response channel for sampling
  - **`framework.go`** — Builder pattern for server construction (ServerBuilder), sampling handler with streaming support, AI API integration
  - **`resources.go`** — MCP resource definitions and handlers (config, version, formats, status)
  - **`prompts.go`** — MCP prompt definitions and handlers (certificate analysis workflows)
  - **`handlers.go`** — Core certificate processing utilities, AI analysis, and individual tool handlers
  - **`helper.go`** — Helper utilities (JSON-RPC parameter extraction: `getStringParam`, `getMapParam`, `getOptionalStringParam`)
  - **`pipe.go`** — Pipe transport implementation for StdioServer input/output interception (sampling) with buffer pooling
  - **`pipe_test.go`** — Pipe transport tests covering I/O performance and interception logic
  - **`resource_usage.go`** — Resource usage monitoring and formatting functions
  - **`server.go`** — Server execution and lifecycle management
  - **`tools.go`** — Tool definitions and creation functions
  - **`config.go`** — Configuration management for AI and MCP settings
- **`src/internal/x509/certs/`** — Certificate encoding/decoding operations
- **`src/internal/x509/chain/`** — Certificate chain resolution logic
  - **`cache.go`** — CRL cache implementation with LRU eviction and metrics
  - **`remote.go`** — Context-aware remote TLS chain retrieval (`FetchRemoteChain`)
  - **`revocation.go`** — OCSP/CRL revocation status checking (`CheckRevocationStatus`, `ParseCRLResponse`)
- **`src/internal/helper/gc/`** — Memory management utilities
- **`src/internal/helper/jsonrpc/`** — JSON-RPC canonicalization helper for MCP transport normalization
- **`src/version/`** — Version information

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
Go Version: 1.25.4
Packages:
- cmd (main)
- src/cli
- src/logger (CLI/MCP logger abstraction, thread-safe with bytebufferpool)
- src/mcp-server (MCP server tools for certificate operations with ServerBuilder pattern and resource monitoring)
- src/internal/x509/certs
- src/internal/x509/chain
- src/internal/helper/gc
- src/internal/helper/jsonrpc
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
gopls_go_search("MCP")             → Find MCP-related implementations
gopls_go_search("handleResolveCertChain") → Find MCP server tool handlers
gopls_go_search("handleGetResourceUsage") → Find resource usage monitoring tool handler
gopls_go_search("addResources") → Find MCP server resource implementations
gopls_go_search("addPrompts") → Find MCP server prompt implementations
gopls_go_search("ServerBuilder") → Find builder pattern implementation
gopls_go_search("createResources") → Find resource creation functions
gopls_go_search("createPrompts") → Find prompt creation functions
gopls_go_search("handleStatusResource") → Find status resource handler
gopls_go_search("analyze_certificate_with_ai") → Find AI certificate analysis tools
gopls_go_search("DefaultSamplingHandler") → Find AI sampling implementation
gopls_go_search("ADKTransportBuilder") → Find Google ADK transport builder
gopls_go_search("NewADKTransportBuilder") → Find ADK transport builder constructor
gopls_go_search("WithInMemoryTransport") → Find ADK in-memory transport configuration
gopls_go_search("BuildTransport") → Find ADK transport building methods
gopls_go_search("InMemoryTransport") → Find in-memory transport implementation
gopls_go_search("NewInMemoryTransport") → Find in-memory transport constructor with context parameter
gopls_go_search("ConnectServer") → Find server connection methods
gopls_go_search("TransportBuilder") → Find transport builder pattern
gopls_go_search("NewTransportBuilder") → Find transport builder constructor
gopls_go_search("BuildInMemoryTransport") → Find in-memory transport building
gopls_go_search("ADKTransportConnection") → Find ADK transport bridge implementation
gopls_go_search("FetchRemoteChain") → Find remote TLS chain retrieval helper (`src/internal/x509/chain/remote.go`)
gopls_go_search("CheckRevocationStatus") → Find OCSP/CRL revocation checking (`src/internal/x509/chain/revocation.go`)
gopls_go_search("RevocationStatus") → Find revocation status structures
gopls_go_search("createOCSPRequest") → Find OCSP request creation functions
gopls_go_search("ParseCRLResponse") → Find CRL response parsing functions
gopls_go_search("getCachedCRL") → Find CRL caching functions
gopls_go_search("tryOCSPServer") → Find OCSP server retry functions
gopls_go_search("tryCRLDistributionPoint") → Find CRL distribution point functions
gopls_go_search("buildCertificateContextWithRevocation") → Find AI certificate context builder with revocation
gopls_go_search("formatKeyUsage") → Find ordered key usage formatting function
gopls_go_search("appendSubjectInfo") → Find certificate subject info appenders
gopls_go_search("appendIssuerInfo") → Find certificate issuer info appenders
gopls_go_search("appendValidityInfo") → Find certificate validity info appenders
gopls_go_search("appendCryptoInfo") → Find certificate crypto info appenders
gopls_go_search("appendCertProperties") → Find certificate properties appenders
gopls_go_search("appendCertExtensions") → Find certificate extensions appenders
gopls_go_search("appendCAInfo") → Find certificate authority info appenders
gopls_go_search("appendChainValidationContext") → Find chain validation context appenders
gopls_go_search("appendSecurityContext") → Find security context appenders
gopls_go_search("CRLCacheEntry") → Find CRL cache entry structures
gopls_go_search("CRLCacheConfig") → Find CRL cache configuration
gopls_go_search("CRLCacheMetrics") → Find CRL cache metrics tracking
gopls_go_search("isFresh") → Find CRL freshness checking methods
gopls_go_search("isExpired") → Find CRL expiration checking methods
gopls_go_search("handleGetResourceUsage") → Find resource usage monitoring tool handler
gopls_go_search("CollectResourceUsage") → Find resource usage data collection functions
gopls_go_search("FormatResourceUsageAsJSON") → Find JSON formatting for resource usage
gopls_go_search("FormatResourceUsageAsMarkdown") → Find Markdown formatting for resource usage
gopls_go_search("ResourceUsageData") → Find resource usage data structures
gopls_go_search("jsonrpc.Marshal") → Find JSON-RPC marshaling functions
gopls_go_search("jsonrpc.Map") → Find JSON-RPC field normalization functions
gopls_go_search("jsonrpc.UnmarshalFromMap") → Find JSON-RPC unmarshaling helper
gopls_go_search("normalizeIDValue") → Find ID value normalization functions
gopls_go_search("getParams") → Find JSON-RPC parameter extraction helper (`src/mcp-server/helper.go`)
gopls_go_search("getStringParam") → Find required string parameter extraction
gopls_go_search("getOptionalStringParam") → Find optional string parameter extraction
gopls_go_search("getMapParam") → Find map parameter extraction
gopls_go_search("UnmarshalFromMap") → Find JSON-RPC map-to-struct unmarshaling helper
gopls_go_search("pipeReader") → Find pipe reader implementation for StdioServer interception
gopls_go_search("pipeWriter") → Find pipe writer implementation for StdioServer interception
gopls_go_search("internalRespCh") → Find internal response channel for sampling responses
gopls_go_search("sendInternalResponse") → Find internal response sender for sampling
gopls_go_search("sendInternalErrorResponse") → Find internal error response sender for sampling
gopls_go_search("processMessages") → Find transport message processing with concurrent goroutines
gopls_go_search("SendJSONRPCNotification") → Find JSON-RPC notification sender for streaming
gopls_go_search("ThinkingConfig") → Find AI thinking mode configuration (adk-go example)
gopls_go_search("ThinkingBudget") → Find thinking mode budget settings
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
- Public functions: New, Decode, DecodeMultiple, EncodePEM, EncodeDER, FetchRemoteChain
- Public methods: FetchCertificate, AddRootCA, FilterIntermediates, CheckRevocationStatus
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
3. bash("go test -v ./src/mcp-server 2>&1 | cat")           # Package-specific
4. bash("go test -v ./... 2>&1 | cat")                      # All tests
5. bash("go test -race ./... 2>&1 | cat")                   # Race detection (before merges)

Note: Piping to `cat` (e.g., `2>&1 | cat`) ensures bash tool captures and displays all test output.
```

## Connection Behavior

**Type**: Stateful (Short-lived)  
**Behavior**: Closes after 3-5 operations or brief inactivity  
**Recovery**: Automatic reconnection
**Configuration**: MCP server configured in `opencode.json` with port 8096 on localhost

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

### 2. Understanding MCP Server Operations

```
# Start with workspace
gopls_go_workspace()

# Find MCP server tool implementations
gopls_go_search("resolve_cert_chain")
gopls_go_search("validate_cert_chain")
gopls_go_search("check_cert_expiry")
gopls_go_search("batch_resolve_cert_chain")
gopls_go_search("fetch_remote_cert")
gopls_go_search("analyze_certificate_with_ai") → Find AI certificate analysis entry points
gopls_go_search("addResources") → Find MCP server resource implementations
gopls_go_search("addPrompts") → Find MCP server prompt implementations
gopls_go_search("ServerBuilder") → Find builder pattern implementation
gopls_go_search("WithSampling") → Locate sampling registration on the server builder
gopls_go_search("DefaultSamplingHandler") → Inspect bidirectional AI streaming handler (`src/mcp-server/framework.go`)
gopls_go_search("TokenCallback") → Find streaming token callback configuration
gopls_go_search("parseStreamingResponse") → Find SSE streaming response parser
gopls_go_search("SamplingRequest") → Explore sampling request markers
gopls_go_search("ADKTransportBuilder") → Find Google ADK transport builder implementation
gopls_go_search("NewADKTransportBuilder") → Find ADK transport builder constructor
gopls_go_search("WithInMemoryTransport") → Find ADK in-memory transport configuration
gopls_go_search("BuildTransport") → Find ADK transport building methods
gopls_go_search("InMemoryTransport") → Find in-memory transport implementation
gopls_go_search("NewInMemoryTransport") → Find in-memory transport constructor with context parameter
gopls_go_search("ConnectServer") → Find server connection methods
gopls_go_search("TransportBuilder") → Find transport builder pattern
gopls_go_search("NewTransportBuilder") → Find transport builder constructor
gopls_go_search("BuildInMemoryTransport") → Find in-memory transport building
gopls_go_search("ADKTransportConnection") → Find ADK transport bridge implementation
gopls_go_search("SendJSONRPCNotification") → Find JSON-RPC notification sender
gopls_go_search("jsonRPCError") → Find JSON-RPC error struct
gopls_go_search("jsonRPCResponse") → Find JSON-RPC response struct
gopls_go_search("handleStatusResource") → Find status resource handler
gopls_go_search("certificate-analysis") → Find certificate analysis prompts
gopls_go_search("security-audit") → Find security audit prompts
gopls_go_search("CRLCacheEntry") → Find CRL cache entry structures
gopls_go_search("CRLCacheConfig") → Find CRL cache configuration
gopls_go_search("CRLCacheMetrics") → Find CRL cache metrics tracking
gopls_go_search("isFresh") → Find CRL freshness checking methods
gopls_go_search("isExpired") → Find CRL expiration checking methods
gopls_go_search("GetCachedCRL") → Find CRL cache retrieval functions
gopls_go_search("SetCachedCRL") → Find CRL cache storage functions
gopls_go_search("StartCRLCacheCleanup") → Find CRL cache cleanup lifecycle management
gopls_go_search("StopCRLCacheCleanup") → Find CRL cache cleanup termination
gopls_go_search("updateCacheOrder") → Find LRU access order management
gopls_go_search("removeFromCacheOrder") → Find LRU order removal functions
gopls_go_search("pruneCRLCache") → Find LRU eviction implementation

# Understand MCP server package API
gopls_go_package_api(["github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server"])

# Read MCP server implementations
read("src/mcp-server/framework.go")  # ServerBuilder pattern, AI streaming integration with buffer pooling
read("src/mcp-server/resources.go")  # Resource definitions including status resource
read("src/mcp-server/prompts.go")    # Prompt definitions
read("src/mcp-server/templates/certificate-analysis-system-prompt.md")  # Embedded system prompt for AI analysis
read("src/mcp-server/handlers.go")   # Tool handlers, AI analysis with analysis types
read("src/mcp-server/config.go")     # AI and MCP configuration
read("src/mcp-server/adk.go")        # Google ADK integration support
read("src/mcp-server/transport.go")  # In-memory transport for ADK compatibility with JSON-RPC normalization, concurrent message processing, semaphore-based rate limiting
read("src/mcp-server/helper.go")     # JSON-RPC parameter extraction helper (getParams, getStringParam, getOptionalStringParam, getMapParam)
read("src/mcp-server/pipe.go")       # Pipe transport implementation with buffer pooling
read("src/mcp-server/adk_test.go")   # Comprehensive ADK transport tests with JSON-RPC cycle testing
read("src/mcp-server/run_graceful_test.go")  # Graceful shutdown tests
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
// Always use HTTPConfig for HTTP operations in certificate chains
chain := x509chain.New(cert, version)
// HTTPConfig automatically provides User-Agent and timeout handling
// Use chain.HTTPConfig.Client() for all HTTP requests

// Always check revocation status after chain resolution
chain := x509chain.New(cert, version)
err := chain.FetchCertificate(ctx)
if err == nil {
    revocationStatus, _ := chain.CheckRevocationStatus(ctx)
    // Process revocation status
}
```

### HTTP Requests with User-Agent

```go
// Set User-Agent header with version and GitHub link for certificate fetching
req, err := http.NewRequestWithContext(ctx, http.MethodGet, parentURL, nil)
if err != nil {
    return err
}

// User-Agent format: "X.509-Certificate-Chain-Resolver/{version} (+{github-url})"
req.Header.Set("User-Agent", "X.509-Certificate-Chain-Resolver/"+ch.Version+" (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)")

resp, err := http.DefaultClient.Do(req)
// ...
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

// MCP mode - structured JSON output, thread-safe with buffer pooling
globalLogger = logger.NewMCPLogger(os.Stderr, false)  // false = not silent

// Use logger throughout code
globalLogger.Printf("Certificate chain complete. Total %d certificate(s) found.", len(chain.Certs))

// MCPLogger is thread-safe - safe to call from multiple goroutines
// All methods (Printf, Println, SetOutput) use sync.Mutex + gc.Pool internally
// Buffer pooling minimizes allocations under high concurrency
```

### Buffer Pool Testing

```go
// Use gc.Pool for buffer pooling (see src/internal/helper/gc/)
// Import: "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"

// Standard buffer pool usage pattern
buf := gc.Default.Get()
defer func() {
    buf.Reset()         // Always reset before returning to pool
    gc.Default.Put(buf)
}()

// Use buffer methods
buf.WriteString("data")
buf.WriteByte('\n')
buf.Write([]byte("more data"))

// Mock buffer for testing (see mock_buffer_test.go)
type mockBuffer struct {
    buf *bytes.Buffer
}

// Implement gc.Buffer interface methods:
// Write, WriteString, WriteByte, WriteTo, ReadFrom,
// Bytes, String, Len, Set, SetString, Reset
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

## Repository-Specific Patterns

### Common MCP Server Patterns

```go
# Find context cancellation tests
grep("context\\.WithCancel\\|ctx\\.Done", include="*_test.go")

# Find table-driven tests
grep("tests := \\[\\]struct", include="*_test.go")

# Find platform-specific test skips
grep("runtime\\.GOOS", include="*_test.go")

# Find test cleanup patterns
grep("t\\.TempDir\\|t\\.Cleanup", include="*_test.go")

# Find JSON escaping tests
grep("JSONEscaping\\|json\\.Unmarshal", include="*_test.go")

# Find concurrent test patterns
grep("sync\\.WaitGroup\\|numGoroutines", include="*_test.go")

# Find MCP server tools
grep("resolve_cert_chain\\|validate_cert_chain\\|check_cert_expiry\\|batch_resolve_cert_chain\\|fetch_remote_cert\\|analyze_certificate_with_ai\\|get_resource_usage", include="*.go")

# Find MCP server configuration
grep("MCP_X509_CONFIG_FILE\\|config\\.Defaults\\|AI.*API", include="*.go")

# Find MCP tool handlers
grep("handleResolveCertChain\\|handleValidateCertChain\\|handleCheckCertExpiry\\|handleBatchResolveCertChain\\|handleFetchRemoteCert\\|handleAnalyzeCertificateWithAI\\|handleGetResourceUsage", include="*.go")

# Find MCP resources and prompts
grep("addResources\\|addPrompts\\|certificate-analysis\\|expiry-monitoring\\|security-audit\\|troubleshooting\\|config://template\\|info://version\\|docs://certificate-formats\\|status://server-status", include="*.go")

# Find AI integration patterns
grep("DefaultSamplingHandler\\|CreateMessage\\|SamplingRequest\\|streaming\\|MaxTokens\\|handleNoAPIKey\\|convertMessages\\|selectModel\\|prepareMessages\\|buildAPIRequest\\|sendAPIRequest\\|handleAPIError\\|parseStreamingResponse\\|buildSamplingResult\\|TokenCallback", include="*.go")

# Find MCP server builder pattern
grep("ServerBuilder\\|NewServerBuilder\\|WithConfig\\|WithDefaultTools\\|createResources\\|createPrompts", include="*.go")

# Find ADK integration patterns
grep("ADKTransportBuilder\\|NewADKTransportBuilder\\|WithInMemoryTransport\\|BuildTransport\\|ADKTransportConfig\\|InMemoryTransport\\|NewInMemoryTransport\\|ConnectServer\\|TransportBuilder\\|NewTransportBuilder\\|BuildInMemoryTransport", include="*.go")

# Find MCP server status resource
grep("handleStatusResource\\|status://server-status", include="*.go")

# Find embedded templates
grep("MagicEmbed\\|templates/certificate.*\\.md", include="*.go")

# Find revocation checking patterns
grep("CheckRevocationStatus\\|ParseCRLResponse\\|RevocationStatus\\|OCSPStatus\\|CRLStatus\\|getCachedCRL\\|setCachedCRL\\|tryOCSPServer\\|tryCRLDistributionPoint", include="*.go")

# Find CRL cache patterns
grep("CRLCacheEntry\\|CRLCacheConfig\\|CRLCacheMetrics\\|GetCachedCRL\\|SetCachedCRL\\|StartCRLCacheCleanup\\|StopCRLCacheCleanup\\|updateCacheOrder\\|removeFromCacheOrder\\|pruneCRLCache\\|isFresh\\|isExpired", include="*.go")

# Find LRU eviction patterns
grep("updateCacheOrder\\|removeFromCacheOrder\\|pruneCRLCache", include="*.go")

# Find HTTP client configuration
grep("HTTPConfig\\|Client\\(\\)\\|GetUserAgent", include="*.go")

# Find certificate context builders
grep("buildCertificateContextWithRevocation\\|buildCertificateContext", include="*.go")

# Find JSON-RPC normalization patterns
grep("jsonrpc\\.Marshal\\|jsonrpc\\.Map\\|normalizeIDValue\\|UnmarshalFromMap", include="*.go")
grep("getParams\\|getStringParam\\|getOptionalStringParam\\|getMapParam", include="*.go")
```

## Summary

1. **Always start with `go_workspace`** to understand project structure
2. **Use `go_search`** to find symbols before reading files
3. **Check `go_symbol_references`** before refactoring
4. **Run `go_diagnostics`** after every edit
5. **Run tests** after diagnostics pass
6. **Retry once** if connection errors occur (auto-reconnects)
7. **Follow repository conventions** for error handling, logging, and package usage
8. **Use platform-specific test skips** when OS behavior differs (e.g., macOS EKU constraints)

