# Gopls MCP Server Instructions

## Purpose

The Gopls MCP server provides Go language intelligence and workspace operations for this X509 certificate chain resolver repository.

## Repository Context

See [README.md](../../README.md) for repository overview and structure.

## Detecting a Go Workspace

At the start of every session, you MUST use the `go_workspace` tool to learn about the Go workspace. The rest of these instructions apply whenever that tool indicates that the user is in a Go workspace.

## Core Workflows

These guidelines MUST be followed whenever working in a Go workspace. There are two workflows described below: the 'Read Workflow' must be followed when the user asks a question about a Go workspace. The 'Edit Workflow' must be followed when the user edits a Go workspace.

You may re-do parts of each workflow as necessary to recover from errors. However, you must not skip any steps.

### 1. Read Workflow (Understanding Code)

**Order**: `go_workspace` → `go_search` → `go_file_context` → `go_package_api`

**Goal**: Understand the codebase

1. **Understand the workspace layout**: Start by using `go_workspace` to understand the overall structure of the workspace, such as whether it's a module, a workspace, or a GOPATH project.

2. **Find relevant symbols**: If you're looking for a specific type, function, or variable, use `go_search`. This is a fuzzy search that will help you locate symbols even if you don't know the exact name or location.
   EXAMPLE: search for the 'Server' type: `gopls_go_search("server")`

3. **Understand a file and its intra-package dependencies**: When you have a file path and want to understand its contents and how it connects to other files *in the same package*, use `go_file_context`. This tool will show you a summary of the declarations from other files in the same package that are used by the current file. `go_file_context` MUST be used immediately after reading any Go file for the first time, and MAY be re-used if dependencies have changed.
   EXAMPLE: to understand `server.go`'s dependencies on other files in its package: `gopls_go_file_context({"file":"/path/to/server.go"})`

4. **Understand a package's public API**: When you need to understand what a package provides to external code (i.e., its public API), use `go_package_api`. This is especially useful for understanding third-party dependencies or other packages in the same monorepo.
   EXAMPLE: to see the API of the `storage` package: `gopls_go_package_api({"packagePaths":["example.com/internal/storage"]})`

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

**Iterative Process**: Cycle through these steps until the task is complete.

1. **Read first**: Before making any edits, follow the Read Workflow to understand the user's request and the relevant code.

2. **Find references**: Before modifying the definition of any symbol, use the `go_symbol_references` tool to find all references to that identifier. This is critical for understanding the impact of your change. Read the files containing references to evaluate if any further edits are required.
   EXAMPLE: `gopls_go_symbol_references({"file":"/path/to/server.go","symbol":"Server.Run"})`

3. **Make edits**: Make the required edits, including edits to references you identified in the previous step. Don't proceed to the next step until all planned edits are complete.

4. **Check for errors**: After every code modification, you MUST call the `go_diagnostics` tool. Pass the paths of the files you have edited. This tool will report any build or analysis errors.
   EXAMPLE: `gopls_go_diagnostics({"files":["/path/to/server.go"]})`

5. **Fix errors**: If `go_diagnostics` reports any errors, fix them. The tool may provide suggested quick fixes in the form of diffs. You should review these diffs and apply them if they are correct. Once you've applied a fix, re-run `go_diagnostics` to confirm that the issue is resolved. It is OK to ignore 'hint' or 'info' diagnostics if they are not relevant to the current task. Note that Go diagnostic messages may contain a summary of the source code, which may not match its exact text.

6. **Run tests**: Once `go_diagnostics` reports no errors (and ONLY once there are no errors), run the tests for the packages you have changed. You can do this with `go test [packagePath...]`. Don't run `go test ./...` unless the user explicitly requests it, as doing so may slow down the iteration loop.

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
Packages: [lists all Go packages in the workspace]
```

See [AGENTS.md](../../AGENTS.md) for repository module and Go version information.

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
gopls_go_search("WithPopulate") → Find opt-in metadata cache population method
gopls_go_search("createResources") → Find resource creation functions
gopls_go_search("createPrompts") → Find prompt creation functions
gopls_go_search("handleStatusResource") → Find status resource handler
gopls_go_search("ToolAnalyzeCertificateWithAI") → Find AI certificate analysis tool constant
gopls_go_search("DefaultSamplingHandler") → Find AI sampling implementation
gopls_go_search("CreateMessage") → Find AI message creation methods
gopls_go_search("TokenCallback") → Find AI token streaming callbacks
gopls_go_search("WithInMemoryTransport") → Find ADK in-memory transport configuration
gopls_go_search("BuildTransport") → Find ADK transport building methods
gopls_go_search("InMemoryTransport") → Find in-memory transport implementation
gopls_go_search("NewInMemoryTransport") → Find in-memory transport constructor with context parameter
gopls_go_search("ConnectServer") → Find server connection methods
gopls_go_search("TransportBuilder") → Find transport builder pattern
gopls_go_search("NewTransportBuilder") → Find transport builder constructor
gopls_go_search("BuildInMemoryTransport") → Find in-memory transport building
gopls_go_search("ADKTransportConnection") → Find ADK transport bridge implementation
gopls_go_search("sendInternalResponse") → Find internal response sending methods
gopls_go_search("sendInternalErrorResponse") → Find internal error response methods
gopls_go_search("sendErrorResponse") → Find JSON-RPC error response methods
gopls_go_search("FetchRemoteChain") → Find remote TLS chain retrieval helper (`src/internal/x509/chain/remote.go`)
gopls_go_search("CheckRevocationStatus") → Find OCSP/CRL revocation checking (`src/internal/x509/chain/revocation.go`)
gopls_go_search("RevocationStatus") → Find revocation status structures
gopls_go_search("ParseCRLResponse") → Find CRL response parsing functions
gopls_go_search("getCachedCRL") → Find CRL caching functions
gopls_go_search("tryOCSPServer") → Find OCSP server retry functions
gopls_go_search("tryCRLDistributionPoint") → Find CRL distribution point functions
gopls_go_search("buildCertificateContextWithRevocation") → Find AI certificate context builder with revocation
gopls_go_search("Chain.GetCertificateRole") → Find certificate role determination method
gopls_go_search("CRLCacheEntry") → Find CRL cache entry structures
gopls_go_search("CRLCacheConfig") → Find CRL cache configuration
gopls_go_search("CRLCacheMetrics") → Find CRL cache metrics tracking
gopls_go_search("isFresh") → Find CRL freshness checking methods
gopls_go_search("isExpired") → Find CRL expiration checking methods
gopls_go_search("CollectResourceUsage") → Find resource usage data collection functions
gopls_go_search("FormatResourceUsageAsJSON") → Find JSON formatting for resource usage
gopls_go_search("FormatResourceUsageAsMarkdown") → Find Markdown formatting for resource usage
gopls_go_search("ResourceUsageData") → Find resource usage data structures
gopls_go_search("MagicEmbed") → Find embedded filesystem abstraction
gopls_go_search("loadInstructions") → Find MCP server instruction loader with dynamic template rendering
gopls_go_search("parseRevocationStatusForVisualization") → Find revocation status parsing for visualization
gopls_go_search("handleCertificateAnalysisPrompt") → Find certificate analysis prompt handler
gopls_go_search("handleExpiryMonitoringPrompt") → Find expiry monitoring prompt handler
gopls_go_search("handleSecurityAuditPrompt") → Find security audit prompt handler
gopls_go_search("handleTroubleshootingPrompt") → Find troubleshooting prompt handler
gopls_go_search("parsePromptTemplate") → Find prompt template parsing function
gopls_go_search("detectRoleMarker") → Find role marker detection for prompt parsing
gopls_go_search("promptTemplateData") → Find prompt template data structures
gopls_go_search("GenerateResources") → Find resource generation functions
gopls_go_search("GenerateTools") → Find tool generation functions
gopls_go_search("GeneratePrompts") → Find prompt generation functions
gopls_go_search("writeGeneratedFile") → Find generated file writing functions
gopls_go_search("validateParamConstraints") → Find parameter validation functions
gopls_go_search("validateToolParams") → Find tool parameter validation functions
gopls_go_search("ToolParam") → Find tool parameter structures
gopls_go_search("ToolAnnotation") → Find tool annotation structures
gopls_go_search("toGoMap") → Find Go map literal generation functions
gopls_go_search("formatGoValue") → Find Go value formatting functions
gopls_go_search("generateFile") → Find file generation functions
gopls_go_search("writeHeader") → Find generated file header writing functions
gopls_go_search("RenderASCIITree") → Find ASCII tree rendering for certificate chains
gopls_go_search("RenderTable") → Find table rendering for certificate chains
gopls_go_search("ToVisualizationJSON") → Find JSON visualization for certificate chains
gopls_go_search("getCertificateStatusIcon") → Find certificate status icon determination function
gopls_go_search("templateCache") → Find template caching implementation
gopls_go_search("handleResourceMonitoringPrompt") → Find resource monitoring prompt handler
gopls_go_search("getOrCreateTemplate") → Find template caching and cloning functions
gopls_go_search("validateTemplateStructure") → Find template validation functions
gopls_go_search("executeTemplate") → Find template execution functions
gopls_go_search("parseMessagesFromContent") → Find message parsing from template content
gopls_go_search("MaxTemplateSize") → Find template size constants
gopls_go_search("MaxMessageContentSize") → Find message size limits
gopls_go_search("MaxMessagesPerTemplate") → Find template message limits
gopls_go_search("parseSSELine") → Find SSE line parsing functions
gopls_go_search("parseJSONChunk") → Find JSON chunk parsing functions
gopls_go_search("parseStreamingResponse") → Find streaming response parsing functions
gopls_go_search("WithEmbed") → Find embedded FS configuration methods
gopls_go_search("EmbedFS") → Find embedded filesystem interface
gopls_go_search("ServerConfig.Embed") → Find embedded FS in server configuration
gopls_go_search("ServerPromptWithEmbed") → Find embedded prompt structures
gopls_go_search("ServerResourceWithEmbed") → Find embedded resource structures
gopls_go_search("WithEmbeddedPrompts") → Find embedded prompts configuration
gopls_go_search("WithEmbeddedResources") → Find embedded resources configuration
gopls_go_search("PromptDefinition.WithEmbed") → Find embed flag in prompt definitions
gopls_go_search("ResourceDefinition.WithEmbed") → Find embed flag in resource definitions
gopls_go_search("PromptHandlerWithEmbed") → Find embedded prompt handlers
gopls_go_search("ResourceHandlerWithEmbed") → Find embedded resource handlers
gopls_go_search("PromptsWithEmbed") → Find embedded prompts field in server dependencies
gopls_go_search("ResourcesWithEmbed") → Find embedded resources field in server dependencies
gopls_go_search("readCertificateData") → Find certificate data reading helper
gopls_go_search("processSingleCertificate") → Find single certificate processing helper
gopls_go_search("validateResolveParams") → Find certificate resolution parameter validation
gopls_go_search("resolveCertChain") → Find certificate chain resolution logic
gopls_go_search("formatChainOutput") → Find certificate chain output formatting
gopls_go_search("buildResolveResult") → Find resolution result building
gopls_go_search("processBatchCertificates") → Find batch certificate processing
gopls_go_search("BatchConcurrency") → Find batch concurrency configuration
gopls_go_search("initializeStatusMap") → Find revocation status map initialization
gopls_go_search("extractCertificateIndex") → Find certificate index extraction for visualization
gopls_go_search("findFinalStatus") → Find final revocation status parsing
gopls_go_search("TestHandleVisualizeCertChain") → Find visualize certificate chain test
gopls_go_search("formatBatchResults") → Find batch result formatting helper
gopls_go_search("setupTestServer") → Find MCP server test setup helper
gopls_go_search("setupTestTransport") → Find transport test setup helper
gopls_go_search("sendJSONRPCMessage") → Find JSON-RPC message sending test helper
gopls_go_search("runJSONRPCTestCase") → Find JSON-RPC test case execution helper
gopls_go_search("extractTestContent") → Find test content extraction helper
gopls_go_search("appendSubjectInfo") → Find AI context subject info builder
gopls_go_search("appendIssuerInfo") → Find AI context issuer info builder
gopls_go_search("appendValidityInfo") → Find AI context validity info builder
gopls_go_search("appendCryptoInfo") → Find AI context crypto info builder
gopls_go_search("appendCertProperties") → Find AI context certificate properties builder
gopls_go_search("appendCertExtensions") → Find AI context certificate extensions builder
gopls_go_search("appendCAInfo") → Find AI context CA info builder
gopls_go_search("appendChainValidationContext") → Find AI context chain validation builder
gopls_go_search("appendSecurityContext") → Find AI context security recommendations builder
gopls_go_search("formatKeyUsage") → Find key usage formatting helper
gopls_go_search("formatExtKeyUsage") → Find extended key usage formatting helper
gopls_go_search("getAnalysisInstruction") → Find AI analysis instruction selector
gopls_go_search("crlCacheCounters") → Find CRL cache counters (documented unexported type)
gopls_go_search("handleVisualizeCertChain") → Find visualize certificate chain tool handler
gopls_go_search("NewCLIFramework") → Find CLI framework constructor
gopls_go_search("BuildRootCommand") → Find CLI root command builder
gopls_go_search("printInstructions") → Find CLI instructions display function
gopls_go_search("startMCPServer") → Find MCP server startup function
gopls_go_search("GetExecutableName") → Find cross-platform executable name helper function
gopls_go_search("posix") → Find POSIX-compliant helper package
gopls_go_search("CLIFramework") → Find CLI framework struct and methods
gopls_go_search("loadAndExecuteCLIHelpTemplate") → Find CLI help template loader with embedded Markdown
gopls_go_search("parseTemplateResult") → Find template result parser for cross-platform line endings
gopls_go_search("extractFlagNames") → Find dynamic flag name extraction for help text
gopls_go_search("createRootCommandRunE") → Find root command RunE wrapper with error handling
gopls_go_search("signal.NotifyContext") → Find modern signal handling for graceful shutdown
gopls_go_search("detectConfigFormat") → Find config format detection (JSON/YAML)
gopls_go_search("unmarshalConfig") → Find config unmarshaling with format support
gopls_go_search("configFormat") → Find config format type constants
gopls_go_search("writeJSONString") → Find optimized control character escaping in logger
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
4. Run linting: bash("gofmt -l . && go vet ./...") (optional but recommended)
5. If clean → run tests: bash("go test -race ./... 2>&1 | cat")
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

### 2. Understanding Tool Constants and Roles (New Pattern)

```
# Start with workspace
gopls_go_workspace()

# Find tool name constants (type-safe tool definitions)
gopls_go_search("ToolResolveCertChain")  # Tool name constant
gopls_go_search("ToolValidateCertChain")
gopls_go_search("ToolAnalyzeCertificateWithAI")
gopls_go_search("ToolGetResourceUsage")

# Find tool role constants (for dynamic template generation)
gopls_go_search("RoleChainResolver")     # Role constant for template
gopls_go_search("RoleChainValidator")
gopls_go_search("RoleAIAnalyzer")
gopls_go_search("RoleResourceMonitor")

# Find instruction template system
gopls_go_search("loadInstructions")      # Template loader function
gopls_go_search("instructionData")       # Template data structure
gopls_go_search("toolInfo")              # Tool info for template rendering
gopls_go_search("WithInstructions")      # ServerBuilder method for instructions

# Read tool definitions
read("src/mcp-server/tools.go")          # Tool constants and creation functions
read("src/mcp-server/templates/X509_instructions.md")  # Instruction template with role placeholders
```

### 3. CLI Development Workflow

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

### Common Repository Patterns

See [filesystem.instructions.md](./filesystem.instructions.md) for comprehensive search patterns. Key patterns for Go development:

## Summary

1. **Always start with `go_workspace`** to understand project structure
2. **Use `go_search`** to find symbols before reading files
3. **Check `go_symbol_references`** before refactoring
4. **Run `go_diagnostics`** after every edit
5. **Run tests** after diagnostics pass
6. **Retry once** if connection errors occur (auto-reconnects)
7. **Follow repository conventions** for error handling, logging, and package usage
8. **Use platform-specific test skips** when OS behavior differs (e.g., macOS EKU constraints)
