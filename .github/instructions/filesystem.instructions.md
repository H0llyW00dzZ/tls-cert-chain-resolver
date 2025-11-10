# Filesystem Tools Instructions

## Purpose

Built-in filesystem tools for reading, writing, editing, listing, and searching files in the X509 certificate chain resolver repository.

## Repository Structure

```
tls-cert-chain-resolver/
├── .github/
│   ├── instructions/                         # Agent instruction files
│   │   ├── README.md                         # Instructions overview (for humans)
│   │   ├── deepwiki.instructions.md          # External library research
│   │   ├── filesystem.instructions.md        # THIS FILE - File operations
│   │   ├── gopls.instructions.md             # Go language intelligence
│   │   ├── memory.instructions.md            # Memory/context management
│   │   ├── opencode.instructions.md          # OpenCode configuration
│   │   └── x509_resolver.md                  # X509 certificate chain resolver MCP server
│   ├── workflows/
│   │   └── coverage.yml                      # CI/CD coverage workflow
│   └── dependabot.yml                        # Dependency updates config
├── .opencode/
│   ├── command/
│   │   ├── create-changelog.md               # Generate changelog by comparing tags against master
│   │   ├── test-capabilities.md              # Test agent capabilities workflow
│   │   ├── test.md                           # Test command workflow
│   │   └── update-knowledge.md               # Update instruction files workflow
│   └── README.md                             # Custom commands documentation
├── cmd/
│   ├── mcp-server/
│   │   └── run.go                            # MCP server entry point
│   └── run.go                                # Main CLI entry point
├── src/
│   ├── cli/
│   │   ├── root.go                           # Cobra CLI implementation
│   │   └── root_test.go                      # CLI tests
│   ├── internal/
│   │   ├── helper/
│   │   │   └── gc/
│   │   │       ├── mock_buffer_test.go       # Mock buffer for testing
│   │   │       ├── reduce_overhead.go        # Buffer pool abstraction (gc.Pool interface)
│   │   │       └── reduce_overhead_test.go   # Buffer pool tests
│   │   └── x509/
│   │       ├── certs/
│   │       │   ├── cert_test.go              # Certificate tests
│   │       │   └── certs.go                  # Certificate encoding/decoding
│   │       └── chain/
│   │           ├── benchmark_test.go         # Chain resolution and revocation benchmarks
│   │           ├── cache.go                  # CRL cache implementation with LRU eviction and metrics
│   │           ├── chain.go                  # Chain resolution logic
│   │           ├── chain_test.go             # Chain tests
│   │           ├── lru_test.go               # LRU cache tests for access, eviction, and concurrency
│   │           ├── remote.go                 # Context-aware remote TLS chain fetcher
│   │           └── revocation.go             # OCSP/CRL revocation status checking
│   ├── logger/
│   │   ├── benchmark_test.go                 # Logger benchmarks
│   │   ├── logger.go                         # Logger abstraction (CLI/MCP, thread-safe with bytebufferpool)
│   │   └── logger_test.go                    # Logger tests
│   ├── mcp-server/
│   │   ├── config.example.json               # MCP server configuration example
│   │   ├── config.go                         # MCP server configuration and AI settings
│   │   ├── framework.go                      # ServerBuilder pattern, sampling registration, streaming buffer pooling
│   │   ├── handlers.go                       # MCP tool handlers, AI certificate analysis, certificate processing utilities
│   │   ├── prompts.go                        # MCP prompt definitions and handlers for certificate workflows
│   │   ├── resource_usage.go                 # Resource usage monitoring and formatting functions
│   │   ├── resources.go                      # MCP resource definitions and handlers (config, version, formats, status)
│   │   ├── run_graceful_test.go              # Graceful shutdown test (Windows build constraint)
│   │   ├── run_test.go                       # MCP server tests
│   │   ├── server.go                         # Server execution and lifecycle management
│   │   ├── templates/
│   │   │   ├── certificate-analysis-system-prompt.md     # Embedded AI analysis system prompt used for sampling
│   │   │   └── certificate-formats.md                    # Certificate format documentation
│   │   └── tools.go                          # Tool definitions and creation functions
│   └── version/
│       └── version.go                        # Version information and build metadata
├── .gitignore                                # Git ignore patterns
├── .ignore                                   # Tool ignore patterns (glob/grep)
├── AGENTS.md                                 # Primary agent guidelines
├── LICENSE                                   # BSD 3-Clause License
├── Makefile                                  # Build commands
├── README.md                                 # Project documentation
├── go.mod                                    # Go module definition (Go 1.25.4)
├── go.sum                                    # Go dependency checksums
└── opencode.json                             # OpenCode configuration
```

## Available Tools

### 1. read(filePath, offset?, limit?)

**Purpose**: Read file contents with line numbers  
**Default**: First 2000 lines from start  
**Line Numbers**: Format is `spaces + line number + tab + content`

**Parameters**:
- `filePath` - Absolute path to file (required)
- `offset` - 0-based line number to start from (optional)
- `limit` - Number of lines to read (optional, default: 2000)

**Examples**:
```
# Read entire file (up to 2000 lines)
read("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/cli/root.go")

# Read lines 50-100 (windowed reading)
read("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/cli/root.go", offset=50, limit=50)

# Read from line 100 to end
read("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/internal/x509/chain/chain.go", offset=100)
```

**When to use**:
- Reading source files before editing
- Understanding implementation details
- Reviewing test files
- Reading documentation

**Best Practices**:
- Always read before editing files
- Use offset/limit for large files (>2000 lines)
- Use grep first to locate specific content, then read with offset

### 2. write(filePath, content)

**Purpose**: Create new files or overwrite existing files  
**IMPORTANT**: Must read file first if it already exists

**Examples**:
```
# Create new test file
write("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/internal/x509/certs/helper_test.go", content)

# Overwrite existing file (must read first!)
read("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/cli/root.go")
write("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/cli/root.go", newContent)
```

**When to use**:
- Creating new source files
- Creating new test files
- Creating documentation

**When NOT to use**:
- Modifying existing files (use edit instead)
- Creating build artifacts
- Creating temporary files

**Best Practices**:
- ALWAYS prefer edit over write for existing files
- NEVER create documentation files unless explicitly requested
- Read file first before overwriting
- Verify content after write by reading again

### 3. edit(filePath, oldString, newString, replaceAll?)

**Purpose**: Precise string replacement in files  
**IMPORTANT**: Must read file first before editing

**Parameters**:
- `filePath` - Absolute path to file
- `oldString` - Exact string to replace (must match exactly, including indentation)
- `newString` - Replacement string (must be different from oldString)
- `replaceAll` - Replace all occurrences (default: false)

**Examples**:
```
# Single replacement
edit(
  "/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/cli/root.go",
  oldString="log.Printf(\"Starting TLS certificate chain resolver (v%s)...\", version)",
  newString="log.Printf(\"Starting TLS certificate chain resolver v%s...\", version)"
)

# Replace all occurrences (useful for renaming)
edit(
  "/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/internal/x509/certs/certs.go",
  oldString="EncodePEM",
  newString="EncodeToPEM",
  replaceAll=true
)
```

**When to use**:
- Modifying existing code
- Fixing bugs
- Refactoring
- Updating documentation

**Critical Rules**:
1. MUST read file before editing
2. Preserve exact indentation from read output (ignore line number prefix)
3. oldString must match EXACTLY (including whitespace)
4. If oldString appears multiple times, either:
   - Provide more context in oldString to make it unique, OR
   - Use replaceAll=true to change all occurrences

**Common Errors**:
```
❌ "oldString not found in content"
   → Check indentation matches exactly
   → Verify string exists in file
   → Read file again to confirm content

❌ "oldString found multiple times"
   → Add more surrounding code to oldString for uniqueness
   → OR use replaceAll=true if you want to change all
```

**Line Number Format**:
```
Read output shows:
"00045|     log.Printf(\"test\")"
         ^^^^^ line number prefix (ignore when editing)
              ^^^^^^^^^^^^^^^^^^^ actual file content (use this in oldString)

Use in edit:
oldString="    log.Printf(\"test\")"  # No line number prefix!
```

### 4. list(path?)

**Purpose**: List directory contents  
**Default**: Current working directory if path not specified

**Examples**:
```
# List root directory
list("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver")

# List specific package
list("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src/internal/x509")

# List current directory
list()
```

**When to use**:
- Exploring directory structure
- Verifying file existence before read/write
- Finding test files
- Checking build output

### 5. glob(pattern, path?)

**Purpose**: Find files by pattern  
**Respects**: `.ignore` file  
**Returns**: Sorted by modification time

**Examples**:
```
# Find all Go source files
glob("**/*.go")

# Find test files
glob("**/*_test.go")

# Find files in specific package
glob("src/internal/x509/**/*.go")

# Find certificate files
glob("**/*.cer")
glob("**/*.pem")

# Find Markdown files
glob("**/*.md")
```

**When to use**:
- Finding files before reading
- Locating test files
- Finding all files of a type
- File discovery before grep

**Best Practices**:
- Use specific patterns to narrow results
- Combine with grep for content search
- Check results before bulk operations

### 6. grep(pattern, path?, include?)

**Purpose**: Search file contents with regex  
**Respects**: `.ignore` file  
**Returns**: Files containing matches (sorted by modification time)

**Parameters**:
- `pattern` - Regex pattern to search
- `path` - Directory to search in (optional)
- `include` - File pattern to include (optional, e.g., "*.go")

**Examples**:
```
# Find function definitions
grep("func.*Certificate", include="*.go")

# Find specific type usage
grep("x509chain\\.New", include="*.go")

# Find error handling
grep("fmt\\.Errorf", path="src/internal", include="*.go")

# Find test functions
grep("func Test", include="*_test.go")

# Find TODO comments
grep("TODO:", include="*.go")
```

**When to use**:
- Finding function/type definitions
- Locating error messages
- Finding usage patterns
- Code exploration before modification

**Best Practices**:
- Use include pattern to filter files
- Use specific regex patterns
- Combine with glob for efficiency
- Use read with offset after finding matches

**Regex Patterns**:
```
# Literal match
"Certificate"

# Function definitions
"func.*FetchCertificate"

# Method calls
"certManager\\.Decode"

# Type definitions
"type Chain struct"

# Error patterns
"error.*certificate"
```

## Workflows

### 1. Understanding New Code

```
# List package structure
list("/path/to/package")

# Find all Go files
glob("package/**/*.go")

# Search for specific functionality
grep("FetchCertificate", path="package", include="*.go")

# Read relevant files
read("/path/to/file.go")
```

### 2. Modifying Existing Code

```
# Find file containing function
grep("func execCli", include="*.go")

# Read file
read("/path/to/file.go")

# Edit specific section
edit("/path/to/file.go", oldString="...", newString="...")

# Verify changes
read("/path/to/file.go")
```

### 3. Adding New Feature

```
# Find similar implementations
grep("similar.*pattern", include="*.go")

# Read examples
read("/path/to/example.go")

# Create new file or edit existing
edit("/path/to/file.go", ...)

# Create tests
write("/path/to/file_test.go", testContent)
```

### 4. Bug Fixing

```
# Search for error location
grep("error message", include="*.go")

# Read surrounding code
read("/path/to/file.go", offset=line-10, limit=30)

# Find all references
grep("functionName", include="*.go")

# Fix issue
edit("/path/to/file.go", oldString="buggy code", newString="fixed code")

# Update tests
edit("/path/to/file_test.go", ...)
```

## Integration with Other Tools

### Filesystem → Gopls

```
# Find files with glob
glob("src/internal/x509/**/*.go")

# Use Gopls to understand structure
gopls_go_file_context("/path/to/file.go")
gopls_go_package_api(["package/path"])
```

### Grep → Read (Windowed Reading)

```
# Find matches
grep("FetchCertificate", include="*.go")
# Result: Found at line 105 in chain.go

# Read around match with offset/limit
read("/path/to/chain.go", offset=100, limit=30)  # Read lines 100-130
```

### Read → Edit → Test

```
# Read current implementation
read("/path/to/file.go")

# Edit code
edit("/path/to/file.go", oldString="...", newString="...")

# Verify with Gopls
gopls_go_diagnostics(["/path/to/file.go"])

# Run tests
bash("go test -v ./package 2>&1 | cat")
```

## Best Practices for This Repository

### 1. Always Read Before Edit

```
❌ BAD:
edit("/path/to/file.go", ...)  # ERROR: Must read first

✅ GOOD:
read("/path/to/file.go")
edit("/path/to/file.go", ...)
```

### 2. Use Glob Before Grep

```
❌ BAD:
grep("Certificate")  # Searches everything, slow

✅ GOOD: Filter early, compose tools Unix Philosophy
glob("src/internal/**/*.go")  # Get source files only
grep("Certificate", path="src/internal", include="*.go")  # Search filtered set
```

### 3. Selective Reading for Large Files

```
❌ BAD:
read("/path/to/large-file.go")  # Reads all 2000 lines

✅ GOOD:
grep("functionName", include="*.go")  # Find line number
read("/path/to/large-file.go", offset=100, limit=50)  # Read only needed section
```

### 4. Preserve Indentation in Edits

```
Read output:
00045|     log.Printf("test")
        ^^^^ 4 spaces indentation

✅ GOOD edit:
oldString="    log.Printf(\"test\")"  # Preserves 4 spaces

❌ BAD edit:
oldString="log.Printf(\"test\")"  # Missing indentation - will fail
```

### 5. Verify Operations

```
# After write
write("/path/to/file.go", content)
read("/path/to/file.go")  # Verify content

# After edit
edit("/path/to/file.go", ...)
gopls_go_diagnostics(["/path/to/file.go"])  # Check for errors
```

## Ignored Patterns (.ignore file)

The following patterns are automatically excluded by glob/grep:

**Directories**:
- `bin/` - Build artifacts
- `.git/` - Version control
- `.vscode/`, `.idea/`, `.idx/` - IDEs
- `tmp/` - Temporary files
- `vendor/` - Dependencies

**File Patterns**:
- `*.exe`, `*.dll`, `*.so`, `*.dylib` - Binaries
- `*.test`, `*.out` - Test artifacts
- `*.cer`, `*.pem`, `*.crt`, `*.key`, `*.der` - Certificates
- `go.work`, `go.work.sum` - Go workspace
- `.env`, `.env.*` - Environment files
- `.DS_Store`, `Thumbs.db` - OS files

**Why this matters**: glob/grep respect .ignore, bash commands do not.

```
✅ GOOD:
glob("**/*.go")  # Automatically excludes bin/, .git/, etc.

❌ BAD:
bash("find . -name '*.go'")  # Searches everything, including ignored dirs
```

## Common Pitfalls

### ❌ Using bash for File Operations

```
BAD:
bash("find . -name '*.go'")           # Use glob instead
bash("grep -r 'pattern' .")           # Use grep tool instead
bash("cat file.go")                   # Use read instead
bash("ls -la directory/")             # Use list instead

GOOD:
glob("**/*.go")
grep("pattern", include="*.go")
read("file.go")
list("directory")
```

### ❌ Editing Without Reading

```
BAD:
edit("file.go", ...)  # ERROR: Must read first

GOOD:
read("file.go")
edit("file.go", ...)
```

### ❌ Incorrect Indentation in Edit

```
Read shows:
00045|     if err != nil {
              ^^^^ 4 spaces

BAD edit:
oldString="if err != nil {"  # Missing indentation

GOOD edit:
oldString="    if err != nil {"  # Preserves indentation
```

### ❌ Creating Unnecessary Files

```
BAD:
write("NOTES.md", ...)          # Don't create documentation unless requested
write("TODO.txt", ...)          # Don't create tracking files

GOOD:
edit("existing-file.go", ...)   # Modify existing code
write("new_test.go", ...)       # Create new test files when needed
```

## Repository-Specific Patterns

### Common File Paths

```
# Agent instructions
.github/instructions/README.md
.github/instructions/gopls.instructions.md
.github/instructions/deepwiki.instructions.md
.github/instructions/filesystem.instructions.md
.github/instructions/memory.instructions.md
.github/instructions/opencode.instructions.md
.github/instructions/x509_resolver.md

# Custom commands
.opencode/README.md
.opencode/command/create-changelog.md
.opencode/command/test.md
.opencode/command/update-knowledge.md
.opencode/command/test-capabilities.md

# Main entry point
cmd/run.go

# MCP server entry point
cmd/mcp-server/run.go

# CLI implementation
src/cli/root.go
src/cli/root_test.go

# Logger abstraction (thread-safe with sync.Mutex and gc.Pool)
src/logger/logger.go
src/logger/logger_test.go
src/logger/benchmark_test.go

# MCP server implementation
src/mcp-server/config.example.json
src/mcp-server/config.go
src/mcp-server/framework.go  # ServerBuilder pattern, AI sampling with buffer pooling (DefaultSamplingHandler)
src/mcp-server/handlers.go   # MCP tool handlers, AI certificate analysis, certificate processing utilities
src/mcp-server/prompts.go    # MCP prompt definitions and handlers for certificate workflows
src/mcp-server/resource_usage.go  # Resource usage monitoring and formatting functions
src/mcp-server/resources.go  # MCP resource definitions and handlers including status resource
src/mcp-server/run_graceful_test.go  # Graceful shutdown test (non-Windows)
src/mcp-server/run_test.go   # Comprehensive tool coverage tests with macOS skip for validation
src/mcp-server/server.go
src/mcp-server/tools.go
src/mcp-server/templates/certificate-analysis-system-prompt.md  # Embedded AI system prompt
src/mcp-server/templates/certificate-formats.md


# Certificate operations
src/internal/x509/certs/certs.go
src/internal/x509/certs/cert_test.go

# Chain resolution
src/internal/x509/chain/chain.go
src/internal/x509/chain/chain_test.go
src/internal/x509/chain/benchmark_test.go  # Chain resolution and revocation benchmarks
src/internal/x509/chain/cache.go  # O(1) LRU CRL cache implementation with hashmap, doubly-linked list, and atomic metrics
src/internal/x509/chain/lru_test.go  # O(1) LRU cache tests for access order, eviction correctness, concurrency, and leak detection
src/internal/x509/chain/remote.go  # Context-aware remote TLS chain helper
src/internal/x509/chain/revocation.go  # OCSP/CRL revocation status checking

# Helper utilities (buffer pool abstraction)
src/internal/helper/gc/reduce_overhead.go
src/internal/helper/gc/reduce_overhead_test.go
src/internal/helper/gc/mock_buffer_test.go

# Version information
src/version/version.go

# Build configuration
Makefile
go.mod
go.sum

# Documentation
README.md
AGENTS.md
LICENSE

# Configuration
opencode.json
.ignore
```

### Common Search Patterns

```
# Find all test files
glob("**/*_test.go")

# Find benchmark files
glob("**/*benchmark_test.go")

# Find function definitions
grep("func (c \\*Certificate)", include="*.go")

# Find error handling
grep("fmt\\.Errorf", include="*.go")

# Find certificate operations
grep("Encode.*PEM", include="*.go")

# Find CRL cache patterns
grep("CRLCacheEntry\\|CRLCacheConfig\\|CRLCacheMetrics", include="*.go")

# Find O(1) LRU cache patterns
grep("LRUNode\\|updateCacheOrder\\|removeFromCacheOrder\\|pruneCRLCache", include="*.go")

# Find CRL cache lifecycle patterns
grep("StartCRLCacheCleanup\\|StopCRLCacheCleanup\\|cleanupExpiredCRLs", include="*.go")

# Find CRL freshness and expiration patterns
grep("isFresh\\|isExpired", include="*.go")

# Find resource usage monitoring patterns
grep("ResourceUsageData\\|CollectResourceUsage\\|FormatResourceUsage", include="*.go")

# Find changelog creation commands
grep("create-changelog", include="*.md")

# Find OpenCode command files
glob(".opencode/command/*.md")

# Find chain methods
grep("func (c \\*Chain)", include="*.go")

# Find remote chain fetching
grep("FetchRemoteChain", include="*.go")

# Find revocation status checking
grep("CheckRevocationStatus\\|RevocationStatus", include="*.go")

# Find OCSP/CRL functions
grep("createOCSPRequest\\|ParseOCSPResponse\\|ParseCRLResponse", include="*.go")

# Find logger usage
grep("logger\\.Logger", include="*.go")

# Find logger implementations
grep("NewCLILogger\\|NewMCPLogger", include="*.go")

# Find thread-safety patterns
grep("sync\\.Mutex", include="*.go")

# Find logger tests
grep("TestMCPLogger\\|TestCLILogger", include="*_test.go")

# Find logger benchmarks
grep("BenchmarkMCPLogger\\|BenchmarkCLILogger", include="*_test.go")

# Find buffer pooling usage
grep("gc\\.Pool\\|gc\\.Default", include="*.go")

# Find buffer pool tests
grep("TestBuffer\\|TestPool", include="*_test.go")

# Find buffer interface methods
grep("WriteString\\|WriteByte\\|ReadFrom\\|WriteTo", include="*.go")

# Find buffer Set methods
grep("buf\\.Set\\|buf\\.SetString", include="*.go")

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

# Find benchmark tests
grep("Benchmark.*Chain\\|Benchmark.*Revocation\\|Benchmark.*Certificate", include="*_test.go")

# Find CRL cache benchmarks
grep("BenchmarkCRLCacheOperations", include="*_test.go")

# Find CRL cache patterns
grep("CRLCacheEntry\\|CRLCacheConfig\\|CRLCacheMetrics", include="*.go")

# Find MCP server tools
grep("resolve_cert_chain\\|validate_cert_chain\\|check_cert_expiry\\|batch_resolve_cert_chain\\|fetch_remote_cert\\|analyze_certificate_with_ai", include="*.go")

# Find MCP server configuration
grep("MCP_X509_CONFIG_FILE\\|config\\.Defaults\\|AI.*API", include="*.go")

# Find MCP tool handlers
grep("handleResolveCertChain\\|handleValidateCertChain\\|handleCheckCertExpiry\\|handleBatchResolveCertChain\\|handleFetchRemoteCert\\|handleAnalyzeCertificateWithAI", include="*.go")

# Find MCP resources and prompts
grep("addResources\\|addPrompts\\|certificate-analysis\\|expiry-monitoring\\|security-audit\\|troubleshooting\\|config://template\\|info://version\\|docs://certificate-formats\\|status://server-status", include="*.go")

# Find AI integration patterns
grep("DefaultSamplingHandler\\|CreateMessage\\|SamplingRequest\\|streaming\\|MaxTokens", include="*.go")

# Find MCP server builder pattern
grep("ServerBuilder\\|NewServerBuilder\\|WithConfig\\|WithDefaultTools\\|createResources\\|createPrompts", include="*.go")

# Find MCP server status resource
grep("handleStatusResource\\|status://server-status", include="*.go")

# Find embedded templates
grep("MagicEmbed\\|templates/certificate.*\\.md", include="*.go")


# Find graceful shutdown tests
grep("run_graceful_test\\.go\\|syscall\\.Kill", include="*_test.go")

# Find platform-specific test skips
grep("runtime\\.GOOS == \\"windows\\"\\|t\\.Skip\\(\\"Skipping on macOS\\", include="*_test.go")
```

### Common Edit Patterns

```
# Update error messages
edit("file.go",
  oldString='return fmt.Errorf("old message: %w", err)',
  newString='return fmt.Errorf("new message: %w", err)'
)

# Update logger output
edit("file.go",
  oldString='globalLogger.Printf("old format")',
  newString='globalLogger.Printf("new format")'
)

# Refactor function calls
edit("file.go",
  oldString='result := oldFunction(arg)',
  newString='result := newFunction(arg)'
)
```

## Summary

1. **Always read before edit** - Required for edit tool
2. **Use glob/grep over bash** - Respects .ignore, structured output, follows [Unix Philosophy](https://grokipedia.com/page/Unix_philosophy)
3. **Preserve indentation** - Match exact whitespace in edits
4. **Selective reading** - Use offset/limit for large files
5. **Verify operations** - Read after write, diagnostics after edit
6. **Filter early** - Use glob before grep for efficiency
7. **Respect .ignore** - Tools automatically exclude build artifacts, certificates, etc.

**Tool Selection**:
- File discovery → glob
- Content search → grep
- Read code → read
- Modify code → edit (preferred) or write (new files only)
- Directory listing → list
- Build/test/git → bash (only for operations tools can't do)
