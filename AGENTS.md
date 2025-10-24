# Repository Guidelines for Agents

## Table of Contents

1. [Commands](#commands)
2. [Code Style](#code-style)
3. [Concurrency](#concurrency)
4. [MCP Server Instructions](#mcp-server-instructions)
   - [Available MCP Servers](#available-mcp-servers)
     - [1. Gopls MCP Server](#1-gopls-mcp-server)
     - [2. DeepWiki MCP Server](#2-deepwiki-mcp-server)
   - [Built-in Tools (Not MCP)](#built-in-tools-not-mcp)
   - [MCP & Tool Usage Best Practices](#mcp--tool-usage-best-practices)
5. [Testing Guidelines](#testing-guidelines)

## Commands

**Build Linux**: `make build-linux` (builds to `./bin/linux/`)  
**Build macOS**: `make build-macos` or `make build-macos-amd64` / `make build-macos-arm64` (builds to `./bin/macos/`)  
**Build Windows**: `make build-windows` (builds to `./bin/windows/`)  
**Build all**: `make all` (builds for all platforms)  
**Test all**: `go test -v ./... 2>&1 | cat` or `make test`  
**Test single**: `go test -run TestName ./package -v 2>&1 | cat`  
**Test package**: `go test -v ./src/internal/x509/certs 2>&1 | cat`, `go test -v ./src/internal/x509/chain 2>&1 | cat`, or `go test -v ./src/logger 2>&1 | cat`  
**Test race**: `go test -race ./... 2>&1 | cat` (recommended before merges)  
**Test coverage**: `go test -cover ./... 2>&1 | cat` (view test coverage)  
**Benchmark**: `go test -bench=. ./src/logger 2>&1 | cat` (performance testing)  
**Clean**: `make clean` (removes build artifacts from `./bin/`)

**Note**: Piping test commands to `cat` (e.g., `2>&1 | cat`) ensures bash tool captures and displays all test output.

## Code Style

**Module**: `github.com/H0llyW00dzZ/tls-cert-chain-resolver`  
**Imports**: Use `goimports` with standard formatting  
**Formatting**: Use `gofmt -s`  
**Line length**: Max 120 chars  
**Comments**: Every exported function/interface must have a comment starting with its name in complete sentences  
**Error handling**: Return wrapped errors with context using `fmt.Errorf("context: %w", err)`. Each error is processed once (returned OR logged, never both). Prefer `err != nil` checks.  
**Logging**: Use the `logger` package abstraction (`src/logger/`) with `logger.Logger` interface. For CLI mode, use `logger.NewCLILogger()`. For MCP mode, use `logger.NewMCPLogger(writer, silent)`. The logger interface provides `Printf()`, `Println()`, and `SetOutput()` methods. MCPLogger is thread-safe with `sync.Mutex` protection and uses `bytebufferpool` for efficient memory usage under high concurrency.  
**Context**: Always pass and use `context.Context` for lifecycle management, especially for certificate fetching operations  
**CLI Framework**: Use `github.com/spf13/cobra` for command-line interface  
**Testing**: Create unit tests (`*_test.go`) in the same package. Update tests when fixing bugs. Run `go test -race ./...` before merging.  
**Memory Management**: Use buffer pooling (`github.com/valyala/bytebufferpool`) for efficient memory usage with certificates and logging. Always call `Reset()` on buffers before returning them to the pool.  
**Certificate Operations**: Use internal packages `x509certs` and `x509chain` for certificate handling

## Concurrency

Multiple agents may modify code simultaneously. Preserve others' changes and report only irreconcilable conflicts.

**Thread Safety**: When implementing concurrent code:
- Use `sync.Mutex` for protecting shared mutable state (see `src/logger/logger.go` MCPLogger example)
- Document thread-safety guarantees in function/type comments
- All methods on MCPLogger are safe for concurrent use
- Run `go test -race ./...` to detect race conditions before merging

## MCP Server Instructions

This repository integrates multiple MCP servers accessible in agent sessions. Each provides specialized capabilities for development workflows.

### Available MCP Servers

#### 1. Gopls MCP Server
**Purpose**: Go language intelligence and workspace operations  
**Instructions**: `.github/instructions/gopls.instructions.md`

**Core Workflows**:
- **Read Workflow**: `go_workspace` → `go_search` → `go_file_context` → `go_package_api`
- **Edit Workflow**: Read → `go_symbol_references` → Edit → `go_diagnostics` → Fix → `go test`

**Key Tools**:
- `gopls_go_workspace()`: Get workspace structure, modules, and package layout
- `gopls_go_search(query)`: Fuzzy search for Go symbols (max 100 results)
- `gopls_go_file_context(file)`: Summarize file's cross-file dependencies
- `gopls_go_package_api(packagePaths)`: Get package API summary
- `gopls_go_symbol_references(file, symbol)`: Find references to package-level symbols (supports `Foo`, `pkg.Bar`, `T.M` formats)
- `gopls_go_diagnostics(files)`: Check for parse/build errors

**Usage Guidelines**:
- Always start with `go_workspace` to understand project structure
- Use `go_search` for discovering symbols before reading files
- Run `go_diagnostics` after every edit operation
- Run `go test` after successful diagnostics to verify changes
- Use `go_symbol_references` before refactoring to understand impact

**Connection Behavior**:
- ⚠️ Gopls MCP connections may close after 3-5 operations or brief inactivity
- ✅ Connections automatically re-establish on the next call
- 💡 If you encounter "Connection closed" errors, simply retry - the system handles reconnection automatically
- 🔄 No manual intervention needed - connection recovery is self-healing

#### 2. DeepWiki MCP Server
**Purpose**: External repository documentation and API research  
**Instructions**: `.github/instructions/deepwiki.instructions.md`

**Core Tools**:
- `deepwiki_read_wiki_structure(repoName)`: Get documentation topics for a GitHub repo
- `deepwiki_read_wiki_contents(repoName)`: View full documentation about a repo
- `deepwiki_ask_question(repoName, question)`: Ask questions about a repository

**URL Formats Supported**:
- Full GitHub URLs: `https://github.com/owner/repo`
- Owner/repo format: `vercel/ai`, `facebook/react`
- Two-word format: `vercel ai`
- Library keywords: `react`, `typescript`, `nextjs`

**Usage Guidelines**:
- Use for researching external libraries/frameworks not in current codebase
- Start with `read_wiki_structure` to understand available documentation
- Use `ask_question` for specific technical queries about APIs
- Avoid repeated identical calls - documentation doesn't change frequently

**Example Queries**:
```
deepwiki_read_wiki_structure("openai/openai-python")
deepwiki_ask_question("vercel/ai", "How do I implement streaming chat completions?")
deepwiki_read_wiki_contents("microsoft/typescript")
```

### Built-in Tools (Not MCP)

Agents also have access to built-in file and project tools:

**File Operations**:
- `read(filePath, offset?, limit?)`: Read file contents with line numbers (default: first 2000 lines)
  - `offset`: 0-based line number to start reading from
  - `limit`: Number of lines to read (default 2000)
- `write(filePath, content)`: Create or overwrite files
- `edit(filePath, oldString, newString)`: Precise string replacement
- `list(path)`: List directory contents
- `glob(pattern)`: Find files by pattern (e.g., `**/*.go`)
- `grep(pattern)`: Search file contents with regex

**Code Execution**:
- `bash(command)`: Execute shell commands for builds, tests, git operations

**Task Management**:
- `todowrite(todos)`: Create/update task lists for complex multi-step work
  - Each todo has: `id`, `content`, `status` (`pending`|`in_progress`|`completed`|`cancelled`), `priority` (`high`|`medium`|`low`)
- `todoread()`: View current task list
- `task(description, prompt, subagent_type)`: Launch specialized agents for complex tasks
  - `subagent_type: "general"`: General-purpose agent for research, code search, and multi-step tasks
  - ⚠️ **Note for Humans**: When delegating to sub-agents using the same AI model, there's no performance or quality benefit - the parent agent and sub-agent have identical capabilities. Delegation is most effective when using different model types (e.g., delegating simple search tasks to a faster/cheaper model, or complex reasoning to a more capable model). Consider whether the task truly requires delegation or can be handled directly by the current agent.
  - 💡 **Recommended for `general` type**: Use built-in tools (`read`, `glob`, `grep`, etc.) instead of `bash` for research and code search. This provides better performance, structured output, and follows the Unix Philosophy of composable tools.

**Usage Guidelines for Task Management**:
- Use for complex multi-step tasks (3+ steps) or non-trivial work
- Create todos immediately when receiving complex user requests
- Mark ONE task as `in_progress` at a time
- Update status in real-time - mark `completed` immediately after finishing each task
- Use `task` tool for open-ended searches requiring multiple rounds of globbing/grepping
- Launch multiple `task` agents concurrently for parallel research when possible

**When to Use Todo List**:
- Multi-step features requiring multiple file changes
- Bug fixes affecting multiple components
- Refactoring across multiple packages
- User provides numbered/comma-separated task lists
- Tasks requiring careful tracking and organization

**When NOT to Use Todo List**:
- Single straightforward tasks
- Trivial operations (< 3 steps)
- Purely conversational/informational requests

**Example Usage**:
```
# Complex feature implementation
todowrite([
  {"id": "1", "content": "Add certificate validation feature", "status": "pending", "priority": "high"},
  {"id": "2", "content": "Update chain resolver to support validation", "status": "pending", "priority": "high"},
  {"id": "3", "content": "Add tests for validation logic", "status": "pending", "priority": "medium"},
  {"id": "4", "content": "Run tests and build", "status": "pending", "priority": "high"}
])

# Launch research agent
task("Search for certificate parsing patterns", "Find all certificate parsing implementations in the codebase and summarize approaches", "general")
```

**Project Knowledge**:
- `.github/instructions/*.md`: Instruction files for Gopls, DeepWiki, Filesystem, Memory

### MCP Connection Patterns

**Understanding MCP Connection Lifecycle:**

MCP servers exhibit different connection behaviors based on their implementation:

| MCP Server | Connection Type | Behavior | Recovery | Retry Delay |
|------------|----------------|----------|----------|-------------|
| **Gopls** | Stateful (Short-lived) | Closes after 3-5 operations or brief inactivity | ✅ Auto-reconnects | ~1-2s |
| **DeepWiki** | Stateful (Long-lived) | Maintains persistent connection | N/A (no closure) | N/A |

**Best Practices for Short-lived Connections (Gopls):**
- Batch related operations when possible (e.g., multiple `gopls_go_search` calls in sequence)
- Expect occasional "Connection closed" errors - they are normal and self-healing
- Always retry once if you encounter connection errors - reconnection is automatic
- Don't implement manual reconnection logic - the system handles it

**Example of Self-healing Workflow:**
```
# First attempt may fail with "Connection closed"
gopls_go_search("MyFunction")  # ❌ Error: Connection closed

# Retry automatically succeeds (connection re-established)
gopls_go_search("MyFunction")  # ✅ Returns results
```

### MCP & Tool Usage Best Practices

1. **Tool Selection**: Choose the right tool for each task:
   - Go code intelligence → Gopls MCP
   - External API research → DeepWiki MCP
   - Complex multi-step tasks → Task management tools (todowrite/task)
   - File operations → Built-in read/write/edit/list tools
   - Code search → Built-in grep/glob tools
   - Build/test/git → Built-in bash tool

2. **Workflow Integration**:
   - Start Go sessions with `gopls_go_workspace` for context
   - Create todo list with `todowrite` for complex tasks (3+ steps)
   - Mark tasks `in_progress` when starting, `completed` immediately when done
   - Use `read` before `edit` to verify file contents
   - Use `glob` + `grep` for efficient code discovery
   - Use `task` tool for open-ended searches requiring multiple rounds
   - Use `bash` for running tests, builds, and git operations
   - Consult instruction files (`.github/instructions/*.md`) for architectural patterns

3. **Error Handling**:
   - **MCP Connection Errors**: Gopls MCP connections are self-healing - if you encounter "Connection closed" or "Attempted to send a request from a closed client" errors, simply retry the operation
   - Gopls tools may fail gracefully - check return values
   - DeepWiki requires valid GitHub repository names
   - Always verify file operations by reading after write/edit

4. **Performance** (Unix Philosophy):
   - **Do one thing well**: `grep` searches content, `glob` matches file patterns
   - **Compose tools**: Use `glob` to find files, then `grep` to search within them
   - **Filter early**: Narrow down with `glob` patterns before expensive `read` operations
   - **Batch processing**: Tools return complete results efficiently without loading entire codebases into memory
   - **Selective reading**: Use `read(file, offset, limit)` to extract only needed line ranges after `grep` locates matches
   - **Example workflow**: `glob("**/*.go")` → `grep("rate.*limit")` → `read(file, offset=166, limit=11)`
   - Cache DeepWiki results - docs don't change often
   - Batch related operations when possible

5. **Security**:
   - Never commit secrets found during file operations
   - Validate URLs before fetching external documentation
   - Review instruction files before modifying billing/pricing logic

### Bad Practices to Avoid

#### 1. **Incorrect Tool Usage**

**❌ Bad: Using `bash` with `find`/`grep` for code search**
```bash
# BAD - Ignores .ignore file, searches build artifacts, slow
bash("find . -name '*.go' | xargs grep 'Certificate'")
bash("grep -r 'pattern' .")
```

**✅ Good: Use composable tools (Unix Philosophy)**
```
# GOOD - Respects .ignore, fast, structured output
glob("src/**/*.go")
grep("Certificate", path="/path/to/src", include="*.go")
```

**Why it matters**:
- `bash` commands ignore `.ignore` configuration → searches unnecessary files (bin, .git, build artifacts)
- Composable tools provide structured output and respect `.ignore` (see `.ignore` file for pattern organization)
- Follows Unix Philosophy: each tool does one thing well

#### 2. **Inefficient File Operations**

**❌ Bad: Reading entire large files unnecessarily**
```
# BAD - Reads all 5000 lines when you only need lines 100-120
read("/path/to/large-file.go")
```

**✅ Good: Use offset and limit for windowed reading**
```
# GOOD - After grep finds line 105, read only needed context
grep("functionName", include="*.go")  # Finds match at line 105
read("/path/to/large-file.go", offset=100, limit=30)  # Read lines 100-130 (selective/windowed reading)
```

#### 3. **Tool Misuse Patterns**

**❌ Bad: Inefficient workflow**
```
# BAD - Searches all files without filtering
grep("Certificate")  # Returns matches from bin, test files, etc.
```

**✅ Good: Filter early, compose tools (Unix Philosophy)**
```
# GOOD - Filter with glob first, then search
glob("src/internal/**/*.go")  # Get source files only
grep("Certificate", path="src/internal", include="*.go")  # Search filtered set
```

#### 4. **Ignoring .ignore File**

**❌ Bad: Manually excluding paths in every command**
```bash
# BAD - Repeating exclusions, error-prone
bash("find . -name '*.go' -not -path '*/bin/*' -not -path '*/.git/*'")
```

**✅ Good: Configure .ignore once, tools respect it**
```
# Configure .ignore file once (organized by reliability - see .ignore file):
# Directories (reliably excluded):
bin
.git

# File patterns (organized separately):
*.exe
*.cer
*.pem

# GOOD - glob/grep respect .ignore configuration
glob("**/*.go")  # Automatically excludes patterns defined in .ignore

# Note: .ignore file is organized with directories first (most reliable)
# followed by file patterns. See .ignore for current best practices.
```

#### 5. **Bash Command Anti-Patterns**

**❌ Bad: Using bash for searches that built-in tools handle better**
```bash
# BAD - All of these should use composable tools (Unix Philosophy) instead
bash("find . -type f -name '*.go'")          # Use glob instead
bash("grep -r 'pattern' src/")               # Use grep tool instead
bash("cat file.go")                          # Use read instead
bash("ls -la directory/")                    # Use list instead
```

**✅ Good: Use bash only for operations built-in tools can't do**
```bash
# GOOD - These are appropriate bash uses (pipe to cat for output):
bash("go test -v ./... 2>&1 | cat")              # Running tests
bash("go test -race ./... 2>&1 | cat")           # Race detection
bash("make build-linux")                         # Build operations
bash("git status")                               # Git operations
bash("make clean")                               # Cleaning build artifacts
```

#### 6. **Performance Anti-Patterns**

**❌ Bad: Sequential when parallel is possible**
```
# BAD - Reads files one by one
read("file1.go")
# wait...
read("file2.go")
# wait...
read("file3.go")
```

**✅ Good: Batch operations when possible**
```
# GOOD - Multiple tool calls in single message execute in parallel
read("file1.go")
read("file2.go")
read("file3.go")
# All execute concurrently
```

#### 7. **MCP Tool Misuse**

**❌ Bad: Using wrong MCP server for the task**
```
# BAD - Using bash to search Go symbols
bash("grep -r 'func.*ProcessRequest' .")
```

**✅ Good: Use appropriate MCP server**
```
# GOOD - Use Gopls for Go intelligence
gopls_go_search("ProcessRequest")
gopls_go_symbol_references(file, "ProcessRequest")
```

**Summary**: Always prefer composable tools that follow Unix Philosophy (`glob`, `grep`, `read`, `list`) over `bash` for file operations and code search. These tools respect `.ignore` configuration (see `.ignore` file for pattern organization), provide structured output, and compose efficiently. Reserve `bash` for builds, tests, git, and package management.

## Testing Guidelines

- All bug fixes and features require updated unit tests
- Test files follow the pattern `*_test.go` and are placed in the same package
- Run specific tests: `go test -run TestName ./package -v 2>&1 | cat`
- Run package tests: `go test -v ./src/internal/x509/certs 2>&1 | cat` or `go test -v ./src/internal/x509/chain 2>&1 | cat` or `go test -v ./src/logger 2>&1 | cat`
- Run all tests: `go test -v ./... 2>&1 | cat` or `make test`
- Run race detection: `go test -race ./... 2>&1 | cat` (recommended before merges)
- Run benchmarks: `go test -bench=. ./src/logger 2>&1 | cat` (for performance testing)
- **Piping to `cat`**: Use `2>&1 | cat` with test commands to ensure bash tool captures and displays all output
- Test certificate operations with both PEM and DER formats
- Test with real certificate data when possible (use test fixtures)
- Verify certificate chain resolution with various chain lengths
- Benchmark concurrent operations to verify performance under load (see `src/logger/benchmark_test.go` for examples)
