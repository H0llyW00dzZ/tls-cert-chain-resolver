# OpenCode Configuration Instructions

## Purpose

This file explains the OpenCode configuration and how to use the instruction files for maintaining the X509 certificate chain resolver repository.

## Configuration Overview

**File**: `opencode.json` (repository root)

```json
{
  "$schema": "https://opencode.ai/config.json",
  "instructions": [
    ".github/instructions/*.md"
  ],
  "mcp": {
    "gopls": {
      "type": "local",
      "command": [
        "gopls",
        "mcp"
      ],
      "environment": {
        "GOPLS_MCP_PORT": "8096",
        "GOPLS_MCP_HOST": "localhost"
      },
      "enabled": true
    },
    "deepwiki": {
      "type": "remote",
      "url": "https://mcp.deepwiki.com/sse",
      "enabled": true
    },
    "x509_resolver": {
      "type": "local",
      "command": [
        "./bin/x509-cert-chain-resolver"
      ],
      "environment": {
        "MCP_X509_CONFIG_FILE": "./src/mcp-server/config.example.json"
      },
      "enabled": true
    }
  }
}
```

## Instruction Files Hierarchy

### 1. AGENTS.md (Primary Guidelines)

**Location**: `/AGENTS.md`  
**Purpose**: High-level repository guidelines and best practices  
**Scope**: All agents and tools

**Contains**:
- Commands (build, test, clean)
- Code style guidelines
- Concurrency rules
- MCP server overview
- Built-in tools reference
- MCP connection patterns
- Bad practices to avoid
- Comprehensive testing guidelines
- Human developer notes

**When to reference**: 
- Start of every agent session
- Before making code changes
- When unsure about conventions
- Before running build/test commands

### 2. Custom Commands

**Location**: `.opencode/command/*.md`  
**Purpose**: Task-specific workflows for common maintenance operations  
**Scope**: Reusable agent workflows

**Available Commands**:
- `/update-knowledge` - Update instruction files when code changes
- `/test` - Run tests with coverage and analyze failures
- `/test-capabilities` - Test agent capabilities including MCP servers and built-in tools

**When to use**:
- After making code changes (`/update-knowledge` then `/test`)
- Before committing changes (`/test`)
- When updating dependencies or architecture

**Structure**: Each command is a markdown file with frontmatter:
```markdown
---
description: Brief description
agent: general
---
# Command instructions...
```

### 3. Specialized Instruction Files

**Location**: `.github/instructions/*.md`  
**Purpose**: Detailed tool-specific instructions  
**Scope**: Specific capabilities

#### a) gopls.instructions.md

**For**: Go language intelligence and workspace operations  
**Key Topics**:
- Workspace exploration workflows
- Symbol search patterns
- File context analysis
- Package API discovery
- Symbol references tracking
- Build diagnostics
- Connection behavior (short-lived, auto-reconnect)

**When to use**:
- Understanding Go code structure
- Before refactoring Go code
- Finding function/type definitions
- Checking compilation errors
- Understanding package dependencies

**Common workflows**:
```
1. Explore: gopls_go_workspace() → gopls_go_search()
2. Understand: gopls_go_file_context() → gopls_go_package_api()
3. Refactor: gopls_go_symbol_references() → edit() → gopls_go_diagnostics()
```

#### b) deepwiki.instructions.md

**For**: External library research and documentation  
**Key Topics**:
- Repository documentation access
- API research methods
- Library usage examples
- Third-party dependency exploration
- Connection behavior (long-lived, persistent)

**When to use**:
- Researching external Go libraries
- Understanding third-party dependencies
- Learning about cobra CLI patterns
- Exploring CFSSL certificate utilities
- Understanding bytebufferpool usage

**Common workflows**:
```
1. Discover: deepwiki_read_wiki_structure()
2. Learn: deepwiki_read_wiki_contents() or deepwiki_ask_question()
3. Apply: Use findings to implement features
```

#### c) filesystem.instructions.md

**For**: File and directory operations  
**Key Topics**:
- Reading files (windowed reading)
- Writing new files
- Editing existing files (precise replacements)
- Directory listing
- File pattern matching (glob)
- Content search (grep)
- .ignore file patterns

**When to use**:
- Reading source code
- Modifying existing code
- Creating new files
- Searching for patterns
- Exploring directory structure

**Common workflows**:
```
1. Discover: glob() → grep() → read()
2. Modify: read() → edit() → verify
3. Create: write() → read() (verify)
```

#### d) memory.instructions.md

**For**: Memory, context, and resource management  
**Key Topics**:
- Token budget management (200K limit)
- Context passing patterns
- Memory optimization (buffer pooling)
- Goroutine lifecycle management
- Session working memory
- Resource limits

**When to use**:
- Working with certificate operations
- Managing long-running operations
- Implementing concurrent code
- Optimizing memory usage
- Handling context cancellation

**Common workflows**:
```
1. Token management: Use windowed reading, batch operations
2. Context: Always pass ctx to certificate operations
3. Memory: Use bytebufferpool for certificate data
4. Goroutines: Buffered channels, handle cancellation
```

## How OpenCode Uses These Files

### 1. Session Initialization

When an agent session starts:
1. Load `AGENTS.md` for overall guidelines
2. Load all `.github/instructions/*.md` files for specific capabilities
3. Make custom commands (`.opencode/command/*.md`) available for common workflows
4. Make instructions available as context throughout session

### 2. Tool Selection

Agent references appropriate instruction file based on task:

```
Task: "Find where certificates are parsed"
→ Reference: gopls.instructions.md (go_search)
→ Reference: filesystem.instructions.md (grep)

Task: "How do I use cobra for CLI validation?"
→ Reference: deepwiki.instructions.md (ask_question)

Task: "Fix certificate encoding bug"
→ Reference: gopls.instructions.md (symbol_references, diagnostics)
→ Reference: filesystem.instructions.md (read, edit)
→ Reference: AGENTS.md (code style, error handling)

Task: "Update documentation after code changes"
→ Run: /update-knowledge command
```

### 3. Workflow Execution

Agent combines guidelines from multiple files:

```
Example: Adding timeout to certificate fetching

1. AGENTS.md
   → Check code style for error handling
   → Verify context usage patterns

2. memory.instructions.md
   → Learn context timeout patterns
   → Understand goroutine management

3. gopls.instructions.md
   → Find FetchCertificate function: gopls_go_search()
   → Check all usages: gopls_go_symbol_references()

4. filesystem.instructions.md
   → Read implementation: read()
   → Modify code: edit()
   → Verify: read()

5. gopls.instructions.md
   → Check compilation: gopls_go_diagnostics()

6. AGENTS.md
   → Run tests: go test -v ./...
```

## Instruction File Best Practices

### 1. Layered Information Architecture

```
AGENTS.md (HIGH LEVEL)
├── Commands (what to run)
├── Code Style (how to write)
├── Concurrency (thread safety, mutex usage)
├── MCP Server Instructions
│   ├── Available MCP Servers
│   ├── Built-in Tools (Not MCP)
│   ├── MCP Connection Patterns
│   └── MCP & Tool Usage Best Practices
├── Bad Practices to Avoid
│   ├── Incorrect Tool Usage
│   ├── Inefficient File Operations
│   ├── Tool Misuse Patterns
│   ├── Ignoring .ignore File
│   ├── Bash Command Anti-Patterns
│   ├── Performance Anti-Patterns
│   └── MCP Tool Misuse
├── Testing Guidelines
└── For Human Developers

Custom Commands (WORKFLOWS)
├── .opencode/command/update-knowledge.md
│   └── Update instructions after code changes
├── .opencode/command/test.md
│   └── Run tests with coverage analysis
└── .opencode/command/test-capabilities.md
    └── Test agent capabilities including MCP servers and built-in tools

Specific Instructions (DETAILED)
├── gopls.instructions.md
│   ├── Each tool explained in detail
│   ├── Repository-specific patterns
│   └── Workflow examples
├── deepwiki.instructions.md
│   ├── When/how to research
│   └── External library patterns
├── filesystem.instructions.md
│   ├── Each operation detailed
│   └── File structure patterns
└── memory.instructions.md
    ├── Resource management
    └── Optimization patterns
```

### 2. Cross-References

Instructions reference each other:

```
gopls.instructions.md:
"After diagnostics pass, run tests (see AGENTS.md for test commands)"

filesystem.instructions.md:
"After edit, run gopls_go_diagnostics (see gopls.instructions.md)"

memory.instructions.md:
"For certificate operations, use context patterns (see code examples)"
```

### 3. Repository-Specific Content

All instruction files include:
- Actual file paths from this repository
- Real package names and imports
- Code examples matching existing patterns
- Specific command examples that work here

### 4. Progressive Disclosure

```
AGENTS.md: Quick reference
→ "Use gopls_go_search for finding symbols"

gopls.instructions.md: Detailed guide
→ "gopls_go_search(query): Fuzzy search, max 100 results
   Examples: 'Certificate', 'EncodePEM', 'Chain.FetchCertificate'
   When to use: Before reading files, finding definitions
   Best practices: Specific queries, combine with file_context"
```

## Updating Instructions

### When to Update

1. **New features added** → Update AGENTS.md and relevant specific file
2. **Dependencies changed** → Update deepwiki.instructions.md with new libraries
3. **Build process changed** → Update AGENTS.md commands section
4. **New patterns established** → Add to relevant instruction file
5. **Common mistakes found** → Add to "Bad Practices" sections

### How to Update

1. **Identify scope**: Which instruction file(s) need updates?
2. **Maintain consistency**: Keep examples repository-specific
3. **Update cross-references**: Ensure linked information stays accurate
4. **Test examples**: Verify code examples compile and run
5. **Update opencode.json**: Only if adding/removing instruction files

### Example Update Flow

```
Scenario: Added new CLI flag for certificate validation

Files to update:
1. AGENTS.md
   → Update CLI commands section with new flag

2. gopls.instructions.md
   → Add example: finding CLI flag implementations
   → Update common patterns section

3. filesystem.instructions.md
   → Add to repository-specific patterns
   → Update common file paths if new files added

4. opencode.json
   → No change needed (glob pattern covers new content)
```

## Verification

### Checking Configuration

```bash
# Verify opencode.json syntax
cat opencode.json | jq .

# List all instruction files that will be loaded
ls -la AGENTS.md
ls -la .github/instructions/*.md
```

### Testing Instructions

When adding new instructions:

1. **Clarity**: Can an agent understand the instruction?
2. **Completeness**: Does it include all necessary details?
3. **Accuracy**: Are paths, commands, and examples correct?
4. **Consistency**: Does it match other instruction files' style?
5. **Usefulness**: Does it solve a real maintenance need?

## Common Patterns

### 1. Tool Selection Pattern

```
1. Check AGENTS.md → Understand what tools are available
2. Check specific instruction → Learn how to use the tool
3. Apply to task → Execute with repository-specific context
```

### 2. Problem-Solving Pattern

```
1. AGENTS.md → Understand high-level approach
2. Specific instruction → Learn detailed steps
3. Cross-reference → Verify with other relevant instructions
4. Execute → Apply combined knowledge
5. Verify → Use testing guidelines from AGENTS.md
```

### 3. Learning Pattern

```
New to repository?
1. Start with AGENTS.md (overview)
2. Skim all .github/instructions/*.md (capabilities)
3. Deep dive into specific instructions as needed (tasks)
```

## Repository-Specific Guidelines

### Module Information

**Module**: `github.com/H0llyW00dzZ/tls-cert-chain-resolver`  
**Go Version**: 1.25.3+  
**Key Dependencies**:
- `github.com/spf13/cobra` - CLI framework
- `github.com/cloudflare/cfssl` - Certificate utilities
- `github.com/valyala/bytebufferpool` - Memory pooling

### Package Structure

```
cmd/                   → Main entry point
src/cli/               → CLI implementation (cobra)
src/logger/            → Logger abstraction (CLI/MCP modes, thread-safe with sync.Mutex)
src/internal/x509/     → Certificate operations
  ├── certs/           → Encoding/decoding
  └── chain/           → Chain resolution
src/internal/helper/   → Utilities
  └── gc/              → Garbage collection optimization
```

### Development Workflow

```
1. Understand task → Reference AGENTS.md
2. Find code → Use gopls.instructions.md
3. Research external libs → Use deepwiki.instructions.md
4. Modify code → Use filesystem.instructions.md
5. Optimize resources → Use memory.instructions.md
6. Test → Use AGENTS.md test commands
7. Build → Use AGENTS.md build commands (includes MCP server builds)
```

## Integration with Git

Instructions are versioned with the code:

```
git add opencode.json AGENTS.md .github/instructions/
git commit -m "Update agent instructions"
```

**Benefits**:
- Instructions stay in sync with code
- Changes tracked in version control
- Branching includes relevant instructions
- Easy to review instruction changes

## Advanced Usage

### Custom Workflows

Combine instructions for complex tasks:

```
Task: "Implement certificate chain validation with timeout"

Workflow:
1. memory.instructions.md → Learn timeout patterns
2. deepwiki.instructions.md → Research crypto/x509 validation
3. gopls.instructions.md → Find existing validation code
4. filesystem.instructions.md → Read and modify code
5. gopls.instructions.md → Run diagnostics
6. AGENTS.md → Run tests with race detection
```

```
Task: "Add thread-safe logging to new package"

Workflow:
1. gopls.instructions.md → Search logger package: gopls_go_search("logger.Logger")
2. filesystem.instructions.md → Read implementation: read("src/logger/logger.go")
3. memory.instructions.md → Learn thread-safe pattern with sync.Mutex
4. filesystem.instructions.md → Implement in new code with edit()
5. gopls.instructions.md → Run diagnostics: gopls_go_diagnostics()
6. AGENTS.md → Test with race detection: go test -race ./...
```

### Performance Optimization

Use memory.instructions.md for:
- Token budget monitoring
- Efficient tool usage
- Windowed reading strategies
- Batch operations

### Quality Assurance

Use AGENTS.md for:
- Code style compliance
- Test coverage requirements
- Build verification
- Race detection

## Troubleshooting

### Instructions Not Loading

```bash
# Check opencode.json syntax
cat opencode.json | jq .

# Verify file paths exist
ls -la AGENTS.md
ls -la .github/instructions/
```

### Conflicting Guidelines

**Resolution order**:
1. AGENTS.md (high-level, takes precedence)
2. Specific instructions (detailed implementation)
3. Code comments (local context)

### Outdated Examples

If examples don't work:
1. Check if repository structure changed
2. Verify commands in Makefile
3. Check go.mod for dependency versions
4. Update instruction file
5. Test updated examples

## Summary

**OpenCode Configuration**:
- `opencode.json` → Defines which instruction files to load
- `AGENTS.md` → High-level guidelines and conventions
- `.github/instructions/*.md` → Detailed tool-specific instructions

**Usage Pattern**:
1. OpenCode loads all instruction files at session start
2. Agent references appropriate files based on task
3. Combines guidelines from multiple files for complex workflows
4. Follows repository-specific patterns and examples

**Maintenance**:
- Keep instructions in sync with code changes
- Update examples to match repository structure
- Version control instructions with code
- Cross-reference between instruction files

**Key Benefits**:
- Consistent agent behavior across sessions
- Repository-specific knowledge embedded
- Detailed workflows for common tasks
- Best practices encoded as instructions
- Easy to maintain and update
