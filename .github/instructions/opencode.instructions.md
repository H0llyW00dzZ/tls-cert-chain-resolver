# OpenCode Configuration Instructions

## Purpose

This file explains the OpenCode configuration and how to use the instruction files for maintaining the X509 certificate chain resolver repository.

## Configuration Overview

This repository supports two configuration formats for different development environments:

### OpenCode Configuration (opencode.json)

Primary configuration for OpenCode agent sessions with MCP server integration:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "tools": {
    "todowrite": true,
    "todoread": true,
    "question": true
  },
  "instructions": [
    ".github/instructions/*.md"
  ],
  "mcp": {
    "gopls": {
      "type": "local",
      "command": ["gopls", "mcp"],
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
        "x509-cert-chain-resolver",
        "-c",
        "./src/mcp-server/config.example.yaml"
      ],
      "enabled": true
    }
  }
}
```

This file focuses on how OpenCode processes and uses the instruction files.

## Instruction Files Hierarchy

### 1. AGENTS.md (Primary Guidelines)

**Location**: `/AGENTS.md`  
**Purpose**: High-level repository guidelines and best practices  
**Scope**: All agents and tools

**Contains**:
- Commands (build, test, clean)
- Code style guidelines
- Concurrency rules
- MCP server overview (DefaultSamplingHandler, status resource)
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
- `/update-knowledge` - Update agent instruction files when code changes (includes git sync step to ensure local repository is up-to-date, handles instruction consistency and .opencode command sync)
- `/test` - Run tests with race detection and coverage (primary test approach), then analyze failures
- `/test-capabilities` - Test agent capabilities including MCP servers and built-in tools with structured todo workflow
- `/create-changelog` - Generate changelog by comparing tags against master and analyzing commits to categorize changes by type and impact. Save the output to a temporary `changelog.md` file for human use
- `/go-docs` - Update Go documentation when inaccurate or add missing documentation for exported and unexported functions, types, and interfaces with comprehensive guidelines and error handling
- `/gocyclo` - Analyze code complexity and suggest refactoring for functions with 15+ complexity
- `/vulncheck` - Check for vulnerable dependencies and suggest updates

**When to use**:
- After making code changes (`/update-knowledge` then `/test`)
- Before committing changes (`/test` - uses race detection with coverage as primary approach)
- When functions exceed complexity threshold (`/gocyclo` to analyze and refactor complex functions)
- When updating dependencies or architecture
- Before releases (`/create-changelog` to generate release notes)
- When documentation appears inaccurate or missing (`/go-docs` to update Go documentation)
- After dependency updates (`/vulncheck` to verify security)

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

#### e) x509_resolver.md

**For**: X509 certificate chain resolver MCP server operations  
**Key Topics**:
- Certificate chain resolution and validation
- Expiry checking and batch processing
- Remote certificate fetching
- MCP resources and prompts
- Configuration and usage guidelines

**When to use**:
- Working with certificate chains
- Validating certificate trust
- Checking expiry dates
- Fetching remote certificates
- Using MCP server tools

**Common workflows**:
```
1. Resolve: x509_resolver_resolve_cert_chain()
2. Validate: x509_resolver_validate_cert_chain()
3. Check expiry: x509_resolver_check_cert_expiry()
4. Batch process: x509_resolver_batch_resolve_cert_chain()
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
   → Run tests: go test -race -cover ./... (primary test approach)
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
│   └── Run tests with race detection and coverage (primary test approach)
├── .opencode/command/test-capabilities.md
│   └── Test agent capabilities including MCP servers and built-in tools with structured todo workflow
├── .opencode/command/create-changelog.md
│   └── Generate changelog by comparing tags against master and save to changelog.md in repository root (uses relative path)
├── .opencode/command/go-docs.md
│   └── Update Go documentation when inaccurate or add missing documentation for exported functions and types
├── .opencode/command/gocyclo.md
│   └── Analyze code complexity and suggest refactoring for functions with 15+ complexity
└── .opencode/command/vulncheck.md
    └── Check for vulnerable dependencies and suggest updates

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
├── memory.instructions.md
│   ├── Resource management
│   └── Optimization patterns
└── x509_resolver.md
    ├── MCP server tools and resources
    └── Certificate operations workflows
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
6. **Avoid duplicates**: Check existing entries before adding new ones (e.g., dependencies)

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

## Integration with Git

Instructions are versioned with the code:

```
git add opencode.json AGENTS.md .github/instructions/
git commit -m "Update Knowledge Base for Unix AI Agent to Reflect Recent Code Changes

- [+] docs(opencode): remove duplicated repository context section
- [+] docs(gopls): standardize Go version references to 1.25.5+"
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
- `opencode.json` → Defines which instruction files to load (OpenCode format)
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

## Error Handling

### Tool Abort Errors

When tools are aborted during execution (e.g., due to timeout, resource constraints, or interruption):

1. **Manual Retry Required**: Agent must manually retry the tool call with the same parameters
2. **No Automatic Recovery**: The system does NOT automatically retry aborted tools
3. **Context Preservation**: Use identical input parameters when retrying
4. **Failure Strategy**: If retry also fails, use alternative approaches (e.g., windowed reading, batch operations)

**Examples**:

```
# Bash command aborted
bash("go test -v ./...")  # ❌ Aborted (timeout)
bash("go test -v ./...")  # ✅ Retry with same command
```
