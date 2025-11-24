# DeepWiki MCP Server Instructions

## Purpose

The DeepWiki MCP server provides access to external repository documentation and API research for libraries and frameworks not in the current X509 certificate chain resolver codebase.

## When to Use DeepWiki

**Use DeepWiki for**:
- Researching external Go libraries and their APIs
- Understanding third-party dependencies (e.g., `github.com/spf13/cobra`, `github.com/valyala/bytebufferpool`)
- Learning about certificate/TLS libraries (e.g., `crypto/x509`, CFSSL)
- Finding usage examples from other repositories
- Understanding best practices for certificate handling

**Do NOT use DeepWiki for**:
- Code in this repository (use Gopls MCP or built-in tools instead)
- Standard library documentation (use `go doc` or official Go docs)
- General Go language questions (use language references)

## Available Tools

### deepwiki_read_wiki_structure(repoName)

**Purpose**: Get list of documentation topics available for a repository  
**Returns**: Table of contents with available documentation sections  
**When to use**: First step when exploring a new repository

**Examples**:
```
deepwiki_read_wiki_structure("spf13/cobra")
deepwiki_read_wiki_structure("cloudflare/cfssl")
deepwiki_read_wiki_structure("valyala/bytebufferpool")
```

**Output Example**:
```
Available documentation topics:
1. Getting Started
2. User Guide
3. Commands
4. Flags
5. Configuration
```

### deepwiki_read_wiki_contents(repoName)

**Purpose**: View full documentation about a repository  
**Returns**: Complete documentation content  
**When to use**: When you need comprehensive information about a library

**Examples**:
```
deepwiki_read_wiki_contents("spf13/cobra")
deepwiki_read_wiki_contents("cloudflare/cfssl")
```

**Output**: Full markdown documentation including:
- Installation instructions
- API reference
- Usage examples
- Best practices

### deepwiki_ask_question(repoName, question)

**Purpose**: Ask specific questions about a repository  
**Returns**: AI-generated answer based on repository documentation  
**When to use**: When you need specific information without reading entire docs

**Examples**:
```
deepwiki_ask_question("spf13/cobra", "How do I add custom validation to command arguments?")
deepwiki_ask_question("cloudflare/cfssl", "What is the recommended way to parse certificate bundles?")
deepwiki_ask_question("valyala/bytebufferpool", "How do I efficiently pool byte buffers for certificate data?")
```

## Supported URL Formats

DeepWiki accepts multiple repository identifier formats:

### 1. Full GitHub URLs
```
deepwiki_read_wiki_structure("https://github.com/spf13/cobra")
```

### 2. Owner/Repo Format (Recommended)
```
deepwiki_read_wiki_structure("spf13/cobra")
deepwiki_read_wiki_structure("cloudflare/cfssl")
```

### 3. Two-Word Format
```
deepwiki_read_wiki_structure("spf13 cobra")
```

### 4. Library Keywords
```
deepwiki_read_wiki_structure("cobra")
deepwiki_read_wiki_structure("cfssl")
```

**Best Practice**: Use `owner/repo` format for clarity and precision.

## Usage Guidelines

### 1. Start with Structure, Then Drill Down

```
GOOD workflow:
1. deepwiki_read_wiki_structure("spf13/cobra")
   → See what topics are available

2. deepwiki_ask_question("spf13/cobra", "How do I handle context in commands?")
   → Get specific answer

BAD workflow:
1. deepwiki_ask_question("spf13/cobra", "How does it work?")
   → Question too broad, unclear what you're looking for
```

### 2. Ask Specific Questions

```
❌ BAD: deepwiki_ask_question("cloudflare/cfssl", "How do I use this?")
✅ GOOD: deepwiki_ask_question("cloudflare/cfssl", "How do I parse a PEM certificate bundle?")

❌ BAD: deepwiki_ask_question("spf13/cobra", "Tell me about commands")
✅ GOOD: deepwiki_ask_question("spf13/cobra", "How do I add subcommands with their own flags?")
```

### 3. Cache Results - Don't Repeat Calls

```
❌ BAD: Calling same query multiple times in one session
deepwiki_read_wiki_contents("spf13/cobra")
... do some work ...
deepwiki_read_wiki_contents("spf13/cobra")  # Unnecessary repeat

✅ GOOD: Call once, use the information
deepwiki_read_wiki_contents("spf13/cobra")
... use the information for the rest of the session ...
```

### 4. Verify Information with Official Docs

DeepWiki provides AI-generated answers. For critical implementations:

```
1. Use DeepWiki to get initial understanding
2. Verify with official documentation or code examples
3. Test implementation with unit tests
```

## Common Use Cases for This Repository

### 1. Understanding Cobra CLI Patterns

**Scenario**: Adding new CLI flags or commands

```
# Understand flag validation
deepwiki_ask_question("spf13/cobra", "How do I add custom validation to command arguments?")

# Learn about command execution
deepwiki_ask_question("spf13/cobra", "How do I handle context cancellation in RunE function?")

# Understand flag types
deepwiki_ask_question("spf13/cobra", "What's the difference between Flags() and PersistentFlags()?")
```

### 2. Certificate Library Research

**Scenario**: Improving certificate parsing or validation

```
# Research CFSSL usage
deepwiki_read_wiki_structure("cloudflare/cfssl")
deepwiki_ask_question("cloudflare/cfssl", "How do I parse PKCS7 certificate bundles?")

# Understand certificate validation
deepwiki_ask_question("cloudflare/cfssl", "What's the recommended way to verify certificate chains?")
```

### 3. Memory Optimization

**Scenario**: Improving buffer pooling for certificate data

```
# Understand bytebufferpool
deepwiki_read_wiki_contents("valyala/bytebufferpool")
deepwiki_ask_question("valyala/bytebufferpool", "How do I efficiently pool buffers for varying sizes?")
```

### 4. MCP Server Implementation

**Scenario**: Adding new MCP tools, resources, or prompts

```
# Research MCP patterns
deepwiki_read_wiki_structure("mark3labs/mcp-go")
deepwiki_ask_question("mark3labs/mcp-go", "How do I implement dynamic resources in MCP?")
deepwiki_ask_question("mark3labs/mcp-go", "What's the difference between static and dynamic resources?")

# Understand prompt handling
deepwiki_ask_question("mark3labs/mcp-go", "How do I implement bidirectional AI communication in MCP sampling?")
```

### 5. Learning from Similar Projects

**Scenario**: Finding certificate chain resolver implementations

```
# Research existing implementations
deepwiki_read_wiki_structure("zakjan/cert-chain-resolver")
deepwiki_ask_question("zakjan/cert-chain-resolver", "How does it handle intermediate certificate fetching?")
```

## Connection Behavior

**Type**: Stateful (Long-lived)  
**Behavior**: Maintains persistent connection throughout session  
**Recovery**: N/A (no connection closure issues)
**Configuration**: MCP server configured in `opencode.json` with remote URL `https://mcp.deepwiki.com/sse`

Unlike Gopls MCP, DeepWiki connections are stable and don't require retry logic.

## Best Practices

### 1. Research Before Implementation

```
Workflow when adding new features:
1. Use DeepWiki to research external library capabilities
2. Use Gopls to understand current codebase
3. Use built-in tools (read/edit) to implement
4. Use bash to test
```

### 2. Combine with Other Tools

```
Example: Adding TLS connection timeout handling

1. deepwiki_ask_question("golang/go", "How do I set timeouts for TLS connections?")
   → Learn about context and http.Client configuration

2. gopls_go_search("FetchCertificate")
   → Find where HTTP requests are made

3. read("src/internal/x509/chain/chain.go")
   → Understand current implementation

4. edit(...)
   → Add timeout handling

5. bash("go test -v ./src/internal/x509/chain")
   → Test changes
```

### 3. Document Findings

When you discover important information via DeepWiki:

```
# Add comments in code referencing external library docs
// Using cobra's Args validation as recommended in spf13/cobra docs
Args: cobra.ExactArgs(1),

// CFSSL-style certificate bundle parsing
// Reference: cloudflare/cfssl certificate parsing patterns
```

## Common Pitfalls

### ❌ Using DeepWiki for Internal Code

```
BAD: deepwiki_ask_question("H0llyW00dzZ/tls-cert-chain-resolver", "How does FetchCertificate work?")
GOOD: gopls_go_search("FetchCertificate") → read the actual code
```

### ❌ Asking Questions Without Context

```
BAD: deepwiki_ask_question("spf13/cobra", "flags")
GOOD: deepwiki_ask_question("spf13/cobra", "How do I make flags required in cobra commands?")
```

### ❌ Repeating Identical Queries

```
BAD: Asking same question multiple times in one session
GOOD: Ask once, save the response, refer back to it
```

### ❌ Not Verifying AI Answers

```
BAD: Implementing code based solely on DeepWiki answer without testing
GOOD: Use DeepWiki → Verify with docs → Test implementation → Run tests
```

## Integration with Repository Workflow

### Typical Development Flow

```
1. Identify need for external library or pattern
   └→ Use DeepWiki to research

2. Understand current codebase implementation
   └→ Use Gopls MCP

3. Read relevant files
   └→ Use built-in read tool

4. Make changes
   └→ Use built-in edit tool

5. Verify compilation
   └→ Use gopls_go_diagnostics

6. Test changes
   └→ Use bash for go test
```

### Example: Adding JSON Output Feature

```
# Research JSON best practices
deepwiki_ask_question("golang/go", "What are best practices for JSON struct tags in Go?")

# Understand current CLI structure
gopls_go_file_context("src/cli/root.go")

# Read implementation
read("src/cli/root.go")

# Find all certificate output locations
gopls_go_symbol_references("src/cli/root.go", "outputCertificates")

# Implement changes
edit(...)

# Verify no errors
gopls_go_diagnostics(["src/cli/root.go"])

# Test
bash("go test -v ./src/cli")
```

## Repository-Specific DeepWiki Queries

### Dependencies in go.mod

Current external dependencies to research:
- `github.com/spf13/cobra` - CLI framework
- `github.com/cloudflare/cfssl` - Certificate utilities
- `github.com/valyala/bytebufferpool` - Memory pooling
- `github.com/mark3labs/mcp-go` v0.43.1 - MCP server implementation with enhanced bidirectional AI sampling support
- `github.com/modelcontextprotocol/go-sdk` v1.1.0 - Official MCP SDK for transport implementations
- `google.golang.org/adk` v0.2.0 - Google ADK integration for MCP transport creation
- `google.golang.org/genai` v1.36.0 - Google GenAI integration for AI model interactions
- `github.com/olekukonko/tablewriter` v1.1.1 - Enhanced markdown table formatting
- `golang.org/x/crypto` v0.45.0 - Supplementary cryptography libraries
- `golang/go` (standard library) - Review Go 1.25.4 crypto/tls and net/http updates

### Useful Queries for This Project

```
# Cobra CLI
deepwiki_ask_question("spf13/cobra", "How do I add custom help text for flags?")
deepwiki_ask_question("spf13/cobra", "How do I handle context cancellation in cobra commands?")

# CFSSL
deepwiki_ask_question("cloudflare/cfssl", "How do I parse DER-encoded certificates?")
deepwiki_ask_question("cloudflare/cfssl", "What's the difference between PEM and DER formats?")

# Buffer pooling
deepwiki_ask_question("valyala/bytebufferpool", "When should I use bytebufferpool vs sync.Pool?")

# Table formatting
deepwiki_ask_question("olekukonko/tablewriter", "How do I create markdown tables with emoji headers?")

# MCP server implementation
deepwiki_ask_question("mark3labs/mcp-go", "How do I implement MCP resources in a Go server?")
deepwiki_ask_question("mark3labs/mcp-go", "How do I add prompts to an MCP server?")

# Official MCP SDK
deepwiki_ask_question("modelcontextprotocol/go-sdk", "How do I implement MCP transports in Go?")
deepwiki_ask_question("modelcontextprotocol/go-sdk", "What's the difference between MCP SDK and mark3labs/mcp-go?")

# Google ADK integration
deepwiki_ask_question("google/adk", "How do I create MCP transports for ADK integration?")
deepwiki_ask_question("google/adk", "What are the transport types supported by ADK?")
deepwiki_ask_question("google/adk", "How do I use mcptoolset with a custom transport?")
```

## Troubleshooting

### Repository Not Found

```
Error: Repository "xyz" not found

Solutions:
1. Verify repository name spelling
2. Use full owner/repo format: "owner/repo"
3. Check if repository is public (DeepWiki requires public repos)
```

### Question Returns Generic Answer

```
Problem: Answer too generic or not specific to your use case

Solutions:
1. Make question more specific with exact API names
2. Include context: "In the context of [feature], how do I..."
3. Try deepwiki_read_wiki_contents first to understand available APIs
```

### Documentation Outdated

```
Problem: DeepWiki returns outdated information

Solutions:
1. Verify with official repository documentation
2. Check repository releases for API changes
3. Test implementation to confirm current behavior
```

## Summary

1. **Use DeepWiki for external libraries only** - not internal code
2. **Start with structure** (`read_wiki_structure`) before drilling down
3. **Ask specific questions** - include API names, feature context
4. **Cache results** - don't repeat identical queries
5. **Verify answers** - test implementations, check official docs
6. **Combine with other tools** - DeepWiki → Gopls → Read → Edit → Test
7. **Document findings** - add comments referencing external library patterns

**Key Dependencies to Research**:
- `spf13/cobra` - For CLI improvements
- `cloudflare/cfssl` - For certificate handling
- `valyala/bytebufferpool` - For memory optimization
- `mark3labs/mcp-go` - For MCP server features
- `modelcontextprotocol/go-sdk` - For official MCP transport implementations
- `google.golang.org/adk` - For Google ADK integration
- `google.golang.org/genai` - For Google GenAI integration
- `golang/go` - For standard library best practices
