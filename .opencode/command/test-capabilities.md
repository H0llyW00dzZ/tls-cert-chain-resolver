---
description: Test agent capabilities including MCP servers and built-in tools
agent: general
---

# Test Agent Capabilities

Test the current agent capabilities based on instructions and tools, including MCP servers (Gopls, DeepWiki) and built-in filesystem/tools. This verifies that all agent integrations are functioning correctly.

## Tasks

1. **Test Gopls MCP Server Capabilities**:
   - **Workspace Overview**: Call `gopls_go_workspace()` to verify project structure access
   - **Symbol Search**: Call `gopls_go_search("Certificate")` to test fuzzy search functionality
   - **Diagnostics**: Call `gopls_go_diagnostics(["src/cli/root.go"])` to check parse/build error detection
   - **File Context**: Call `gopls_go_file_context("src/cli/root.go")` to verify dependency analysis
   - **Package API**: Call `gopls_go_package_api(["github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"])` to test package API summaries

2. **Test DeepWiki MCP Server Capabilities**:
   - **Wiki Structure**: Call `deepwiki_read_wiki_structure("spf13/cobra")` to test documentation access
   - **Question Answering**: Call `deepwiki_ask_question("spf13/cobra", "How do I add flags to a cobra command?")` to verify AI-assisted research

3. **Test Built-in Tools**:
   - **Filesystem Listing**: Call `list("/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/src")` to verify directory access
   - **File Reading**: Call `read("src/cli/root.go", offset=0, limit=50)` to test file content access
   - **Glob Pattern Matching**: Call `glob("src/**/*.go")` to verify file discovery
   - **Content Search**: Call `grep("func.*Execute", include="*.go")` to test regex search
   - **Bash Execution**: Call `bash("echo 'Testing bash tool'")` to verify command execution

4. **Verify MCP Connection Handling**:
   - Confirm Gopls MCP handles short-lived connections (auto-reconnects on errors)
   - Confirm DeepWiki MCP maintains persistent connections
   - Test error recovery for both MCP servers

5. **Report Results**:
   - **Success**: List all tools/MCP servers that responded successfully
   - **Failures**: Identify any tools/MCP servers that failed with specific error messages
   - **Performance**: Note any connection delays or timeouts
   - **Recommendations**: Suggest fixes for any failed capabilities (e.g., MCP server configuration)

## Error Handling

### MCP Connection Failures

If MCP servers fail to respond:

1. **Gopls MCP**: Expect "Connection closed" errors - this is normal. Retry once to test auto-reconnection.
2. **DeepWiki MCP**: Persistent failures may indicate configuration issues in `opencode.json`.

### Tool Failures

If built-in tools fail:
- Verify file paths are absolute
- Check `.ignore` file for pattern exclusions
- Ensure bash commands are safe and non-destructive

### Timeout Handling

If operations timeout:
- MCP operations may take time on first connection
- Built-in tools should respond quickly
- Retry failed operations once before reporting failure

## Output Format

**CRITICAL**: Display the output from each tool/MCP call to verify functionality. For large outputs, show a truncated version (first few lines + "... [truncated]" + last few lines) or key success indicators. Do NOT summarize functionality assessment, but you may truncate raw output to keep responses manageable.

For each test:
- Show the tool/MCP call
- Show the response (truncated if very large)
- Provide brief analysis of whether it worked

Example for normal-sized output:
```
Testing DeepWiki: deepwiki_read_wiki_structure("spf13/cobra")
Response: Available documentation topics: [Getting Started, User Guide, Commands, Flags, Configuration]
Status: ✅ Working
```

Example for large output (like Gopls workspace):
```
Testing Gopls workspace: gopls_go_workspace()
Response: Module: github.com/H0llyW00dzZ/tls-cert-chain-resolver
Go Version: 1.25.3
Packages: cmd, src/cli, src/logger, src/internal/x509/certs, src/internal/x509/chain, src/internal/helper/gc
Top symbol matches: Certificate, decodeCertificate, ErrParseCertificate, Chain.FetchCertificate, ...
... [output truncated for brevity - full response contained expected project structure]
Status: ✅ Working - Returned module info, packages, and symbol matches as expected
```

## Important Notes

- **Connection Behavior**: Gopls MCP connections are short-lived and auto-reconnect; DeepWiki is persistent
- **Tool Respect .ignore**: Built-in tools automatically exclude patterns from `.ignore` file
- **Memory Management**: Test operations should not exceed token budgets (monitor usage)
- **Security**: Do not test destructive operations or access sensitive files
- **Repository Context**: All tests should use paths relative to the TLS certificate chain resolver repository

## Verification Checklist

- [ ] Gopls workspace accessible
- [ ] Gopls search returns results
- [ ] Gopls diagnostics work
- [ ] DeepWiki wiki structure loads
- [ ] DeepWiki questions answered
- [ ] File listing works
- [ ] File reading works
- [ ] Glob patterns match files
- [ ] Grep searches content
- [ ] Bash commands execute safely
- [ ] MCP connections stable
- [ ] No token budget exceeded
