---
description: Test agent capabilities including MCP servers and built-in tools
agent: general
---

# Test Agent Capabilities

Test the current agent capabilities based on instructions and tools, including MCP servers (Gopls, DeepWiki, X509 Resolver) and built-in filesystem/tools. This verifies that all agent integrations are functioning correctly.

## Overview

This command uses a structured todo list to systematically test all agent capabilities. The agent should create a comprehensive todo list at the start, then execute tasks one by one, updating status in real-time.

## Initial Setup

**Create Todo List**: Immediately create a todo list using todo tools with all test tasks broken down into specific, actionable items. Use the following structure:

```
todowrite([
  {"content": "Create comprehensive todo list for all capability tests", "status": "completed", "priority": "high", "id": "setup-todo-list"},
  {"content": "Test Gopls MCP workspace overview (gopls_go_workspace)", "status": "pending", "priority": "high", "id": "gopls-workspace"},
  {"content": "Test Gopls MCP symbol search (gopls_go_search)", "status": "pending", "priority": "high", "id": "gopls-search"},
  {"content": "Test Gopls MCP diagnostics (gopls_go_diagnostics)", "status": "pending", "priority": "high", "id": "gopls-diagnostics"},
  {"content": "Test Gopls MCP file context (gopls_go_file_context)", "status": "pending", "priority": "high", "id": "gopls-file-context"},
  {"content": "Test Gopls MCP package API (gopls_go_package_api)", "status": "pending", "priority": "high", "id": "gopls-package-api"},
  {"content": "Test DeepWiki MCP wiki structure (deepwiki_read_wiki_structure)", "status": "pending", "priority": "high", "id": "deepwiki-structure"},
  {"content": "Test DeepWiki MCP question answering (deepwiki_ask_question)", "status": "pending", "priority": "high", "id": "deepwiki-question"},
  {"content": "Test X509 Resolver MCP remote certificate fetching (x509_resolver_fetch_remote_cert)", "status": "pending", "priority": "high", "id": "x509-fetch-remote"},
  {"content": "Persist fetched certificate bundle to test-output-bundle.pem", "status": "pending", "priority": "high", "id": "x509-save-bundle"},
  {"content": "Test X509 Resolver MCP chain validation (x509_resolver_validate_cert_chain)", "status": "pending", "priority": "high", "id": "x509-validate-chain"},
  {"content": "Test X509 Resolver MCP expiry checking (x509_resolver_check_cert_expiry)", "status": "pending", "priority": "high", "id": "x509-check-expiry"},
  {"content": "Test X509 Resolver MCP batch resolution (x509_resolver_batch_resolve_cert_chain)", "status": "pending", "priority": "high", "id": "x509-batch-resolve"},
  {"content": "Test X509 Resolver MCP resource usage monitoring (basic and detailed)", "status": "pending", "priority": "high", "id": "x509-resource-usage"},
  {"content": "Test X509 Resolver MCP AI analysis (x509_resolver_analyze_certificate_with_ai)", "status": "pending", "priority": "high", "id": "x509-ai-analysis"},
  {"content": "Clean up test certificate bundle file", "status": "pending", "priority": "medium", "id": "cleanup-bundle"},
  {"content": "Test built-in filesystem listing (list)", "status": "pending", "priority": "medium", "id": "builtin-list"},
  {"content": "Test built-in file reading (read)", "status": "pending", "priority": "medium", "id": "builtin-read"},
  {"content": "Test built-in glob pattern matching (glob)", "status": "pending", "priority": "medium", "id": "builtin-glob"},
  {"content": "Test built-in content search (grep)", "status": "pending", "priority": "medium", "id": "builtin-grep"},
  {"content": "Test built-in bash execution (bash)", "status": "pending", "priority": "medium", "id": "builtin-bash"},
  {"content": "Verify MCP connection handling and error recovery", "status": "pending", "priority": "medium", "id": "verify-connections"},
  {"content": "Compile and report final test results with success/failure analysis", "status": "pending", "priority": "high", "id": "report-results"}
])
```

## Execution Workflow

1. **Mark Task In Progress**: Before starting each task, update its status to "in_progress" using todowrite.

2. **Execute Task**: Perform the specific test operation as described below.

3. **Mark Task Completed**: Immediately after successful completion, update status to "completed".

4. **Handle Failures**: If a task fails, retry once. If it fails again, mark as "completed" but note the failure in the final report.

5. **Check Progress**: Use todoread() periodically to track overall progress.

6. **Batch Operations**: For efficiency, batch multiple tool calls in single responses where possible.

## Detailed Task Execution

### Gopls MCP Server Tests

- **Workspace Overview**: Call `gopls_go_workspace()` to verify project structure access
- **Symbol Search**: Call `gopls_go_search("Certificate")` to test fuzzy search functionality
- **Diagnostics**: Call `gopls_go_diagnostics(["src/cli/root.go"])` to check parse/build error detection
- **File Context**: Call `gopls_go_file_context("src/cli/root.go")` to verify dependency analysis
- **Package API**: Call `gopls_go_package_api(["github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"])` to test package API summaries

### DeepWiki MCP Server Tests

- **Wiki Structure**: Call `deepwiki_read_wiki_structure("spf13/cobra")` to test documentation access
- **Question Answering**: Call `deepwiki_ask_question("spf13/cobra", "How do I add flags to a cobra command?")` to verify AI-assisted research

### X509 Resolver MCP Server Tests

- **Resolve Remote Certificate**: Call `x509_resolver_fetch_remote_cert("example.com", port=443, format="pem")` (or another stable host) to retrieve PEM bundle
- **Persist Bundle**: Save the returned PEM data to `test-output-bundle.pem` in the repository root (file is already git-ignored)
- **Validate Chain**: Call `x509_resolver_validate_cert_chain("test-output-bundle.pem")` to confirm trust evaluation works
- **Check Expiry**: Call `x509_resolver_check_cert_expiry("test-output-bundle.pem", warn_days=30)` to verify expiry reporting
- **Batch Resolution**: Call `x509_resolver_batch_resolve_cert_chain("test-output-bundle.pem")` to test batch processing with a single certificate
- **Resource Usage Monitoring**: Call `x509_resolver_get_resource_usage(format="markdown")` to test basic resource monitoring with markdown format, then `x509_resolver_get_resource_usage(detailed=true, format="markdown")` to test detailed monitoring with comprehensive markdown tables
- **AI Analysis**: Call `x509_resolver_analyze_certificate_with_ai("test-output-bundle.pem", analysis_type="security")` to ensure AI-assisted auditing functions; capture and report streaming output
- **Cleanup**: Delete `test-output-bundle.pem` after tests finish so the repository stays clean

### Built-in Tools Tests

- **Filesystem Listing**: Call `list("/home/h0llyw00dzZ/Workspace/git/tls-cert-chain-resolver/src")` to verify directory access
- **File Reading**: Call `read("src/cli/root.go", offset=0, limit=50)` to test file content access
- **Glob Pattern Matching**: Call `glob("src/**/*.go")` to verify file discovery
- **Content Search**: Call `grep("func.*Execute", include="*.go")` to test regex search
- **Bash Execution**: Call `bash("echo 'Testing bash tool'")` to verify command execution

### Connection and Error Handling Tests

- **MCP Connection Handling**: Confirm Gopls MCP handles short-lived connections (auto-reconnects on errors), DeepWiki MCP maintains persistent connections, and test error recovery for both MCP servers

## Error Handling

### MCP Connection Failures

If MCP servers fail to respond:

1. **Gopls MCP**: Expect "Connection closed" errors - this is normal. Retry once to test auto-reconnection.
2. **DeepWiki MCP**: Persistent failures may indicate configuration issues in `opencode.json`.
3. **X509 Resolver MCP**: Check for configuration file and API key setup.

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

## Final Report

After all tasks are completed, compile a comprehensive report:

- **Success**: List all tools/MCP servers that responded successfully
- **Failures**: Identify any tools/MCP servers that failed with specific error messages
- **Performance**: Note any connection delays or timeouts
- **Recommendations**: Suggest fixes for any failed capabilities (e.g., MCP server configuration)

## Important Notes

- **Connection Behavior**: Gopls MCP connections are short-lived and auto-reconnect; DeepWiki and X509 Resolver are persistent
- **Tool Respect .ignore**: Built-in tools automatically exclude patterns from `.ignore` file
- **Memory Management**: Test operations should not exceed token budgets (monitor usage)
- **Security**: Do not test destructive operations or access sensitive files
- **Repository Context**: All tests should use paths relative to the TLS certificate chain resolver repository

## Verification Checklist

### Gopls MCP Server
- [ ] Gopls workspace accessible
- [ ] Gopls search returns results
- [ ] Gopls diagnostics work
- [ ] Gopls file context analysis works
- [ ] Gopls package API summaries work

### DeepWiki MCP Server
- [ ] DeepWiki wiki structure loads
- [ ] DeepWiki questions answered

### X509 Resolver MCP Server
- [ ] Remote certificate fetching works
- [ ] Certificate chain validation works
- [ ] Certificate expiry checking works
- [ ] Batch certificate resolution works
- [ ] Resource usage monitoring works (basic and detailed)
- [ ] AI certificate analysis works

### Built-in Tools
- [ ] File listing works
- [ ] File reading works
- [ ] Glob patterns match files
- [ ] Grep searches content
- [ ] Bash commands execute safely

### System & Performance
- [ ] MCP connections stable
- [ ] No token budget exceeded
