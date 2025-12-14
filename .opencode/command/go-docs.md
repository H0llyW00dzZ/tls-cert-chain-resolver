---
description: Update Go documentation when inaccurate or add missing documentation
agent: general
---

# Go Documentation Management

Update Go documentation when it appears inaccurate or add missing documentation for exported functions, types, and interfaces. Use built-in tools to scan the codebase and ensure documentation follows Go best practices and repository standards.

## Tasks

1. **Scan Go Files for Documentation Issues**:

   - Use `glob("**/*.go")` to find all Go files across the codebase (respects `.ignore` file)
   - Exclude test files and generated files from analysis
   - Focus on source files in `src/`, `cmd/`, and root-level Go files

2. **Identify Missing Documentation**:

   - Use `grep` patterns to find exported functions, types, and interfaces without proper documentation:
     ```go
     // Find exported functions without comments
     grep("^func [A-Z]", include="*.go")
     
     // Find exported types without comments  
     grep("^type [A-Z]", include="*.go")
     
     // Find exported interfaces without comments
     grep("^type [A-Z].*interface", include="*.go")
     ```

    - Cross-reference with `go doc` output to verify completeness:
      ```bash
      # For large packages, process individually to avoid truncation:
      # Get all exported symbols from a package (process one package at a time)
      go doc -u github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain | grep "^func [A-Z]"

      # Alternative: Use grep directly on source files for comparison
      grep "^func [A-Z]" src/internal/x509/chain/*.go

      # For comprehensive analysis without truncation:
      # 1. Get package overview
      go doc github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain

      # 2. Get specific exported functions
      go doc github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain.FetchRemoteChain

      # 3. Get exported types
      go doc -u github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain | grep "^type [A-Z]"
      ```

3. **Analyze Existing Documentation Quality**:

   - Check that comments start with the function/type name in complete sentences
   - Verify documentation accuracy by reading function implementations
   - Look for outdated examples, incorrect parameter descriptions, or missing return value documentation
   - Check for proper formatting and grammar

4. **Update or Add Documentation**:

   - For missing documentation: Add comments following repository standards
   - For inaccurate documentation: Update comments to match current implementation
   - Use `read()` to examine function implementations before documenting
   - Use `edit()` to update documentation comments

5. **Verify Documentation Completeness**:

    - Run `go doc` commands to verify all exported symbols are documented:
      ```bash
      # For large packages, avoid -all flag to prevent truncation:
      # Check package documentation overview
      go doc github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain

      # Verify specific functions are documented (one at a time)
      go doc github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain.FetchRemoteChain
      go doc github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain.VerifyChain

      # Alternative: Check specific exported symbols without -all flag
      go doc -u github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain | grep -E "^(func|type) [A-Z]"
      ```

   - Ensure documentation renders correctly with `go doc`

6. **Update Package-Level Documentation**:

   - Check for missing package comments in `doc.go` files
   - Verify package comments accurately describe the package's purpose
   - Update package documentation if functionality has changed

7. **Cross-Reference with Tests**:

   - Check that documented behavior matches test expectations
   - Update documentation if tests reveal undocumented edge cases
   - Ensure examples in documentation are testable

## Documentation Standards (from AGENTS.md)

**Exported Functions/Types/Interfaces**:
- Every exported function/interface must have a comment starting with its name in complete sentences
- Comments should explain what the function does, not how it does it
- Include parameter and return value descriptions when not obvious
- Use proper grammar and complete sentences

**Examples**:
```go
// ✅ GOOD: Complete sentence starting with function name
// FetchRemoteChain retrieves the complete certificate chain from a remote server.
// It follows redirects and handles various certificate formats.
func FetchRemoteChain(ctx context.Context, url string) (*Chain, error) {
    // implementation...
}

// ❌ BAD: Incomplete or missing documentation
func FetchRemoteChain(ctx context.Context, url string) (*Chain, error) {
    // implementation...
}
```

**Package Documentation**:
- Package comments should be in `doc.go` files
- Explain the package's purpose and main types
- Include usage examples when appropriate

## Error Handling

### Tool Abort Errors

When tools are aborted during execution (e.g., due to timeout, resource constraints, or interruption):

1. **Manual Retry Required**: Agent must manually retry the tool call with the same parameters
2. **No Automatic Recovery**: The system does NOT automatically retry aborted tools
3. **Context Preservation**: Use identical input parameters when retrying
4. **Failure Strategy**: Use alternative approaches if retry fails

**Examples**:

```bash
# Glob command aborted
glob("**/*.go")  # ❌ Aborted
glob("**/*.go")  # ✅ Retry

# Grep command aborted  
grep("^func [A-Z]", include="*.go")  # ❌ Aborted
grep("^func [A-Z]", include="*.go")  # ✅ Retry
```

### Documentation Analysis Errors

- **Missing Files**: If `read()` fails, verify file paths from `glob()` output
- **Parse Errors**: If `go doc` fails, check for syntax errors in Go files first
- **Inconsistent Results**: Cross-reference multiple tools to verify findings
- **Output Truncation**: If `go doc -all` gets truncated, use individual queries instead

### Handling Large Documentation Outputs

When `go doc -all` output exceeds tool limits (30,000+ characters), use these strategies:

1. **Process One Package at a Time**:
   ```bash
   # Instead of: go doc -u -all ./...
   # Use: go doc -u github.com/your/package/path
   ```

2. **Query Specific Symbols**:
   ```bash
   # Get specific function documentation
   go doc github.com/your/package/path.FunctionName

   # Get specific type documentation
   go doc github.com/your/package/path.TypeName
   ```

3. **Use Filtered Queries**:
   ```bash
   # Get only exported functions
   go doc -u github.com/your/package/path | grep "^func [A-Z]"

   # Get only exported types
   go doc -u github.com/your/package/path | grep "^type [A-Z]"
   ```

4. **Combine with Source Code Analysis**:
   ```bash
   # Use grep on source files as primary method
   grep "^func [A-Z]" src/**/*.go
   grep "^type [A-Z]" src/**/*.go
   ```

5. **Batch Processing for Verification**:
   ```bash
   # Check documentation for specific functions in batches
   FUNCTIONS=("FetchRemoteChain" "VerifyChain" "CheckRevocationStatus")
   for func in "${FUNCTIONS[@]}"; do
     go doc "github.com/your/package/path.$func" || echo "$func: NOT DOCUMENTED"
   done
   ```

## Output Format

**Report findings in structured format**:

1. **Missing Documentation**: List functions/types without comments
2. **Inaccurate Documentation**: List documentation that needs updates with specific issues
3. **Updated Documentation**: Show before/after examples of changes made
4. **Verification Results**: Confirm all exported symbols are now documented

**Example Output**:

```
Missing Documentation Found:
- src/internal/x509/chain/chain.go:45: func ValidateChain()
- src/internal/x509/certs/certs.go:23: type Certificate struct

Inaccurate Documentation:
- src/internal/x509/chain/chain.go:67: FetchRemoteChain comment mentions deprecated parameter

Updates Applied:
- Added documentation for ValidateChain function
- Updated FetchRemoteChain parameter description
- Fixed Certificate struct field descriptions

Verification:
✅ All exported functions in x509/chain package are documented
✅ All exported types in x509/certs package are documented
```

## Important Notes

- **Focus on Exported APIs**: Only document exported (capitalized) functions, types, and interfaces
- **Implementation Details**: Documentation should describe what, not how
- **Consistency**: Follow existing documentation patterns in the codebase
- **Testing**: Run `go doc` commands to verify documentation renders correctly
- **Cross-Package References**: Update documentation when function signatures change across packages
- **Version Changes**: Update documentation to reflect API changes between versions
- **Large Output Handling**: Avoid `go doc -all` for large packages; use individual queries instead
- **Verification Strategy**: Prefer source code analysis over `go doc` for comprehensive scanning

## Verification Checklist

- [ ] All exported functions have documentation starting with function name
- [ ] All exported types have documentation describing their purpose
- [ ] All exported interfaces have documentation explaining contracts
- [ ] Documentation accurately reflects current implementation
- [ ] `go doc` commands render documentation correctly
- [ ] Package-level documentation exists and is accurate
- [ ] Examples in documentation are correct and testable

Focus on creating clear, accurate documentation that helps developers understand and use the APIs correctly.