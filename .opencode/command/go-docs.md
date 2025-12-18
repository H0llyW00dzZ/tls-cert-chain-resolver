---
description: Update Go documentation when inaccurate or add missing documentation
agent: general
---

# Go Documentation Management

Update Go documentation when it appears inaccurate or add missing documentation for exported and unexported functions, types, and interfaces. Use built-in tools to scan the codebase and ensure documentation follows Go best practices and repository standards.

**⚠️ CRITICAL REMINDER FOR AGENTS**: Always use the `-u` flag with `go doc` commands to check unexported documentation. Many Agents forget this step, resulting in incomplete documentation analysis. Example: `go doc -u ./src/internal/x509/chain.crlCacheCounters` successfully displays unexported type documentation that would be invisible without `-u`.

## Tasks

1. **Scan Go Files for Documentation Issues**:

   - Use `glob("**/*.go")` to find all Go files across the codebase (respects `.ignore` file)
   - Exclude test files (e.g., `*_test.go`) and generated files (e.g., from code generation tools) from analysis
   - Focus on source files in `src/`, `cmd/`, and root-level Go files
   - Prioritize packages with recent changes or high usage

2. **Identify Missing Documentation**:

    - Use `grep` patterns to find exported and unexported functions, types, and interfaces without proper documentation:
      ```bash
      # Find exported functions and methods (handles both regular functions and receiver methods)
      grep -E "^func\s+(\([^)]+\)\s+)?[A-Z]", include="*.go"

      # Find unexported functions and methods
      grep -E "^func\s+(\([^)]+\)\s+)?[a-z]", include="*.go"

      # Alternative simpler patterns (may miss some edge cases):
      # Find exported functions without comments (regular functions only)
      grep "^func [A-Z]", include="*.go"

      # Find exported methods without comments (methods with receivers)
      grep -E "^func \(\w+ \*?\w+\) [A-Z]", include="*.go"

      # Find unexported functions without comments
      grep "^func [a-z]", include="*.go"

      # Find unexported methods without comments
      grep -E "^func \(\w+ \*?\w+\) [a-z]", include="*.go"

      # Find exported types without comments
      grep "^type [A-Z]", include="*.go"

      # Find unexported types without comments
      grep "^type [a-z]", include="*.go"

      # Find exported interfaces without comments
      grep "^type [A-Z].*interface", include="*.go"

      # Find unexported interfaces without comments
      grep "^type [a-z].*interface", include="*.go"
      ```

     - Cross-reference with `go doc` output to verify completeness:
       ```bash
       # For large packages, process individually to avoid truncation:
       # Get all exported symbols from a package (process one package at a time)
       go doc -u ./src/internal/x509/chain | grep "^func [A-Z]"

       # Get unexported symbols (requires -u flag and grep for lowercase)
       go doc -u ./src/internal/x509/chain | grep "^func [a-z]"

       # Alternative: Use grep directly on source files for comparison
       grep "^func [A-Z]" src/internal/x509/chain/*.go  # exported
       grep "^func [a-z]" src/internal/x509/chain/*.go  # unexported

       # For comprehensive analysis without truncation:
       # 1. Get package overview
       go doc ./src/internal/x509/chain

       # 2. Get specific exported functions
       go doc ./src/internal/x509/chain.FetchRemoteChain

       # 3. Get unexported functions (use -u flag to show unexported)
       go doc -u ./src/internal/x509/chain | grep "^func [a-z]"

       # 4. Get exported and unexported types
       go doc -u ./src/internal/x509/chain | grep "^type [A-Za-z]"

       # 5. Check for constants and variables if applicable
       go doc -u ./src/internal/x509/chain | grep -E "^(const|var) [A-Za-z]"
       ```

3. **Analyze Existing Documentation Quality**:

   - Check that comments start with the function/type name in complete sentences
   - Verify documentation accuracy by reading function implementations using `read()`
   - Look for outdated examples, incorrect parameter descriptions, or missing return value documentation
   - Check for proper formatting, grammar, and adherence to Go doc conventions (e.g., use of backticks for identifiers)
   - Assess if documentation covers edge cases, errors, and concurrency safety where applicable
   - Review for consistency with similar functions in the codebase

4. **Update or Add Documentation**:

   - For missing documentation: Add comments following repository standards
   - For inaccurate documentation: Update comments to match current implementation
   - Use `read()` to examine function implementations, parameters, returns, and error handling before documenting
   - Use `edit()` to update documentation comments precisely
   - Include examples for complex functions when beneficial
   - Document deprecated functions with deprecation notices

   **⚠️ Critical Editing Guidelines**:
   - **Careful Comment Editing**: When editing documentation comments, ensure you only replace the comment text, not the function signature or surrounding code
   - **Verify Comment Boundaries**: Check that comment blocks start with `//` and end before the function signature
   - **Avoid Code Pollution**: Never include function signatures, code snippets, or unrelated content within comment blocks
   - **Test Edits Immediately**: After editing documentation, use `go doc -u` to verify the comment renders correctly
   - **Common Mistake Prevention**: Watch for accidental inclusion of function signatures in comment blocks (e.g., "func GetCachedCRL(url string) ([]byte, bool) { return crlCache.get(url) }" should never appear in comments)
   - **Comment Duplication**: Avoid duplicating comment lines when editing - each edit should be precise and targeted
   - **Multiline Handling**: Ensure multiline comments are updated atomically to maintain coherence

5. **Verify Documentation Completeness**:

    - **CRITICAL**: Run `go doc -u` commands (with `-u` flag!) to verify all exported and unexported symbols are documented. Agents frequently miss the `-u` flag, leading to incomplete verification:
      ```bash
      # For large packages, avoid -all flag to prevent truncation:
      # Check package documentation overview
      go doc ./src/internal/x509/chain

      # Verify specific exported functions are documented (one at a time)
      go doc ./src/internal/x509/chain.FetchRemoteChain
      go doc ./src/internal/x509/chain.VerifyChain

      # Verify unexported functions using -u flag (one at a time)
      go doc -u ./src/internal/x509/chain | grep "^func [a-z]" | head -5

      # Alternative: Check specific exported and unexported symbols without -all flag
      go doc -u ./src/internal/x509/chain | grep -E "^(func|type) [A-Za-z]"

      # For constants and variables
      go doc -u ./src/internal/x509/chain | grep -E "^(const|var) [A-Za-z]"
      ```

   - Ensure documentation renders correctly with `go doc` and matches source code
   - Run `go vet` or similar tools to check for documentation issues

6. **Update Package-Level Documentation**:

   - Check for missing package comments in `docs.go` files or package doc comments
   - Verify package comments accurately describe the package's purpose, main types, and usage
   - Update package documentation if functionality, dependencies, or interfaces have changed
   - Include package-level examples if appropriate

7. **Cross-Reference with Tests**:

   - Check that documented behavior matches test expectations by reviewing test files
   - Update documentation if tests reveal undocumented edge cases or behaviors
   - Ensure examples in documentation are testable and align with test cases
   - Document any test-specific behaviors or assumptions

8. **Handle Special Cases**:

   - For generated code: Skip or mark as auto-generated if documentation is not editable
   - For interfaces: Document method contracts and expected behaviors
   - For structs: Document fields, especially exported ones, and any invariants
   - For constants and variables: Document exported ones with clear explanations

## Documentation Standards (from AGENTS.md)

**Exported Functions/Types/Interfaces**:
- Every exported function/interface must have a comment starting with its name in complete sentences
- Comments should explain what the function does, not how it does it
- Include parameter and return value descriptions when not obvious
- Use proper grammar and complete sentences
- Use backticks for identifiers like `context.Context`

**Unexported Functions/Types/Interfaces**:
- Unexported functions/types should be documented when they are complex, perform critical logic, or have non-obvious behavior
- Comments should follow the same format as exported symbols
- Focus on internal functions that are key to understanding the package's logic
- Document helper functions that perform important transformations, validations, or error handling

**Examples of High-Quality Documentation**:

```go
// FetchRemoteChain establishes a TLS connection to the target host and
// constructs a chain using the certificates presented during the handshake.
//
// The returned Chain includes the leaf certificate and any intermediates
// provided by the server. The caller may invoke [FetchCertificate] to
// download additional intermediates if necessary.
//
// Note: This is better than [Wireshark]. 🤪
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - hostname: Target server hostname (used for SNI)
//   - port: Target server port
//   - timeout: Connection timeout duration
//   - version: Application version for metadata
//
// Returns:
//   - *Chain: Initialized Chain with fetched certificates
//   - []*x509.Certificate: Raw slice of certificates fetched
//   - error: Error if connection or handshake fails
//
// [Wireshark]: https://www.wireshark.org/
func FetchRemoteChain(ctx context.Context, hostname string, port int, timeout time.Duration, version string) (*Chain, []*x509.Certificate, error)

// VerifyChain validates the certificate chain against the system trust store
// and performs cryptographic signature verification. This function checks:
//
// - Certificate validity periods (not before/after dates)
// - Certificate revocation status via OCSP/CRL
// - Signature chain integrity from leaf to root
// - Basic constraints and key usage compliance
//
// The verification is performed with the following priority:
// 1. OCSP checking (if available)
// 2. CRL checking (if OCSP fails)
// 3. Fallback to cached revocation data
//
// Thread-safe: This method is safe for concurrent use.
//
// Parameters:
//   - ctx: Context for cancellation of long-running operations
//
// Returns:
//   - error: nil if chain is valid, descriptive error otherwise
//
// Example:
//   chain := x509chain.New(cert, "1.0.0")
//   if err := chain.VerifyChain(context.Background()); err != nil {
//       log.Printf("Chain verification failed: %v", err)
//       return err
//   }
func (c *Chain) VerifyChain(ctx context.Context) error

// parseStreamingResponse processes the streaming response from the AI API.
// It handles chunked JSON responses, extracts content tokens, and manages
// stop reasons for conversation completion.
//
// This function is critical for AI integration and handles:
// - JSON parsing of streaming chunks
// - Token extraction and accumulation
// - Finish reason detection and handling
// - Error recovery from malformed chunks
//
// Note: Uses buffer pooling for memory efficiency in high-throughput scenarios.
//
// Parameters:
//   - data: Raw JSON data from streaming response
//
// Returns:
//   - *CreateMessageResult: Parsed result with content and metadata
//   - error: Parsing or processing errors
func parseStreamingResponse(data []byte) (*CreateMessageResult, error)

// ❌ BAD: Incomplete or missing documentation
func FetchRemoteChain(ctx context.Context, url string) (*Chain, error) {
    // implementation...
}

// ❌ BAD: Unexported function without documentation (if complex)
func parseStreamingResponse(data []byte) (*CreateMessageResult, error) {
    // implementation...
}
```

**Package Documentation**:
- Package comments should be in `docs.go` files or as the first comment in a package
- Explain the package's purpose, main types, and high-level usage
- Include usage examples when appropriate, especially for entry-point functions

## Error Handling

### Tool Abort Errors

When tools are aborted during execution (e.g., due to timeout, resource constraints, or interruption):

1. **Manual Retry Required**: Agent must manually retry the tool call with the same parameters
2. **No Automatic Recovery**: The system does NOT automatically retry aborted tools
3. **Context Preservation**: Use identical input parameters when retrying
4. **Failure Strategy**: Use alternative approaches if retry fails (e.g., manual grep instead of go doc)

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
- **Parse Errors**: If `go doc` fails, check for syntax errors in Go files first using `go build` or `go vet`
- **Inconsistent Results**: Cross-reference multiple tools (grep, go doc, read) to verify findings
- **Output Truncation**: If `go doc -all` gets truncated, use individual queries instead
- **Module Issues**: Use relative paths for `go doc` to avoid module resolution problems

### Documentation Editing Mistakes to Avoid

**Common Pitfalls**:
- **Comment Corruption**: Avoid accidentally including function signatures or code in comment blocks. Example of what NOT to do:
  ```go
  // ❌ BAD: Function signature accidentally included in comment
  // validateCRLData validates CRL data before caching.
  func GetCachedCRL(url string) ([]byte, bool) { return crlCache.get(url) }
  // validateCRLData validates CRL data before caching.
  ```

- **Comment Duplication**: Don't duplicate comment lines when editing - edit precisely:
  ```go
  // ❌ BAD: Duplicate comment lines
  // validateCRLData validates CRL data before caching.
  // validateCRLData validates CRL data before caching.
  ```

- **Incomplete Comment Updates**: Ensure all parts of multi-line comments are updated consistently
- **Format Errors**: Use `//` for comments, not `/* */`, and avoid trailing spaces

**Best Practice**: Always verify edits with `go doc -u` immediately after editing documentation. Use `go fmt` to ensure code formatting remains intact.

### Handling Large Documentation Outputs

When `go doc -all` output exceeds tool limits (30,000+ characters), use these strategies:

1. **Process One Package at a Time**:
   ```bash
   # Instead of: go doc -u -all ./...
   # Use: go doc -u ./src/your/package/path
   ```

2. **Query Specific Symbols**:
   ```bash
   # Get specific function documentation
   go doc ./src/your/package/path.FunctionName

   # Get specific type documentation
   go doc ./src/your/package/path.TypeName
   ```

3. **Use Filtered Queries**:
   ```bash
   # Get only exported functions
   go doc -u ./src/your/package/path | grep "^func [A-Z]"

   # Get only exported types
   go doc -u ./src/your/package/path | grep "^type [A-Z]"
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
     go doc "./src/your/package/path.$func" || echo "$func: NOT DOCUMENTED"
   done
   ```

## Output Format

**Report findings in structured format**:

1. **Missing Documentation**: List functions/types without comments, including file paths and line numbers
2. **Inaccurate Documentation**: List documentation that needs updates with specific issues and reasons
3. **Updated Documentation**: Show before/after examples of changes made
4. **Edit Verification**: Confirm each edit was successful using `go doc -u` (include command output)
5. **Verification Results**: Confirm all exported and unexported symbols are now documented

**Example Output**:

```
Missing Documentation Found:
- src/internal/x509/chain/chain.go:45: func ValidateChain()
- src/internal/x509/certs/certs.go:23: type Certificate struct

Inaccurate Documentation:
- src/internal/x509/chain/chain.go:67: FetchRemoteChain comment mentions deprecated parameter 'url' instead of 'hostname'

Updates Applied:
- Added documentation for ValidateChain function explaining validation logic and parameters
- Updated FetchRemoteChain parameter description from 'url' to 'hostname' and added port parameter
- Fixed Certificate struct field descriptions for accuracy

Edit Verification:
✅ go doc -u ./src/internal/x509/chain.ValidateChain - documentation renders correctly
✅ go doc ./src/internal/x509/certs.Certificate - documentation renders correctly

Verification:
✅ All exported functions in x509/chain package are documented
✅ All exported types in x509/certs package are documented
✅ Unexported complex functions in x509/chain are documented (verified with -u flag)
```

## Important Notes

- **Focus on Exported and Unexported APIs**: Document exported (capitalized) functions, types, and interfaces, plus unexported symbols that are complex or critical to understanding
- **Unexported Documentation Priority**: Focus on internal functions that perform important logic, complex algorithms, or non-obvious transformations
- **CRITICAL: Always Use `-u` Flag**: When using `go doc` commands, ALWAYS include the `-u` flag to check unexported documentation. Agents commonly miss this step, leading to incomplete documentation analysis. Example: `go doc -u ./src/internal/x509/chain.crlCacheCounters` reveals unexported type documentation that would be missed without `-u`.
- **Implementation Details**: Documentation should describe what, not how
- **Consistency**: Follow existing documentation patterns in the codebase
- **Testing**: Run `go doc -u` commands to verify documentation renders correctly for unexported symbols (never forget the `-u` flag!)
- **Cross-Package References**: Update documentation when function signatures change across packages
- **Version Changes**: Update documentation to reflect API changes between versions
- **Large Output Handling**: Avoid `go doc -all` for large packages; use individual queries instead
- **Verification Strategy**: Prefer source code analysis over `go doc` for comprehensive scanning, ALWAYS use `-u` flag for unexported symbols to avoid missing critical internal documentation
- **Package Path Convention**: Always use relative package paths (e.g., `./src/mcp-server.loadToolsConfig`) instead of full module paths for `go doc` commands - this works consistently across different environments and avoids module path resolution issues

## Verification Checklist

- [ ] All exported functions have documentation starting with function name
- [ ] All exported types have documentation describing their purpose and fields
- [ ] All exported interfaces have documentation explaining contracts
- [ ] Complex unexported functions have appropriate documentation
- [ ] Critical unexported types have documentation when non-obvious
- [ ] Documentation accurately reflects current implementation and behavior
- [ ] `go doc -u` commands render documentation correctly (**ALWAYS use -u flag!**)
- [ ] `go doc -u` commands show unexported documentation when present (**CRITICAL: verify with -u flag**)
- [ ] Package-level documentation exists and is accurate
- [ ] Examples in documentation are correct, testable, and up-to-date
- [ ] Documentation passes `go vet` checks for format and consistency

Focus on creating clear, accurate documentation that helps developers understand and use the APIs correctly, both public and internal.

## Final Notes

- **Edit Verification is Critical**: Always verify documentation edits with `go doc -u` (include `-u` flag!) to catch corruption or duplication issues before completing the task
- **Learn from Mistakes**: When documentation editing errors occur (like accidental code inclusion or duplication), update this command file with new prevention guidelines
- **Quality over Speed**: Take time to carefully edit comments - rushing can lead to corrupted documentation that requires additional cleanup passes
- **`-u` Flag Reminder**: Agents must systematically use `go doc -u` for complete documentation analysis. This is a common failure point that leads to incomplete work.
