---
description: Run tests with coverage
agent: general
---

# Run Tests with Coverage

Run the full test suite with coverage report and analyze any failures.

## Tasks

1. **Run Full Test Suite with Coverage**:
   ```bash
   go test -v -cover ./... 2>&1
   ```
   
   Note: Using `2>&1` redirects stderr to stdout to capture all test output (including failures) in a single stream. This prevents the need for multiple tool calls to retrieve output. Do not generate coverage files unless explicitly requested.

2. **Analyze Failures**:
   - Identify failing tests
   - Review error messages and stack traces
   - Check recent code changes that might have caused failures
   - Review related source code

4. **Suggest Fixes**:
   - For each failing test, provide:
     - Root cause analysis
     - Suggested fix with code example
     - Location in source file (file:line)
   - Consider:
     - Type errors or nil pointer dereferences
     - Logic errors in implementation
     - Missing edge case handling
     - Context cancellation issues
     - Race conditions

5. **Run Race Detection** (if failures involve concurrency):
   ```bash
   go test -race ./... 2>&1
   ```

## Error Handling

### Tool Abort During Tests

When test execution is aborted (e.g., due to timeout, resource constraints, or interruption):

1. **Manual Retry Required**: Agent must manually retry the same `go test` command
2. **No Automatic Recovery**: The system does NOT automatically retry aborted tools
3. **Timeout Strategy**: If timeout persists, use alternative approaches:
   - Run package-specific tests: `go test -v ./src/internal/x509/certs`
   - Use `-short` flag for faster iteration: `go test -short -v ./...`
   - Run tests without verbose output: `go test -cover ./...`
4. **Race Detection Timeout**: If `go test -race` times out, test packages individually

**Examples**:
```bash
# Full test suite aborted
go test -v -cover ./... 2>&1  # ❌ Aborted (timeout)
go test -v -cover ./... 2>&1  # ✅ Retry with same command

# If retry also times out, use package-specific approach
go test -v -cover ./src/internal/x509/certs 2>&1
go test -v -cover ./src/internal/x509/chain 2>&1
go test -v -cover ./src/cli 2>&1
go test -v -cover ./src/logger 2>&1
```

## Important Notes

- **Do NOT generate coverage files** (`coverage.out`, `coverage.html`) unless explicitly requested by the user
- Stream coverage percentages directly from `go test -cover` output
- Focus on test failures and actionable fixes
- Keep output concise and focused on failures only

## Output Format

For each failing test:
- Test name and package
- Error message
- Root cause
- Suggested fix with file path and line number
- Code example of the fix

Focus on actionable fixes with specific code changes.
