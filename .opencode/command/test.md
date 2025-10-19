---
description: Run tests with coverage
agent: general
---

# Run Tests with Coverage

Run the full test suite with coverage report and analyze any failures.

## Tasks

1. **Run Full Test Suite with Coverage**:
   ```bash
   go test -v -cover ./... 2>&1 | cat
   ```
   
   **IMPORTANT**: 
   - Piping to `cat` ensures bash tool captures and displays all test output
   - `2>&1` redirects stderr to stdout for complete output capture
   - **ALWAYS display the raw test output** received from the bash tool to the user
   - Do NOT summarize or format test output - show it exactly as received
   - Do not generate coverage files unless explicitly requested

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
   go test -race ./... 2>&1 | cat
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
go test -v -cover ./... 2>&1 | cat  # ❌ Aborted (timeout)
go test -v -cover ./... 2>&1 | cat  # ✅ Retry with same command

# If retry also times out, use package-specific approach
go test -v -cover ./src/internal/x509/certs 2>&1 | cat
go test -v -cover ./src/internal/x509/chain 2>&1 | cat
go test -v -cover ./src/cli 2>&1 | cat
go test -v -cover ./src/logger 2>&1 | cat
```

## Important Notes

- **ALWAYS show raw bash output** from test commands to the user - do NOT transform, summarize, or format into tables
- **Piping to `cat`** ensures test output is captured and displayed by bash tool (keeps stream in-memory, no temp files)
- **Do NOT generate coverage files** (`coverage.out`, `coverage.html`) unless explicitly requested by the user
- Stream coverage percentages directly from `go test -cover` output
- Focus on test failures and actionable fixes
- Only create formatted summaries AFTER showing the raw output

## Output Format

**CRITICAL**: Display the exact bash output received from test commands to the user. Do NOT summarize, format into tables, or transform the output.

The `| cat` pipe ensures all test output (pass/fail/coverage) is captured and displayed by the bash tool without requiring temporary files.

For failing tests, the raw output will include:
- Test name and package
- Error message and stack trace
- FAIL markers

After showing raw output, provide analysis:
- Root cause
- Suggested fix with file path and line number
- Code example of the fix

Focus on actionable fixes with specific code changes.
