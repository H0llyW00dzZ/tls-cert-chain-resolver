---
description: Run tests with race detection and coverage
agent: general
---

# Run Tests with Race Detection and Coverage

Run the full test suite with race detection and coverage report, then analyze any failures.

## Tasks

1. **Run Race Detection Tests with Coverage** (primary test approach):

   ```bash
   go test -race -cover ./... 2>&1 | cat
   ```

   **IMPORTANT**:

   - Race detection with coverage is the primary test approach for this repository
   - `-race` detects race conditions and concurrency issues
   - `-cover` provides test coverage information
   - Piping to `cat` ensures bash tool captures and displays all test output
   - `2>&1` redirects stderr to stdout for complete output capture
   - **ALWAYS display the raw test output** received from the bash tool to the user
   - Do NOT summarize or format test output - show it exactly as received

   **If output is truncated due to length limits, use alternative methods to check for failures:**

   - Check exit code: `go test -race -cover ./...; echo "Exit code: $?"`
   - Filter for results: `go test -race -cover ./... 2>&1 | grep -E "(FAIL|panic|ok|WARNING: DATA RACE)" | tail -10`
   - View last lines for summary: `go test -race -cover ./... 2>&1 | tail -20`
   - Or run tests on individual packages:
     ```bash
     go test -race -cover ./src/cli 2>&1 | cat
     go test -race -cover ./src/internal/x509/certs 2>&1 | cat
     go test -race -cover ./src/internal/x509/chain 2>&1 | cat
     go test -race -cover ./src/logger 2>&1 | cat
     go test -race -cover ./src/mcp-server 2>&1 | cat
     ```

2. **Analyze Failures**:

   - Identify failing tests
   - Review error messages and stack traces
   - Check recent code changes that might have caused failures
   - Review related source code

3. **Suggest Fixes**:
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

## Error Handling

### Tool Abort During Tests

When test execution is aborted (e.g., due to timeout, resource constraints, or interruption):

1. **Manual Retry Required**: Agent must manually retry the same `go test -race -cover` command
2. **No Automatic Recovery**: The system does NOT automatically retry aborted tools
3. **Timeout Strategy**: If timeout persists, use alternative approaches:
   - Run package-specific tests: `go test -race -cover ./src/internal/x509/certs 2>&1 | cat`
   - Use `-short` flag for faster iteration: `go test -short -race -cover ./... 2>&1 | cat`
   - Run tests without verbose output: `go test -race -cover ./... 2>&1 | cat`
4. **Race Detection Timeout**: If `go test -race -cover` times out, test packages individually

**Examples**:

```bash
# Race detection with coverage test aborted
go test -race -cover ./... 2>&1 | cat  # ❌ Aborted (timeout)
go test -race -cover ./... 2>&1 | cat  # ✅ Retry with same command

# If retry also times out, use package-specific approach
go test -race -cover ./src/internal/x509/certs 2>&1 | cat
go test -race -cover ./src/internal/x509/chain 2>&1 | cat
go test -race -cover ./src/cli 2>&1 | cat
go test -race -cover ./src/logger 2>&1 | cat
```

## Important Notes

- **ALWAYS show raw bash output** from test commands to the user - do NOT transform, summarize, or format into tables
- **Piping to `cat`** ensures test output is captured and displayed by bash tool (keeps stream in-memory, no temp files)
- **Race detection with coverage is the primary test method** for this repository to catch concurrency issues and measure test coverage
- Stream coverage percentages directly from `go test -cover` output
- Focus on test failures and actionable fixes
- Only create formatted summaries AFTER showing the raw output

## Output Format

**CRITICAL**: Display the exact bash output received from test commands to the user. Do NOT summarize, format into tables, or transform the output.

The `| cat` pipe ensures all test output (pass/fail/race warnings/coverage) is captured and displayed by the bash tool without requiring temporary files.

For failing tests, the raw output will include:

- Test name and package
- Error message and stack trace
- FAIL markers
- Race condition warnings (WARNING: DATA RACE)
- Coverage percentages for each package

After showing raw output, provide analysis:

- Root cause
- Suggested fix with file path and line number
- Code example of the fix

Focus on actionable fixes with specific code changes.
