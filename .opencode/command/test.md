---
description: Run tests with coverage
agent: general
---

# Run Tests with Coverage

Run the full test suite with coverage report and analyze any failures.

## Tasks

1. **Run Full Test Suite with Coverage**:
   ```bash
   go test -v -cover ./...
   ```
   
   Note: Output coverage percentages directly to stdout, do not generate coverage files unless explicitly requested.

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
   go test -race ./...
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
