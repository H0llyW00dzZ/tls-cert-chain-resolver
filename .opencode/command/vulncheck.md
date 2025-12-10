---
description: Check for vulnerable dependencies and suggest updates
agent: general
---

# Vulnerability Check and Dependency Update

Check for vulnerable direct dependencies using `govulncheck ./...`, analyze findings, and suggest or apply safe updates to maintain security. Focus only on direct dependencies, ignoring indirect ones.

## Tasks

1. **Run Vulnerability Check**:

   - Execute `govulncheck ./...` to scan for known vulnerabilities in dependencies
   - Capture output for analysis
   - Check exit code: 0 = no vulnerabilities, non-zero = issues found

2. **Analyze Vulnerabilities**:

   - Parse govulncheck output to identify affected modules, versions, and severity
   - Cross-reference with current go.mod/go.sum
   - Focus only on direct dependencies (ignore indirect ones marked with `// indirect`)
   - Assess impact on the codebase (e.g., does it affect certificate operations, MCP server)

3. **Check for Updates**:

   - Use `go list -m -u all` to check for available updates to direct dependencies
   - Read `go.mod` to compare current direct dependencies and identify which ones have available updates
   - Identify safe minor/patch updates that maintain compatibility
   - Prioritize security fixes over breaking changes
   - Generate report of recommended updates with rationale

4. **Apply Safe Updates**:

   - For non-breaking updates to direct dependencies, run `go get <module>@<version>` to update
   - Run `go mod tidy` to clean up go.mod/go.sum
   - Verify updates don't break imports or functionality

5. **Test After Updates**:

   - Run `go build ./...` to ensure compilation
   - Run `go test -race ./...` for race detection and basic functionality
   - Run targeted tests for affected packages (e.g., certificate operations if crypto libs updated)
   - If tests fail, rollback updates and suggest manual intervention

6. **Update Knowledge Base**:

   - If dependencies changed, run `/update-knowledge` to sync agent instructions
   - Update AGENTS.md and deepwiki.instructions.md with new dependency versions
   - Document security improvements in commit messages

7. **Report Findings**:

   - Generate summary report with:
     - Vulnerabilities found in direct dependencies (count, severity)
     - Updates applied (modules, versions)
     - Test results (pass/fail)
     - Recommendations for remaining issues

## What to Look For

- **High-Severity Vulnerabilities**: Prioritize CVEs with high impact (e.g., remote code execution in crypto libraries)
- **Dependency Chains**: Check if vulnerabilities affect core functionality (certificate validation, AI streaming)
- **Update Availability**: Prefer updates from official sources (e.g., golang.org/x/*, google.golang.org/*)
- **Breaking Changes**: Avoid major version updates that could break API compatibility
- **Test Coverage**: Ensure updated dependencies have adequate test coverage

## Error Handling

### Vulncheck Failures

If `govulncheck ./...` fails:
- Check Go version compatibility (requires Go 1.21+)
- Verify internet connection for vulnerability database access
- Retry with `GOPROXY=direct govulncheck ./...` if proxy issues

### Update Conflicts

If `go get` fails:
- Check for conflicting version constraints in go.mod
- Use `go mod edit -require=<module>@<version>` for manual resolution
- Run `go mod tidy` to resolve dependencies

### Test Failures After Update

If tests fail post-update:
- Identify failing tests and affected functionality
- Check if update introduced breaking changes
- Rollback with `go get <module>@<previous-version>`
- Report issue to dependency maintainers if needed

## Output Format

Report in structured format:

1. **Vulnerability Scan Results**: Summary of govulncheck output (vulnerabilities found, affected modules)
2. **Update Recommendations**: List of suggested updates with rationale
3. **Applied Changes**: Modules updated, versions changed
4. **Test Results**: Build and test status after updates
5. **Next Steps**: Recommendations for unresolved issues or manual intervention

## Examples

### Successful Update
```
Vulnerability Scan: Found 2 vulnerabilities in golang.org/x/crypto
Update Recommendations: golang.org/x/crypto v0.45.0 → v0.46.0 (security fix)
Applied Changes: Updated golang.org/x/crypto to v0.46.0
Test Results: All tests pass, no regressions
```

### Manual Intervention Needed
```
Vulnerability Scan: Found 1 high-severity vulnerability in indirect dependency
Update Recommendations: Major version update required (breaking changes)
Applied Changes: None (requires manual review)
Next Steps: Evaluate impact on certificate operations, plan migration
```

Prioritize security while maintaining stability. Use tools proactively to validate changes and ensure no functionality regressions.
