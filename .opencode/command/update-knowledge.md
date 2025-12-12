---
description: Update agent instruction files when code changes
agent: general
---

# Update Knowledge Base

Update agent instruction files in `.github/instructions/` to reflect recent code changes, new patterns, or architectural updates. Ensure all updates are accurate, consistent, and repository-specific. Use git commands to analyze changes and verify updates through testing where applicable. Prioritize precision, avoid redundancy, and centralize common information in README.md. Use tools proactively to validate changes before finalizing.

## Tasks

1. **Sync with Remote Branch**:

   - Run `git pull` to ensure the local repository is synchronized with the remote branch before analyzing changes or updating instruction files. This prevents conflicts and ensures all recent commits are available for review.
   - If there are uncommitted changes, stash them temporarily: `git stash` and restore after: `git stash pop`.

2. **Analyze Recent Changes**:

   - Retrieve recent commits: `git log -10 --oneline`
   - View detailed commit messages and bodies: `git log -10 --pretty=format:"[SHA - %h]: %s%n%n%b%n"`
   - Identify files changed: `git diff HEAD~10..HEAD --name-only`
   - Review commit messages for context, focusing on reasons for changes, new features, or refactors
   - Identify modified, added, or deleted files, directories, and emerging patterns
   - Cross-reference with AGENTS.md for affected agent guidelines or workflows
   - If more history is needed, increase the commit count (e.g., `git log -20 --oneline`) to capture broader changes.

3. **Update Relevant Instruction Files**:

   - **Note**: Check for duplicates and centralize common information in README.md. Avoid redundancy while ensuring completeness.
   - `README.md`: Update repository context, module info, file table, and high-level structure as central reference; include any new dependencies or build requirements.
   - `gopls.instructions.md`: Update for Go code patterns, package structures, new imports, API changes, or symbol definitions; add new search patterns if applicable.
   - `filesystem.instructions.md`: Update for new/moved/deleted file paths and directory structures; revise grep patterns and file trees.
   - `memory.instructions.md`: Update for changes in context/memory management, caching strategies, state handling, or performance optimizations.
   - `deepwiki.instructions.md`: Add new external dependencies, libraries, research targets, or integration points.
   - `opencode.instructions.md`: Update for configuration or workflow changes; document new custom commands or modifications.
   - `x509_resolver.md`: Update for MCP server changes, new tools, API modifications, or certificate-related patterns.
   - For each file, ensure frontmatter (description, agent) is accurate and consistent.

4. **Remove Duplicate Content**:

   - Centralize repository context (module, Go version, dependencies) in README.md
   - Remove redundant package structures from specialized files; link back to README.md
   - Simplify repository structure trees to high-level overviews with references to README.md
   - Eliminate duplicate dependency lists, configuration examples, and code snippets
   - Ensure each file focuses on its specialized purpose without repeating common information; use cross-references where needed.

5. **Check .opencode Directory Changes**:

   - List current commands: `list('.opencode/command')`
   - Compare against git diffs: `git diff HEAD~10..HEAD --name-only` filtered for `.opencode/` paths
   - For new commands: Document in `opencode.instructions.md` under "Custom Commands" and append to the command table in `.opencode/README.md`; include usage examples and parameters.
   - For deleted commands: Remove from `opencode.instructions.md` and `.opencode/README.md` table; update any cross-references.
   - For modified commands: Revise descriptions, examples, and usage in `opencode.instructions.md`; test functionality.
   - Validate frontmatter (description, agent) for accuracy and consistency across files.

6. **Verify Instruction File Patterns**:

    - **Gopls patterns**: Test `gopls_go_search` patterns in `gopls.instructions.md` to ensure they find expected symbols
      - Example: `gopls_go_search("Certificate")` should return certificate-related symbols
      - Verify all search patterns in the examples section work correctly; update or remove invalid ones.
      - Add new patterns for recently added symbols or functions.

    - **Filesystem patterns**: Test `grep` patterns in `filesystem.instructions.md` to ensure they find matches
      - Example: `grep("func \(c \*Certificate\)", include="*.go")` should find certificate methods
      - Remove or fix patterns that don't work (e.g., embedded files, non-existent functions)
      - Remove duplicate patterns across the file; consolidate similar ones.

    - **Other tool patterns**: Verify patterns in other instruction files work correctly
      - Test examples in `x509_resolver.md`, `memory.instructions.md`, etc.
      - Ensure all code examples compile and patterns find expected results; run `go vet ./...` for static analysis.
      - For non-Go files, use appropriate tools (e.g., syntax check for config files).

7. **Verify Consistency**:

    - Confirm examples reference real repository paths (e.g., via `list()` or `grep`); update paths if directories have moved.
    - Update and validate cross-references between instruction files; ensure links are functional.
    - Test commands in examples for functionality (e.g., run sample CLI commands); capture output for verification.
    - Ensure code examples compile: `go build ./... 2>&1 | cat`
    - Perform race detection tests: `go test -v -race ./... 2>&1 | cat`
      - If output is truncated, use alternatives:
        - Check exit code: `go test -race ./...; echo "Exit code: $?"`
        - Filter results: `go test -race ./... 2>&1 | grep -E "(FAIL|panic|ok|WARNING: DATA RACE)" | tail -10`
        - Summarize: `go test -race ./... 2>&1 | tail -20`
        - Test specific packages:
          - `go test -race ./src/cli 2>&1 | cat`
          - `go test -race ./src/internal/x509/certs 2>&1 | cat`
          - `go test -race ./src/internal/x509/chain 2>&1 | cat`
          - `go test -race ./src/logger 2>&1 | cat`
          - `go test -race ./src/mcp-server 2>&1 | cat`

8. **Update AGENTS.md**:

   - Incorporate new build commands if the process has evolved (e.g., new flags or steps).
   - Refine code style guidelines for newly identified patterns; add examples from recent commits.
   - Expand "Bad Practices" with common pitfalls from recent changes or test failures.
   - Update agent roles or workflows if code changes affect multi-agent interactions.

## What to Look For

- **New packages/files**: Document in `gopls.instructions.md` and update repository structure references; add to grep patterns if relevant.
- **Directory reorgs**: Update references in specialized files, centralize details in README.md; verify all paths in examples.
- **New CLI features**: Update examples in relevant specialized files; test new flags or options.
- **New dependencies**: List in `deepwiki.instructions.md` for research; update build commands in AGENTS.md.
- **Refactors**: Revise code snippets in all relevant files, remove duplicates; update patterns and examples.
- **Emerging patterns**: Add to AGENTS.md and specific instruction files; include best practices.
- **Build updates**: Modify commands in AGENTS.md; verify with actual builds.
- **Duplicate content**: Identify and remove, centralize in README.md where appropriate; use shared sections.
- **Pattern verification**: Test gopls_go_search and grep patterns in instruction files, remove non-working or duplicate patterns; add new ones for coverage.
- **.opencode changes**: Track new/deleted/modified commands, updating `opencode.instructions.md` and `.opencode/README.md`; ensure examples run successfully.
- **Security or performance changes**: Update relevant files (e.g., memory.instructions.md) and AGENTS.md with new guidelines.
- **Documentation updates**: If code comments or docs changed, reflect in instruction files.

## Error Handling

### Tool Abort Errors

If tools abort (e.g., due to timeouts or interruptions):

1. **Manual Retry**: Immediately retry the exact same tool call with identical parameters
2. **No Auto-Retry**: System does not handle retries; agent must initiate
3. **Preserve Context**: Use the same inputs to maintain consistency
4. **Fallbacks**: On repeated failures, switch to manual alternatives like incremental file reading or batched operations
5. **Logging**: Note aborted calls and retries in updates for traceability.

**Examples**:

```
# Aborted bash execution
bash("go test -v -race ./...")  # ❌ Aborted
bash("go test -v -race ./...")  # ✅ Manual retry
```

### Additional Error Scenarios

- If git commands fail, verify repository state: `git status`; resolve conflicts or check permissions.
- For compilation errors, run targeted builds: `go build ./path/to/package`; investigate and fix before updating instructions.
- If tests fail persistently, isolate issues by package: `go test ./specific/package`; document failures in AGENTS.md under "Bad Practices".
- For pattern mismatches, manually search code: `grep -r "pattern" .` to confirm and adjust.
- If external tools (e.g., gopls) are unavailable, note in updates and suggest alternatives.

## Output Format

For each updated file, report in this structured format:

1. **Code Changes Summary**: Briefly describe what changed (e.g., "Added new CLI flag for verbose output in commit abc123")
2. **Affected Sections**: Specify which parts of the instruction file require updates (e.g., "Repository Structure tree in filesystem.instructions.md")
3. **Updated Content**: Provide the revised text with examples (e.g., paste the updated tree or code snippet); highlight changes with diffs if applicable.
4. **Verification**: Confirm examples work (e.g., "Tested CLI flag; output matches expected format. Race tests pass for affected package. Patterns verified with grep.")

## Recent Updates Applied

- **Duplicate Removal**: Centralized repository context in README.md, removed redundant information from specialized files
- **Consistency**: Updated cross-references to point to centralized information; validated paths and examples
- **Maintainability**: Each instruction file now focuses on its specialized purpose without repeating common details; added cross-links
- **Pattern Verification**: Added verification of gopls_go_search and grep patterns in instruction files, removed non-working patterns and duplicates; included new patterns for better coverage
- **Testing Enhancements**: Expanded verification with linting, vetting, and integration tests; added fallback testing methods

Prioritize precision, avoid overgeneralization, and ensure all updates align with actual repository state. Use tools proactively to validate before finalizing changes. If major refactors occur, consider regenerating entire sections from scratch.
