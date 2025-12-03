---
description: Update agent instruction files when code changes
agent: general
---

# Update Knowledge Base

Update agent instruction files in `.github/instructions/` to reflect recent code changes, new patterns, or architectural updates. Ensure all updates are accurate, consistent, and repository-specific. Use git commands to analyze changes and verify updates through testing where applicable.

## Tasks

1. **Analyze Recent Changes**:

   - Retrieve recent commits: `git log -10 --oneline`
   - View detailed commit messages and bodies: `git log -10 --pretty=format:"[SHA - %h]: %s%n%n%b%n"`
   - Identify files changed: `git diff HEAD~10..HEAD --name-only`
   - Review commit messages for context, focusing on reasons for changes, new features, or refactors
   - Identify modified, added, or deleted files, directories, and emerging patterns
   - Cross-reference with AGENTS.md for affected agent guidelines or workflows

2. **Update Relevant Instruction Files**:

   - **Note**: Before adding any entries, check for duplicates (e.g., verify if a dependency is already documented in `deepwiki.instructions.md`). Avoid redundancy while ensuring completeness.
   - `gopls.instructions.md`: Update for Go code patterns, package structures, new imports, or API changes
   - `filesystem.instructions.md`: Update for new/moved/deleted file paths, directory structures, and the **Repository Structure tree** (starting at line 7)
   - `memory.instructions.md`: Update for changes in context/memory management, caching strategies, or state handling
   - `deepwiki.instructions.md`: Add new external dependencies, libraries, or research targets
   - `opencode.instructions.md`: Update for configuration or workflow changes, including additions, deletions, or modifications to commands in `.opencode/command/`

3. **Update Repository Structure Tree in filesystem.instructions.md**:

   - Identify structural changes: `git diff HEAD~10..HEAD --name-only`
   - Verify current structure: Use `list()` to confirm paths
   - Update the Repository Structure tree (starting at line 7) in `filesystem.instructions.md` to include:
     - Newly added files (with concise, purpose-driven descriptions)
     - Moved or renamed files/directories
     - Newly created or reorganized directories
     - Removed files/directories (delete from tree)
   - Ensure descriptions are precise and reflect current functionality
   - Preserve indentation, formatting, and hierarchical structure
   - If major changes occur, update the "Common File Paths" section (starting at line 607) with new shortcuts or references

4. **Check .opencode Directory Changes**:

   - List current commands: `list('.opencode/command')`
   - Compare against git diffs: `git diff HEAD~10..HEAD --name-only` filtered for `.opencode/` paths
   - For new commands: Document in `opencode.instructions.md` under "Custom Commands" and append to the command table in `.opencode/README.md`
   - For deleted commands: Remove from `opencode.instructions.md` and `.opencode/README.md` table; update any cross-references
   - For modified commands: Revise descriptions, examples, and usage in `opencode.instructions.md`
   - Validate frontmatter (description, agent) for accuracy and consistency across files

5. **Verify Consistency**:

   - Confirm examples reference real repository paths (e.g., via `list()`)
   - Update and validate cross-references between instruction files
   - Test commands in examples for functionality (e.g., run sample CLI commands)
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

6. **Update AGENTS.md**:
   - Incorporate new build commands if the process has evolved
   - Refine code style guidelines for newly identified patterns
   - Expand "Bad Practices" with common pitfalls from recent changes

## What to Look For

- **New packages/files**: Document in `gopls.instructions.md` and update the Repository Structure tree in `filesystem.instructions.md`
- **Directory reorgs**: Reflect in `filesystem.instructions.md` tree and paths
- **New CLI features**: Update examples in `gopls.instructions.md` and `filesystem.instructions.md`
- **New dependencies**: List in `deepwiki.instructions.md` for research
- **Refactors**: Revise code snippets in all relevant files
- **Emerging patterns**: Add to AGENTS.md and specific instruction files
- **Build updates**: Modify commands in AGENTS.md
- **.opencode changes**: Track new/deleted/modified commands, updating `opencode.instructions.md` and `.opencode/README.md`

## Error Handling

### Tool Abort Errors

If tools abort (e.g., due to timeouts or interruptions):

1. **Manual Retry**: Immediately retry the exact same tool call with identical parameters
2. **No Auto-Retry**: System does not handle retries; agent must initiate
3. **Preserve Context**: Use the same inputs to maintain consistency
4. **Fallbacks**: On repeated failures, switch to manual alternatives like incremental file reading or batched operations

**Examples**:

```
# Aborted bash execution
bash("go test -v -race ./...")  # ❌ Aborted
bash("go test -v -race ./...")  # ✅ Manual retry
```

### Additional Error Scenarios

- If git commands fail, verify repository state: `git status`
- For compilation errors, run targeted builds: `go build ./path/to/package`
- If tests fail persistently, isolate issues by package: `go test ./specific/package`

## Output Format

For each updated file, report in this structured format:

1. **Code Changes Summary**: Briefly describe what changed (e.g., "Added new CLI flag for verbose output in commit abc123")
2. **Affected Sections**: Specify which parts of the instruction file require updates (e.g., "Repository Structure tree in filesystem.instructions.md")
3. **Updated Content**: Provide the revised text with examples (e.g., paste the updated tree or code snippet)
4. **Verification**: Confirm examples work (e.g., "Tested CLI flag; output matches expected format. Race tests pass for affected package.")

Prioritize precision, avoid overgeneralization, and ensure all updates align with actual repository state. Use tools proactively to validate before finalizing changes.
