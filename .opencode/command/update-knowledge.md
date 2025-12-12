---
description: Update agent instruction files when code changes
agent: general
---

# Update Knowledge Base

Update agent instruction files in `.github/instructions/` to reflect recent code changes, new patterns, or architectural updates. Ensure all updates are accurate, consistent, and repository-specific. Use git commands to analyze changes and verify updates through testing where applicable.

## Tasks

1. **Sync with Remote Branch**:

   - Run `git pull` to ensure the local repository is synchronized with the remote branch before analyzing changes or updating instruction files. This prevents conflicts and ensures all recent commits are available for review.

2. **Analyze Recent Changes**:

   - Retrieve recent commits: `git log -10 --oneline`
   - View detailed commit messages and bodies: `git log -10 --pretty=format:"[SHA - %h]: %s%n%n%b%n"`
   - Identify files changed: `git diff HEAD~10..HEAD --name-only`
   - Review commit messages for context, focusing on reasons for changes, new features, or refactors
   - Identify modified, added, or deleted files, directories, and emerging patterns
   - Cross-reference with AGENTS.md for affected agent guidelines or workflows

3. **Update Relevant Instruction Files**:

   - **Note**: Check for duplicates and centralize common information in README.md. Avoid redundancy while ensuring completeness.
   - `README.md`: Update repository context, module info, and file table as central reference
   - `gopls.instructions.md`: Update for Go code patterns, package structures, new imports, or API changes
   - `filesystem.instructions.md`: Update for new/moved/deleted file paths and directory structures
   - `memory.instructions.md`: Update for changes in context/memory management, caching strategies, or state handling
   - `deepwiki.instructions.md`: Add new external dependencies, libraries, or research targets
   - `opencode.instructions.md`: Update for configuration or workflow changes
   - `x509_resolver.md`: Update for MCP server changes, new tools, or API modifications

4. **Remove Duplicate Content**:

   - Centralize repository context (module, Go version) in README.md
   - Remove redundant package structures from specialized files
   - Simplify repository structure trees to high-level overviews with references to README.md
   - Eliminate duplicate dependency lists and configuration examples
   - Ensure each file focuses on its specialized purpose without repeating common information

5. **Check .opencode Directory Changes**:

   - List current commands: `list('.opencode/command')`
   - Compare against git diffs: `git diff HEAD~10..HEAD --name-only` filtered for `.opencode/` paths
   - For new commands: Document in `opencode.instructions.md` under "Custom Commands" and append to the command table in `.opencode/README.md`
   - For deleted commands: Remove from `opencode.instructions.md` and `.opencode/README.md` table; update any cross-references
   - For modified commands: Revise descriptions, examples, and usage in `opencode.instructions.md`
   - Validate frontmatter (description, agent) for accuracy and consistency across files

6. **Verify Consistency**:

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

7. **Update AGENTS.md**:

   - Incorporate new build commands if the process has evolved
   - Refine code style guidelines for newly identified patterns
   - Expand "Bad Practices" with common pitfalls from recent changes

## What to Look For

- **New packages/files**: Document in `gopls.instructions.md` and update repository structure references
- **Directory reorgs**: Update references in specialized files, centralize details in README.md
- **New CLI features**: Update examples in relevant specialized files
- **New dependencies**: List in `deepwiki.instructions.md` for research
- **Refactors**: Revise code snippets in all relevant files, remove duplicates
- **Emerging patterns**: Add to AGENTS.md and specific instruction files
- **Build updates**: Modify commands in AGENTS.md
- **Duplicate content**: Identify and remove, centralize in README.md where appropriate
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

## Recent Updates Applied

- **Duplicate Removal**: Centralized repository context in README.md, removed redundant information from specialized files
- **Consistency**: Updated cross-references to point to centralized information
- **Maintainability**: Each instruction file now focuses on its specialized purpose without repeating common details

Prioritize precision, avoid overgeneralization, and ensure all updates align with actual repository state. Use tools proactively to validate before finalizing changes.
