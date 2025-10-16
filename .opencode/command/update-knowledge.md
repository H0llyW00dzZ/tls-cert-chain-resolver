---
description: Update agent instruction files when code changes
agent: general
---

# Update Knowledge Base

Update agent instruction files in `.github/instructions/` to reflect recent code changes, new patterns, or architectural updates.

## Tasks

1. **Analyze Recent Changes**:
   - Check git log for recent commits: `git log -10 --oneline`
   - View detailed commit messages: `git log -10 --pretty=format:"[SHA - %h]: %s%n%b%n"`
   - Check files changed in recent commits: `git diff HEAD~10..HEAD --name-only`
   - Review commit messages for context on why changes were made
   - Identify modified files and new patterns
   - Review AGENTS.md for affected guidelines

2. **Update Relevant Instruction Files**:
   - `gopls.instructions.md` - Go code patterns, package structure changes
   - `filesystem.instructions.md` - New file paths, directory structure changes
   - `memory.instructions.md` - Context/memory management pattern changes
   - `deepwiki.instructions.md` - New external dependencies
   - `opencode.instructions.md` - Configuration or workflow changes

3. **Verify Consistency**:
   - Ensure examples use actual file paths from repository
   - Update cross-references between instruction files
   - Verify commands in examples work correctly
   - Check that code examples compile

4. **Update AGENTS.md**:
   - Add new commands if build process changed
   - Update code style guidelines for new patterns
   - Add common mistakes to "Bad Practices" section

## What to Look For

- **New packages or files**: Update gopls.instructions.md with new package structure
- **New CLI flags/commands**: Update examples in gopls.instructions.md and filesystem.instructions.md
- **New dependencies**: Update deepwiki.instructions.md with new libraries to research
- **Refactored code**: Update code examples across all instruction files
- **New patterns**: Add to AGENTS.md and relevant specific instruction files
- **Build changes**: Update commands in AGENTS.md

## Error Handling

### Tool Abort Errors

When tools are aborted during execution (e.g., due to timeout, resource constraints, or interruption):

1. **Manual Retry Required**: Agent must manually retry the tool call with the same parameters
2. **No Automatic Recovery**: The system does NOT automatically retry aborted tools
3. **Context Preservation**: Use identical input parameters when retrying
4. **Failure Strategy**: If retry also fails, use alternative approaches (e.g., windowed reading, batch operations)

**Examples**:

```
# Bash command aborted
bash("go test -v ./...")  # ❌ Aborted (timeout)
bash("go test -v ./...")  # ✅ Retry with same command
```

## Output Format

For each updated instruction file, provide:
1. What changed in the code
2. Which sections of the instruction file need updates
3. Updated content with specific examples
4. Verification that examples work

Focus on keeping instructions accurate and repository-specific.
