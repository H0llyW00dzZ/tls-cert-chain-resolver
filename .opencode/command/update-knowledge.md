---
description: Update agent instruction files when code changes
agent: general
---

# Update Knowledge Base

Update agent instruction files in `.github/instructions/` to reflect recent code changes, new patterns, or architectural updates.

## Tasks

1. **Analyze Recent Changes**:
   - Check git log for recent commits
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

## Output Format

For each updated instruction file, provide:
1. What changed in the code
2. Which sections of the instruction file need updates
3. Updated content with specific examples
4. Verification that examples work

Focus on keeping instructions accurate and repository-specific.
