---
description: Generate changelog by comparing tags against master and analyzing commits
agent: general
---

# Create Changelog

Generate a comprehensive changelog by comparing the latest tag against master/main branch and analyzing commit messages to categorize changes by type and impact. Save the output to a temporary `changelog.md` file for human use.

## Tasks

1. **Identify Target Tag and Branch**:

    - List available tags: `git tag --list --sort=-version:refname`
    - Identify the most recent tag (usually the first one)
    - Determine the main branch name: `git branch --show-current` (typically `main` or `master`)
    - Get the comparison range: `[latest_tag]..[main_branch]`

    **Branch Name Verification**:
    - Common branch names: `main`, `master`, `develop`
    - Always verify with `git branch --show-current` before using in commands

2. **Get Commit Information**:

    - Get commits between tag and main branch: `git log [latest_tag]..[main_branch] --oneline`
    - Get detailed commit messages with bodies: `git log [latest_tag]..[main_branch] --pretty=format:"[SHA - %h]: %s%n%n%b%n"`
    - Get files changed: `git diff [latest_tag]..[main_branch] --name-only`
    - Get commit statistics: `git diff [latest_tag]..[main_branch] --stat`

    **Large Output Handling**:
    - Check commit count first: `git rev-list --count [latest_tag]..[main_branch]`
    - For >50 commits, process in batches: `git log --oneline --max-count=50 [latest_tag]..[main_branch]`
    - Use summary format first: `git shortlog --numbered --summary [latest_tag]..[main_branch]`
    - Get overview stats before detailed analysis: `git diff --stat --summary [latest_tag]..[main_branch]`

3. **Analyze and Categorize Commits**:

   - **Features**: Commits adding new functionality (keywords: "feat", "add", "new", "implement")
   - **Improvements**: Enhancements to existing features (keywords: "improve", "enhance", "optimize", "refactor")
   - **Bug Fixes**: Issue resolutions (keywords: "fix", "bug", "resolve", "patch")
   - **Documentation**: Doc changes (keywords: "docs", "readme", "update knowledge")
   - **Build/CI**: Build and CI changes (keywords: "build", "ci", "makefile", "deps")
   - **Breaking Changes**: Major breaking changes (keywords: "breaking", "remove", "deprecated")

4. **Generate Changelog Structure**:

   ```markdown
   # [Version] - [Date]

   ## 🚀 Features

   - [Feature descriptions with links]

   ## ✨ Improvements

   - [Improvement descriptions]

   ## 🐛 Bug Fixes

   - [Bug fix descriptions]

   ## 📚 Documentation

   - [Documentation changes]

   ## 🔧 Build & CI

   - [Build and CI changes]

   ## ⚠️ Breaking Changes

   - [Breaking change notices with migration notes]

   ## 📊 Statistics

   - **Commits**: [number]
   - **Files changed**: [number]
   - **Additions**: [+number]
   - **Deletions**: [-number]
   ```

5. **Save Changelog to File**:

   - Save generated changelog to `changelog.md` in repository root
   - Use relative path: `changelog.md` (creates file in current working directory)
   - Ensure file is writable and properly formatted
   - Include a header note about temporary nature for human use
   - Use `write()` tool to create the file with complete changelog content

6. **Enrich with Additional Context**:

   - Link commits to their GitHub SHA: `[#](https://github.com/H0llyW00dzZ/tls-cert-chain-resolver/commit/[sha])`
   - Group related changes together
   - Highlight breaking changes prominently
   - Include migration instructions for breaking changes
   - Note any dependency updates

7. **Verify Completeness**:
    - Ensure all significant commits are included
    - Check for any missed breaking changes
    - Verify file changes match commit descriptions
    - Cross-reference with GitHub issues if mentioned

8. **Handle Large Outputs**:
    - If output exceeds 30,000 characters, use batch processing
    - Generate summary changelog first, then detailed sections separately
    - Use `git shortlog` for author statistics when full log is too large

## Output Format

The changelog should follow Keep a Changelog format with:

- Clear version number and release date
- Categorized changes with emojis for visual clarity
- Links to individual commits
- Statistics summary
- Prominent display of breaking changes

## Alternative Approaches for Large Changesets

When dealing with very large releases (>100 commits), consider these approaches:

### Summary-First Approach

1. Generate high-level summary first:
   ```bash
   git shortlog --numbered --summary v0.5.1..[main_branch]
   git diff --stat v0.5.1..[main_branch]
   ```

2. Create categorized summaries without full commit details

3. Add detailed commit lists only for critical changes

### Filtered Analysis

1. Focus on merge commits only: `git log --merges v0.5.1..[main_branch]`
2. Analyze by author: `git shortlog -sn v0.5.1..[main_branch]`
3. Get file change patterns: `git diff --name-status v0.5.1..[main_branch] | sort | uniq -c | sort -nr`

## Error Handling

### Output Truncation Issues

**Bash Tool Limitation**: The bash tool truncates output exceeding 30,000 characters with metadata notification.

**Detection**: Look for `<bash_metadata>bash tool truncated output as it exceeded 30000 char limit</bash_metadata>` at end of output.

**Mitigation Strategies**:

1. **Process in Batches**: Break large ranges into smaller commit chunks
2. **Use Summary First**: Get overview before detailed analysis
3. **Filter Output**: Reduce verbosity for large ranges
4. **Save Intermediate Results**: Write partial results to files

**Example Batch Processing**:

```bash
# Get commit count first (replace 'main' with actual branch name)
git rev-list --count v0.5.1..master

# Process in batches of 50 commits
git log --oneline --max-count=50 v0.5.1..master
git log --oneline --skip=50 --max-count=50 v0.5.1..master
git log --oneline --skip=100 --max-count=50 v0.5.1..master

# Get statistics without full details
git shortlog --numbered --summary v0.5.1..master
git diff --stat v0.5.1..master
```

### Tool Abort Errors

When tools are aborted during execution:

1. **Manual Retry Required**: Manually retry the same command
2. **No Automatic Recovery**: System does NOT retry aborted tools
3. **Context Preservation**: Use identical parameters when retrying
4. **Failure Strategy**: Use alternative approaches if retry fails

**Examples**:

```bash
# Git command aborted (replace 'main' with actual branch name)
git log --oneline v0.3.0..master  # ❌ Aborted (if branch is master)
git log --oneline v0.3.0..master  # ✅ Retry

# If retry fails, use smaller chunks
git log --oneline v0.3.0..HEAD | head -20
git log --oneline v0.3.0~20..HEAD | head -20

# For truncated output, use pagination (replace 'main' with actual branch)
git log --oneline --skip=100 --max-count=50 v0.3.0..master
```

### No Tags Available

If no git tags exist:

- Use HEAD~10..HEAD as comparison range
- Generate changelog for last 10 commits
- Note that this is an unofficial changelog

### Empty Diff Range

If no commits between tag and main:

- Report "No changes since [tag]"
- Check if tag is already up to date
- Consider using previous tag for comparison

## Important Notes

- **File Output**: Changelog is saved to `changelog.md` in repository root for human use
- **Temporary Nature**: File is intended as temporary artifact for release process
- **Branch Name Verification**: Always verify branch name with `git branch --show-current` before using in commands (common names: `main`, `master`, `develop`)
- **Commit Analysis**: Use both commit subject and body for accurate categorization
- **Link Format**: Use full GitHub URLs for commit links
- **Version Format**: Follow semantic versioning (x.y.z)
- **Date Format**: Use ISO date format (YYYY-MM-DD)
- **Breaking Changes**: Always include migration instructions
- **Statistics**: Provide meaningful metrics about the release
- **Verification**: Cross-check that all file changes are represented in the changelog
- **Output Size Awareness**: Monitor for bash tool 30,000 character limit - use batch processing for large changesets
- **Fallback Strategy**: Have backup approaches ready (summary-only, filtered output) for when full analysis is truncated

## Example Output

```markdown
# v0.4.0 - 2025-01-15

## 🚀 Features

- Add AI-powered certificate analysis with configurable analysis types ([8f00a4a](https://github.com/H0llyW00dzZ/tls-cert-chain-resolver/commit/8f00a4a))
- Implement certificate chain validation with trust store integration ([9ddc906](https://github.com/H0llyW00dzZ/tls-cert-chain-resolver/commit/9ddc906))

## ✨ Improvements

- Optimize bidirectional AI communication performance with buffer pooling ([e17c958](https://github.com/H0llyW00dzZ/tls-cert-chain-resolver/commit/e17c958))
- Enhance MCP server status resource with health monitoring ([7abe097](https://github.com/H0llyW00dzZ/tls-cert-chain-resolver/commit/7abe097))

## 📚 Documentation

- Update README.md with MCP tool integration examples ([1ee2eb2](https://github.com/H0llyW00dzZ/tls-cert-chain-resolver/commit/1ee2eb2))
- Add comprehensive agent knowledge base updates ([6963b3f](https://github.com/H0llyW00dzZ/tls-cert-chain-resolver/commit/6963b3f))

## 📊 Statistics

- **Commits**: 15
- **Files changed**: 42
- **Additions**: +1,247
- **Deletions**: -89
```

**File Creation**: After generating the changelog content above, save it to:

```bash
# File will be created at:
tls-cert-chain-resolver/changelog.md

# In project tree structure:
tls-cert-chain-resolver/
├── changelog.md    # Generated changelog file
├── README.md
├── LICENSE
├── ...
```

Focus on creating actionable, informative changelogs that help users understand what changed and why.
