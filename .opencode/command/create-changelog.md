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
   - Determine the main branch name (`main` or `master`): `git branch --show-current`
   - Get the comparison range: `[latest_tag]..[main_branch]`

2. **Get Commit Information**:

   - Get commits between tag and main: `git log [latest_tag]..[main_branch] --oneline`
   - Get detailed commit messages with bodies: `git log [latest_tag]..[main_branch] --pretty=format:"[SHA - %h]: %s%n%n%b%n"`
   - Get files changed: `git diff [latest_tag]..[main_branch] --name-only`
   - Get commit statistics: `git diff [latest_tag]..[main_branch] --stat`

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
   - Use absolute path: `/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/changelog.md`
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

## Output Format

The changelog should follow Keep a Changelog format with:

- Clear version number and release date
- Categorized changes with emojis for visual clarity
- Links to individual commits
- Statistics summary
- Prominent display of breaking changes

## Error Handling

### Tool Abort Errors

When tools are aborted during execution:

1. **Manual Retry Required**: Manually retry the same command
2. **No Automatic Recovery**: System does NOT retry aborted tools
3. **Context Preservation**: Use identical parameters when retrying
4. **Failure Strategy**: Use alternative approaches if retry fails

**Examples**:

```bash
# Git command aborted
git log --oneline v0.3.0..main  # ❌ Aborted
git log --oneline v0.3.0..main  # ✅ Retry

# If retry fails, use smaller chunks
git log --oneline v0.3.0..HEAD | head -20
git log --oneline v0.3.0~20..HEAD | head -20
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
- **Commit Analysis**: Use both commit subject and body for accurate categorization
- **Link Format**: Use full GitHub URLs for commit links
- **Version Format**: Follow semantic versioning (x.y.z)
- **Date Format**: Use ISO date format (YYYY-MM-DD)
- **Breaking Changes**: Always include migration instructions
- **Statistics**: Provide meaningful metrics about the release
- **Verification**: Cross-check that all file changes are represented in the changelog

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
/home/h0llyw00dzz/Workspace/git/tls-cert-chain-resolver/changelog.md
```

Focus on creating actionable, informative changelogs that help users understand what changed and why.
