# OpenCode Custom Commands

This directory contains custom commands for OpenCode agents to assist with repository maintenance and development tasks.

## Available Commands

| Command | Description | Usage |
|---------|-------------|-------|
| [`update-knowledge`](./command/update-knowledge.md) | Update agent instruction files when code changes | `/update-knowledge` |
| [`test`](./command/test.md) | Run tests with coverage and analyze failures | `/test` |
| [`test-capabilities`](./command/test-capabilities.md) | Test agent capabilities including MCP servers and built-in tools | `/test-capabilities` |
| [`create-changelog`](./command/create-changelog.md) | Generate changelog by comparing tags against master and save to temporary file | `/create-changelog` |

## Command Usage

Commands are invoked in OpenCode sessions using the `/command-name` syntax:

```
/test
/update-knowledge
/test-capabilities
/create-changelog
```

## Command Structure

Each command is defined in a markdown file with:

```markdown
---
description: Brief description of what the command does
agent: general
---

# Command Title

Detailed instructions for the agent...
```

## Creating New Commands

1. Create a new markdown file in `command/` directory
2. Add frontmatter with `description`, `agent`, and `model`
3. Write detailed instructions for the agent
4. Include specific tasks, expected outputs, and examples
5. Reference repository-specific patterns from AGENTS.md

## Command Best Practices

- **Be specific**: Include exact commands to run, file paths to check
- **Reference guidelines**: Point to AGENTS.md and instruction files
- **Expected output**: Define clear output format for agent responses
- **Repository context**: Use actual file paths and package names
- **Actionable**: Focus on concrete tasks the agent can perform

## Integration with Instructions

Commands work alongside instruction files:

- **AGENTS.md**: High-level guidelines and conventions
- **.github/instructions/*.md**: Detailed tool-specific instructions
- **.opencode/command/*.md**: Task-specific workflows

Commands should reference and follow patterns from instruction files.

## Example Workflows

### After Making Code Changes
```
1. /update-knowledge
2. /test
3. /test-capabilities
```

### Before Releases
```
/create-changelog
```

### Verifying Changes
```
/test
/update-knowledge
```

## Notes

- Commands run with full access to repository tools (Gopls, DeepWiki, filesystem tools)
- Commands follow repository guidelines from AGENTS.md automatically
- Command output should be concise and actionable
- Commands can use all available MCP servers and built-in tools
