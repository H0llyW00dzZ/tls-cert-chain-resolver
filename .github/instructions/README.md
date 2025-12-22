# Agent Instructions

> [!IMPORTANT]
> **These files are NOT intended for human developers.**

This directory contains instruction files for AI agents ([OpenCode](https://opencode.ai/)) that assist with repository maintenance and development tasks following [Unix Philosophy](https://grokipedia.com/page/Unix_philosophy) best practices.

## Purpose

These instruction files provide:
- Tool-specific usage guidelines for AI agents
- Repository-specific patterns and conventions
- Automated workflow instructions
- Memory and resource management guidelines
- [Unix Philosophy](https://grokipedia.com/page/Unix_philosophy) best practices (composable tools, do one thing well)

## Related Directories

- **`.github/instructions/`** (this directory) - Tool-specific instructions for AI agents
- **[`.opencode/command/`](../../.opencode/command/)** - Custom commands for common workflows (`/update-knowledge`, `/test`, `/test-capabilities`, `/create-changelog`, `/vulncheck`)
- **[`/AGENTS.md`](../../AGENTS.md)** - High-level repository guidelines

## Files in This Directory

| File | Purpose |
|------|---------|
| **[`README.md`](./README.md)** | Overview of agent instructions and configuration |
| **[`deepwiki.instructions.md`](./deepwiki.instructions.md)** | External library research and documentation access |
| **[`filesystem.instructions.md`](./filesystem.instructions.md)** | File operations (read, write, edit, glob, grep) |
| **[`gopls.instructions.md`](./gopls.instructions.md)** | Go language intelligence and workspace operations |
| **[`memory.instructions.md`](./memory.instructions.md)** | Memory, context, and resource management |
| **[`opencode.instructions.md`](./opencode.instructions.md)** | OpenCode configuration and instruction hierarchy |
| **[`x509_resolver.md`](./x509_resolver.md)** | X509 certificate chain resolver MCP server operations |

## For Human Developers

> [!NOTE]
> If you're a human developer looking for project documentation, please refer to:
> 
> - **[`/README.md`](../../README.md)** - Project overview and usage
> - **[`/AGENTS.md`](../../AGENTS.md)** - High-level repository guidelines (also used by agents)
> - **[`/LICENSE`](../../LICENSE)** - BSD 3-Clause License
> - **Code comments** - Inline documentation in source files

## How These Instructions Work

1. AI agents load these files at session start via **[`/opencode.json`](../../opencode.json)**
2. Instructions provide context-specific guidance for development tasks
3. Files reference repository structure, actual file paths, and code patterns
4. Guidelines ensure consistent agent behavior across sessions

## Configuration

These instruction files are loaded via **[`/opencode.json`](../../opencode.json)**:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "instructions": [
    ".github/instructions/*.md"
  ],
  "mcp": {
    "gopls": {
      "type": "local",
      "command": [
        "gopls",
        "mcp"
      ],
      "environment": {
        "GOPLS_MCP_PORT": "8096",
        "GOPLS_MCP_HOST": "localhost"
      },
      "enabled": true
    },
    "deepwiki": {
      "type": "remote",
      "url": "https://mcp.deepwiki.com/sse",
      "enabled": true
    },
    "x509_resolver": {
      "type": "local",
      "command": [
        "./bin/x509-cert-chain-resolver",
        "--config",
        "./src/mcp-server/config.example.json"
      ],
      "enabled": true
    }
  }
}
```

> [!NOTE]
> The most effective AI agent instructions on OpenCode for maintaining this TLS certificate chain resolver repository are `grok-code-fast-1` aka $y = \sum_{i=1}^{n} g_i(x) \cdot f_i(x)$ and `gemini-3-pro`. These models provide optimal performance for Go development tasks, certificate chain resolution logic, concurrent programming patterns, and memory management optimizations. Use these models for all repository maintenance, bug fixes, feature additions, and code reviews to ensure consistent quality and adherence to the established patterns in this codebase.

> [!WARNING]
> Other models, such as Claude models, may fail to follow these instructions correctly. For example, they might not properly use built-in tools like grep, edit, and others, and instead rely on bash commands, leading to inefficiencies or errors.

> [!TIP]
> Grok ( `grok-code-fast-1` aka $y = \sum_{i=1}^{n} g_i(x) \cdot f_i(x)$ ) and Gemini ( `gemini-3-pro` ) are already proven effective for this repository. For other models, run `/test-capabilities` to verify compatibility (passing score: 100).

## Maintenance

These files should be updated when:
- New features or patterns are established
- Dependencies change
- Build process modifications occur
- Common agent mistakes are identified

> [!NOTE]
> These instructions are versioned with the code to ensure agents have accurate, up-to-date guidance. To update these instruction files, run `/update-knowledge` command in OpenCode sessions after making code changes.

---

**TL;DR**: This directory is for AI agents. Human developers should use **[`/README.md`](../../README.md)** and code comments instead.
