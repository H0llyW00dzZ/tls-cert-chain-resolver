# x509-cert-chain-resolver

Model Context Protocol (MCP) server that exposes X.509 certificate operations to AI assistants and automation clients over stdio.

## Installation

Install with Go 1.25.5 or later:

```bash
go install github.com/H0llyW00dzZ/tls-cert-chain-resolver/cmd/x509-cert-chain-resolver@latest
```

Or build from source:

```bash
make build-mcp-linux      # or build-mcp-macos / build-mcp-windows
```

## Usage

```bash
x509-cert-chain-resolver [FLAGS]
```

### Flags

| Flag | Description |
|------|-------------|
| `--config` (`-c`) | Path to MCP server configuration file (JSON or YAML) |
| `--instructions` (`-i`) | Display certificate operation workflows and MCP server usage |
| `--help` | Show help information |
| `--version` | Show version information |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `X509_AI_APIKEY` | API key for AI-backed certificate analysis (optional) |
| `MCP_X509_CONFIG_FILE` | Path to configuration file (alternative to `--config` flag) |

## Examples

Start MCP server with default configuration:

```bash
x509-cert-chain-resolver
```

Load custom configuration (JSON or YAML):

```bash
x509-cert-chain-resolver -c /path/to/config.json
x509-cert-chain-resolver -c /path/to/config.yaml
```

Show certificate operation workflows:

```bash
x509-cert-chain-resolver -i
```

## MCP Tools

| Tool | Purpose |
|------|---------|
| `resolve_cert_chain` | Build a full chain from a certificate file or base64 payload |
| `validate_cert_chain` | Verify trust relationships and highlight validation issues |
| `check_cert_expiry` | Report upcoming expirations with configurable warning windows |
| `batch_resolve_cert_chain` | Resolve multiple certificates in a single call |
| `fetch_remote_cert` | Retrieve chains directly from TLS endpoints (HTTPS, SMTP, IMAP, etc.) |
| `visualize_cert_chain` | Visualize certificate chains in ASCII tree, table, or JSON formats |
| `analyze_certificate_with_ai` | Delegate structured certificate analysis to a configured LLM |
| `get_resource_usage` | Monitor server resource usage (memory, GC, system info) in JSON or markdown format |

## MCP Resources

| Resource | Purpose |
|----------|---------|
| `config://template` | Server configuration template |
| `info://version` | Version and capabilities info |
| `docs://certificate-formats` | Certificate format documentation |
| `status://server-status` | Current server health status |

## MCP Prompts

| Prompt | Purpose |
|--------|---------|
| `certificate-analysis` | Comprehensive certificate chain analysis workflow |
| `expiry-monitoring` | Monitor certificate expiration dates and generate renewal alerts |
| `security-audit` | Perform comprehensive SSL/TLS security audit on a server |
| `troubleshooting` | Troubleshoot common certificate and TLS issues |
| `resource-monitoring` | Monitor server resource usage and performance metrics |

## Configuration

The MCP server supports both JSON and YAML configuration formats. The format is auto-detected based on file extension.

**JSON format**:

```json
{
  "defaults": {
    "warnDays": 30,
    "timeoutSeconds": 30,
    "batchConcurrency": 10
  },
  "ai": {
    "apiKey": "",
    "endpoint": "https://api.x.ai",
    "model": "grok-4-1-fast-non-reasoning",
    "timeout": 30,
    "maxTokens": 4096,
    "temperature": 0.3
  }
}
```

**YAML format**:

```yaml
defaults:
  warnDays: 30
  timeoutSeconds: 30
  batchConcurrency: 10

ai:
  apiKey: ""  # Set via X509_AI_APIKEY environment variable
  endpoint: https://api.x.ai
  model: grok-4-1-fast-non-reasoning
  timeout: 30
  maxTokens: 4096
  temperature: 0.3
```

## AI-Assisted Analysis

Set `X509_AI_APIKEY` or configure the `ai` section of the MCP config to allow the server to request completions from xAI Grok (default), OpenAI, or any OpenAI-compatible API. Responses include:

- Validation status and trust insights
- Cryptographic details (algorithms, key sizes, signatures)
- Compliance and risk summaries
- Actionable remediation guidance

## Instructions for MCP Clients

For MCP clients that don't have a built-in instruction mechanism to automatically pass server instructions into the system prompt, you can manually copy the instructions:

```bash
x509-cert-chain-resolver -i > X509_instructions.md
```

Then, include the contents of `X509_instructions.md` in your AI agent's instruction field.

## Security Considerations

The remote fetcher sets `InsecureSkipVerify` on its TLS dialer so it can capture every handshake certificate without relying on the sandbox trust store. No verification is performed during that session; always validate the returned chain (for example with `validate_cert_chain`) before treating the endpoint as trusted.

## Related

- [tls-cert-chain-resolver](../tls-cert-chain-resolver/) - CLI tool for certificate chain resolution
- [adk-go](../adk-go/) - Google ADK integration example
- [Module Documentation](https://pkg.go.dev/github.com/H0llyW00dzZ/tls-cert-chain-resolver) - Full API reference

## License

BSD 3-Clause License. See [LICENSE](../../LICENSE).
