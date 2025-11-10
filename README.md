# TLS Cert Chain Resolver

[![Go Reference](https://pkg.go.dev/badge/github.com/H0llyW00dzZ/tls-cert-chain-resolver.svg)](https://pkg.go.dev/github.com/H0llyW00dzZ/tls-cert-chain-resolver)
[![Go Report Card](https://goreportcard.com/badge/github.com/H0llyW00dzZ/tls-cert-chain-resolver)](https://goreportcard.com/report/github.com/H0llyW00dzZ/tls-cert-chain-resolver)
[![codecov](https://codecov.io/gh/H0llyW00dzZ/tls-cert-chain-resolver/graph/badge.svg?token=BO8NEXX170)](https://codecov.io/gh/H0llyW00dzZ/tls-cert-chain-resolver)

TLS Cert Chain Resolver is a Go toolkit for building, validating, and inspecting TLS certificate chains. It ships with a CLI application, a composable [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs/getting-started/intro) server, and helper libraries that emphasize memory efficiency and predictable output formats.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
  - [Flags](#flags)
  - [Examples](#examples)
- [Model Context Protocol (MCP) Server](#model-context-protocol-mcp-server)
  - [MCP Tooling](#mcp-tooling)
  - [Security considerations](#security-considerations)
  - [AI-Assisted Analysis](#ai-assisted-analysis)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Config File](#config-file)
- [Building From Source](#building-from-source)
- [Development](#development)
  - [Testing](#testing)
  - [Project Layout](#project-layout)
  - [TODO List](#todo-list)
  - [MCP Integration Enhancements](#mcp-integration-enhancements)
    - [Completed](#completed)
    - [Remaining (Low Priority)](#remaining-low-priority)
    - [X.509 Operations Roadmap](#x509-operations-roadmap)
- [Motivation](#motivation)
- [License](#license)

## Features

- Deterministic TLS certificate chain resolution with optional system trust roots
- Multiple output formats: PEM, DER, or JSON (structured metadata with PEM payloads)
- Efficient memory usage via reusable buffer pools
- Standalone MCP server with composable tools for automation workflows
- Optional AI-powered certificate analysis using bidirectional sampling

## Quick Start

Install the CLI with Go 1.25.4 or later:

```bash
go install github.com/H0llyW00dzZ/tls-cert-chain-resolver@latest
```

Run against a certificate file:

```bash
tls-cert-chain-resolver -f cert.pem -o chain.pem
```

## CLI Usage

```bash
tls-cert-chain-resolver -f INPUT_CERT [FLAGS]
```

### Flags

| Flag | Description |
|------|-------------|
| `-f, --file` | Input certificate file (PEM, DER, or base64) **required** |
| `-o, --output` | Destination file (default: stdout) |
| `-i, --intermediate-only` | Emit only intermediate certificates |
| `-d, --der` | Output bundle in DER format |
| `-s, --include-system` | Append system trust root (where available) |
| `-j, --json` | Emit JSON summary with PEM-encoded certificates |

> **Tip:** If `go install github.com/H0llyW00dzZ/tls-cert-chain-resolver@latest` fails due to module proxies, use `go install github.com/H0llyW00dzZ/tls-cert-chain-resolver/cmd@latest` or build from source with the provided Makefile targets.

### Examples

Resolve a leaf certificate into a PEM bundle and verify with OpenSSL:

```bash
./bin/linux/tls-cert-chain-resolver -f test-leaf.cer -o test-output-bundle.pem
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
  -untrusted test-output-bundle.pem test-output-bundle.pem
```

Produce JSON output:

```bash
tls-cert-chain-resolver -f cert.pem --json > chain.json
```

## Model Context Protocol (MCP) Server

The repository includes a first-party MCP server (`cmd/mcp-server`) that exposes certificate operations to AI assistants or automation clients over stdio.

### MCP Tooling

| Tool | Purpose |
|------|---------|
| `resolve_cert_chain` | Build a full chain from a certificate file or base64 payload |
| `validate_cert_chain` | Verify trust relationships and highlight validation issues |
| `check_cert_expiry` | Report upcoming expirations with configurable warning windows |
| `batch_resolve_cert_chain` | Resolve multiple certificates in a single call |
| `fetch_remote_cert` | Retrieve chains directly from TLS endpoints (HTTPS, SMTP, IMAP, etc.) |
| `analyze_certificate_with_ai` | Delegate structured certificate analysis to a configured LLM |
| `get_resource_usage` | Monitor server resource usage (memory, GC, system info) in JSON or markdown format |

#### Security considerations

The remote fetcher sets `InsecureSkipVerify` on its TLS dialer so it can capture every handshake certificate without relying on the sandbox trust store. No verification is performed during that session; always validate the returned chain (for example with `VerifyChain`) before treating the endpoint as trusted, since a [man-in-the-middle](https://grokipedia.com/page/Man-in-the-middle_attack) could present an arbitrary certificate set.

Enable the MCP server in `opencode.json` or run manually:

```bash
make build-mcp-linux
./bin/linux/x509-cert-chain-resolver
```

### AI-Assisted Analysis

Set `X509_AI_APIKEY` or configure the `ai` section of the MCP config to allow the server to request completions from xAI Grok (default), OpenAI, or any OpenAI-compatible API. Responses include:

- Validation status and trust insights
- Cryptographic details (algorithms, key sizes, signatures)
- Compliance and risk summaries
- Actionable remediation guidance

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `X509_AI_APIKEY` | API key for AI-backed certificate analysis (optional) |
| `MCP_X509_CONFIG_FILE` | Path to MCP server configuration JSON |

### Config File

Default configuration (`src/mcp-server/config.example.json`):

```json
{
  "defaults": {
    "format": "pem",
    "includeSystemRoot": false,
    "intermediateOnly": false,
    "warnDays": 30,
    "timeoutSeconds": 10
  },
  "ai": {
    "apiKey": "",
    "endpoint": "https://api.x.ai",
    "model": "grok-beta",
    "timeout": 30
  }
}
```

Custom endpoints following the OpenAI chat completions schema are supported.

## Building From Source

```bash
git clone https://github.com/H0llyW00dzZ/tls-cert-chain-resolver.git
cd tls-cert-chain-resolver

make build-linux      # or build-macos / build-windows
make build-mcp-linux  # MCP server binaries
```

Artifacts are written to `./bin/<platform>/`.

## Development

### Testing

Run the full suite:

```bash
go test -v ./... 2>&1 | cat
```

Additional targets are available in `Makefile`, including race detection and platform-specific builds.

### Project Layout

```
cmd/
  run.go            # CLI entry point
  mcp-server/
    run.go          # MCP server entry point
src/
  cli/              # Cobra-based CLI implementation
  internal/x509/
    certs/          # Certificate encoding/decoding helpers
    chain/          # Chain resolution logic
  logger/           # Thread-safe logging abstraction
  mcp-server/       # MCP server framework, tools, prompts, resources
  helper/gc/        # Buffer pooling utilities
  version/          # Build metadata
```

### TODO List

#### MCP Integration Enhancements

##### Completed Tasks

- [x] Create standalone MCP server binary in `src/mcp-server/`
- [x] Add configuration file support for MCP server settings
- [x] Add MCP server tests with mock certificate data
- [x] Add support for certificate validation through MCP tool
- [x] Implement certificate expiry checking via MCP
- [x] Add batch certificate resolution support
- [x] Support for remote certificate fetching via URL/hostname
- [x] Document MCP server deployment options (Docker, systemd, etc.)
- [x] Create example MCP client implementations
- [x] Create MCP server configuration examples
- [x] Add troubleshooting guide for MCP integration
- [x] **Implement bidirectional AI communication** via MCP sampling (servers can request LLM completions from clients)
- [x] Add OCSP/CRL revocation status checks to MCP tools
- [x] **Add resource usage monitoring tool** with JSON and markdown output formats

##### Remaining (Low Priority)

- [ ] Maintain compatibility with `github.com/mark3labs/mcp-go` (ongoing)
- [ ] Create abstraction layer for both MCP libraries
- [ ] Document differences and use cases for each library

##### [X.509](https://grokipedia.com/page/X.509) Operations Roadmap

- [ ] Implement streaming support for large certificate chains
- [x] Add OCSP/CRL revocation status checks to MCP tools
- [ ] Evaluate post-quantum signature support (e.g., hybrid or PQC-only chains)

## Motivation

TLS Cert Chain Resolver is inspired by the unmaintained [`zakjan/cert-chain-resolver`](https://github.com/zakjan/cert-chain-resolver.git) project. This repository aims to provide an actively maintained, memory-conscious implementation with modern tooling support (CLI + MCP + AI sampling).

## License

Licensed under the [BSD 3-Clause License](https://grokipedia.com/page/BSD_licenses#3-clause-license-bsd-license-20-revised-bsd-license-new-bsd-license-or-modified-bsd-license). See [LICENSE](LICENSE).
