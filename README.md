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
  - [Google ADK Integration](#google-adk-integration)
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
- Rich certificate chain visualization: ASCII tree diagrams, markdown tables, and JSON exports
- Efficient memory usage via reusable buffer pools
- Standalone MCP server with composable tools for automation workflows
- Optional AI-powered certificate analysis using bidirectional sampling

## Quick Start

Install the CLI with Go 1.25.5 or later:

```bash
go install github.com/H0llyW00dzZ/tls-cert-chain-resolver@latest
```

Run against a certificate file:

```bash
tls-cert-chain-resolver -f cert.pem -o chain.pem
```

Visualize certificate chains:

```bash
tls-cert-chain-resolver -f cert.pem --tree    # ASCII tree diagram
tls-cert-chain-resolver -f cert.pem --table   # Markdown table
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
| `-t, --tree` | Display certificate chain as ASCII tree diagram |
| `--table` | Display certificate chain as markdown table |

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

Visualize certificate chain as ASCII tree:

```bash
tls-cert-chain-resolver -f cert.pem --tree
```

Display certificate chain as markdown table:

```bash
tls-cert-chain-resolver -f cert.pem --table
```

## Model Context Protocol (MCP) Server

The repository includes a first-party MCP server (`cmd/mcp-server`) that exposes certificate operations to AI assistants or automation clients over stdio.

> [!IMPORTANT]
> **Go-Native Implementation**: This MCP server is implemented entirely in Go and leverages Go-specific features that provide superior performance and memory efficiency but limit portability to other programming languages. Key Go-native dependencies include:
>
> - **`embed` package**: Templates and resources are embedded directly into the binary at compile time (configuration is loaded from external files)
> - **Goroutines and channels**: Concurrent request processing with semaphore-based rate limiting (100 concurrent requests)
> - **Buffer pooling**: Custom `gc.Pool` interface for efficient memory reuse in certificate operations and AI streaming
> - **Context management**: Native Go context propagation for cancellation and timeouts
> - **Interface-based design**: Type-safe abstractions that aren't directly translatable to other languages
>
> While this provides excellent performance and reliability, it means the implementation cannot be easily ported to languages like Python, JavaScript, or Java without significant reimplementation effort. Consider this when evaluating MCP server options for multi-language environments.
>
> Learn more about Go's design principles at [Effective Go](https://go.dev/doc/effective_go).

### MCP Tooling

The MCP server provides comprehensive certificate operations powered by Go's efficient crypto libraries and concurrent processing capabilities:

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

**Performance Benefits**: Go's goroutines enable concurrent certificate processing, buffer pooling minimizes memory allocations, and the `embed` package eliminates filesystem dependencies for templates and resources (while allowing runtime configuration loading).

#### MCP Resources

The MCP server provides static resources with annotations and metadata for enhanced client integration:

| Resource | Purpose | Annotations |
|----------|---------|-------------|
| `config://template` | Server configuration template | User/Assistant access, priority 1.0 |
| `info://version` | Version and capabilities info | User/Assistant access, priority 0.8 |
| `docs://certificate-formats` | Certificate format documentation | User/Assistant access, priority 0.9 |
| `status://server-status` | Current server health status | User/Assistant access, priority 0.7 |

All resources include metadata for categorization and read-only status.

#### MCP Prompts

The MCP server provides structured prompts with metadata for guided certificate analysis workflows:

| Prompt | Purpose | Required Args | Metadata |
|--------|---------|---------------|----------|
| `certificate-analysis` | Comprehensive certificate chain analysis workflow | certificate_path | category: "analysis", workflow: "comprehensive" |
| `expiry-monitoring` | Monitor certificate expiration dates and generate renewal alerts | certificate_path | category: "monitoring", workflow: "renewal" |
| `security-audit` | Perform comprehensive SSL/TLS security audit on a server | hostname | category: "security", workflow: "audit" |
| `troubleshooting` | Troubleshoot common certificate and TLS issues | issue_type | category: "support", workflow: "diagnostic" |

All prompts include metadata for categorization and workflow identification.

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

### Google ADK Integration

This project supports [`adk-go`](https://github.com/google/adk-go) integration, which leverages AI to perform tasks with human-like capabilities. For example, it is possible to let AI play games or execute complex autonomous workflows using the provided tools.

> [!NOTE]
> The [`adk-go`](https://github.com/google/adk-go) integration is a powerful AI framework with minimal vendor lock-in. It enables the creation of AI agents capable of performing human-like tasks (e.g., playing games), offering greater flexibility compared to other frameworks (e.g., Claude Code/Claude Desktop) that often enforce stricter vendor lock-in, limiting provider choices.

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

Run the full suite with race detection and coverage:

```bash
go test -race -cover ./... 2>&1 | cat
```

Additional targets are available in `Makefile`, including race detection and platform-specific builds.

### Project Layout

```
tls-cert-chain-resolver/
├── cmd/
│   ├── adk-go/           # Google ADK integration example
│   ├── run.go            # CLI entry point
│   └── mcp-server/
│       └── run.go        # MCP server entry point
├── src/
│   ├── cli/              # Cobra-based CLI implementation
│   ├── internal/
│   │   ├── helper/
│   │   │   ├── gc/       # Buffer pooling utilities
│   │   │   └── jsonrpc/  # JSON-RPC 2.0 normalization utilities
│   │   └── x509/
│   │       ├── certs/    # Certificate encoding/decoding helpers
│   │       └── chain/    # Chain resolution, revocation logic, and visualization
│   ├── logger/           # Thread-safe logging abstraction
│   ├── mcp-server/       # MCP server framework, tools, prompts, resources
│   └── version/          # Build metadata
└── tools/
    └── codegen/          # Code generation tool for MCP server resources, tools, and prompts
        ├── run.go        # Main entry point
        ├── internal/
        │   ├── codegen.go      # Core generation logic
        │   └── codegen_test.go # Codegen tests for parameter validation
        ├── config/
        │   ├── prompts.json          # Prompt definitions
        │   ├── prompts.schema.json   # JSON schema for prompt validation
        │   ├── resources.json        # Resource definitions
        │   ├── resources.schema.json # JSON schema for resource validation
        │   ├── tools.json            # Tool definitions
        │   └── tools.schema.json     # JSON schema for tool validation
        ├── templates/
        │   ├── resources.go.tmpl  # Resources template
        │   ├── tools.go.tmpl      # Tools template
        │   └── prompts.go.tmpl    # Prompts template
        └── README.md      # Codegen documentation
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
- [x] **Add certificate chain visualization tool** with ASCII tree, table, and JSON output formats
- [x] Integrate with [`google.golang.org/adk`](https://github.com/google/adk-go) (adk-go) for MCP transport creation
- [x] Create abstraction layer for both MCP libraries (mark3labs server + ADK transport bridge)
- [x] Improve internal package documentation and API consistency in `src/internal/`

##### Remaining (Low Priority)

- [ ] Maintain compatibility with `github.com/mark3labs/mcp-go` (ongoing)
- [ ] Document differences and use cases for each library

##### [X.509](https://grokipedia.com/page/X.509) Operations Roadmap

- [ ] Implement streaming support for large certificate chains
- [x] Add OCSP/CRL revocation status checks to MCP tools
- [ ] Improve certificate chain visualization tool to support output image formats such as .png
- [ ] Evaluate post-quantum signature support (e.g., hybrid or PQC-only chains)
- [ ] Implement notification mechanism to send to client when GC gets overhead; this implementation requires custom MCP client similar to how adk-go is built on top of MCP
- [ ] Implement MCP tools for AI to clear CRL cache

## Motivation

TLS Cert Chain Resolver is inspired by the unmaintained [`zakjan/cert-chain-resolver`](https://github.com/zakjan/cert-chain-resolver.git) project. This repository aims to provide an actively maintained, memory-conscious implementation with modern tooling support (CLI + MCP + AI sampling).

**Why Go?** This project leverages Go's strengths in systems programming and concurrency to deliver a high-performance, memory-efficient certificate chain resolver. The Go ecosystem provides excellent TLS/crypto libraries and the language's design enables efficient implementations that would be challenging in other languages. However, this Go-native approach means the MCP server implementation is not easily portable to other programming languages.

## License

Licensed under the [BSD 3-Clause License](https://grokipedia.com/page/BSD_licenses#3-clause-license-bsd-license-20-revised-bsd-license-new-bsd-license-or-modified-bsd-license). See [LICENSE](LICENSE).
