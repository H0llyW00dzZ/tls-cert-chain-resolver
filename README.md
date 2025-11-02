# TLS Cert Chain Resolver

[![Go Reference](https://pkg.go.dev/badge/github.com/H0llyW00dzZ/tls-cert-chain-resolver.svg)](https://pkg.go.dev/github.com/H0llyW00dzZ/tls-cert-chain-resolver) [![Go Report Card](https://goreportcard.com/badge/github.com/H0llyW00dzZ/tls-cert-chain-resolver)](https://goreportcard.com/report/github.com/H0llyW00dzZ/tls-cert-chain-resolver)
[![codecov](https://codecov.io/gh/H0llyW00dzZ/tls-cert-chain-resolver/graph/badge.svg?token=BO8NEXX170)](https://codecov.io/gh/H0llyW00dzZ/tls-cert-chain-resolver)

TLS Cert Chain Resolver is a CLI tool designed to resolve and manage TLS certificate chains efficiently. This tool is inspired by [zakjan/cert-chain-resolver](https://github.com/zakjan/cert-chain-resolver.git), but offers a more maintainable codebase and is actively maintained.

## Features

- Resolve TLS certificate chains
- Output in PEM, DER, or JSON format. The JSON format includes PEM-encoded certificates with their chains.
- Optionally include system root CAs
- Efficient memory usage with buffer pooling

## Installation

To install the tool, use the following command:

```bash
go install github.com/H0llyW00dzZ/tls-cert-chain-resolver@latest
```

## Usage

```bash
tls-cert-chain-resolver -f [INPUT_FILE] [FLAGS]
```

### Environment Variables

For AI-powered certificate analysis features:
- `X509_AI_APIKEY`: AI API key for intelligent certificate analysis (optional, can also be configured in config.json)

### AI Configuration

The MCP server supports configurable AI API integration for bidirectional communication:

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
    "apiKey": "your-api-key-here",
    "endpoint": "https://api.x.ai",
    "model": "grok-beta",
    "timeout": 30
  }
}
```

**Supported AI Providers:**
- **xAI** (default): `https://api.x.ai` with Grok models
- **OpenAI**: `https://api.openai.com/v1` with GPT models  
- **Any OpenAI-compatible API**: Custom endpoints that follow OpenAI's chat completions format

### Flags

- `-f, --file`: Input certificate file (required)
- `-o, --output`: Output to a specified file (default: stdout)
- `-i, --intermediate-only`: Output intermediate certificates only
- `-d, --der`: Output in DER format
- `-s, --include-system`: Include root CA from the system in output
- `-j, --json`: Output in JSON format containing PEM for listed certificates with their chains

> [!NOTE]
> If you encounter issues installing with `go install github.com/H0llyW00dzZ/tls-cert-chain-resolver@latest`, try using `go install github.com/H0llyW00dzZ/tls-cert-chain-resolver/cmd@latest` or build manually from source with `make build-linux`, `make build-macos`, or `make build-windows`.

## Development

### Prerequisites

- Go 1.25.3 or later

### Building from Source

Clone the repository:

```bash
git clone https://github.com/H0llyW00dzZ/tls-cert-chain-resolver.git
cd tls-cert-chain-resolver
```

Build the project for Linux:

```bash
make build-linux
```

Build the project for macOS:

```bash
make build-macos
```

Build the project for Windows:

```bash
make build-windows
```

## Compatibility

This tool is compatible with Go 1.25.3 or later and works effectively across various clients (e.g., HTTP clients in Go, mobile browsers, OpenSSL). It resolves chaining issues, providing enhanced flexibility and control over certificate chain resolution.

### Example with OpenSSL:

```bash
h0llyw00dzz@ubuntu-pro:~/Workspace/git/tls-cert-chain-resolver$ ./bin/linux/tls-cert-chain-resolver -f test-leaf.cer -o test-output-bundle.pem
Starting TLS certificate chain resolver (v0.2.5)...
Note: Press CTRL+C or send a termination signal (e.g., SIGINT or SIGTERM) via your operating system to exit if incomplete (e.g., hanging while fetching certificates).
1: *.b0zal.io
2: Sectigo ECC Domain Validation Secure Server CA
3: USERTrust ECC Certification Authority
Output successfully written to test-output-bundle.pem.
Certificate chain complete. Total 3 certificate(s) found.
Certificate chain resolution completed successfully.
TLS certificate chain resolver stopped.
```

- **Verification:**

```bash
h0llyw00dzz@ubuntu-pro:~/Workspace/git/tls-cert-chain-resolver$ openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted test-output-bundle.pem test-output-bundle.pem
test-output-bundle.pem: OK
```
> [!NOTE]
> These examples demonstrate the tool's effectiveness in resolving and verifying certificate chains using OpenSSL.

## MCP Tool Integration

This tool can be integrated with [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs/getting-started/intro) servers for automated certificate chain resolution. The MCP integration allows AI assistants and other tools to resolve TLS certificate chains programmatically, with support for bidirectional AI communication through sampling.

**MCP Server Features:**
- Resolve [X509](https://grokipedia.com/page/X.509) certificate chains from files or remote servers
- Validate certificate chains and check expiry dates
- Support for remote certificate fetching over HTTPS, SMTPS, IMAPS, and any TLS-enabled service
- Batch processing of multiple certificates
- Multiple output formats (PEM, DER, JSON)
- **✅ Bidirectional AI Communication**: MCP sampling allows AI agents to collaborate (servers can request LLM completions from clients)

### Using the MCP Server with Built Binary

You can also integrate with MCP by running the built MCP server binary directly. The MCP server is configured in `opencode.json` to use the local binary:

```json
{
  "mcp": {
    "x509_resolver": {
      "type": "local",
      "command": ["./bin/x509-cert-chain-resolver"],
      "environment": {
        "MCP_X509_CONFIG_FILE": "./src/mcp-server/config.example.json"
      },
      "enabled": true
    }
  }
}
```

To use the MCP server with AI agents:

1. **Build the MCP server binary**:
   ```bash
   make build-mcp-linux  # or build-mcp-macos, build-mcp-windows
   ```

2. **Configure your AI assistant** (like Claude Desktop) to use the MCP server:
    ```json
    {
      "mcpServers": {
        "tls-cert-resolver": {
          "command": "/path/to/tls-cert-chain-resolver/bin/x509-cert-chain-resolver",
          "env": {
            "MCP_X509_CONFIG_FILE": "/path/to/tls-cert-chain-resolver/src/mcp-server/config.example.json",
            "X509_AI_APIKEY": "your-ai-api-key-here"
          }
        }
      }
    }
    ```

3. **Use the tools in your AI assistant**:
    - `fetch_remote_cert`: Fetch certificates from remote servers (supports IMAP, SMTP, HTTPS, etc.)
    - `resolve_cert_chain`: Resolve certificate chains from files
    - `validate_cert_chain`: Validate certificate chain integrity
    - `check_cert_expiry`: Check certificate expiration dates
    - `batch_resolve_cert_chain`: Process multiple certificates
    - **✅ `analyze_certificate_with_ai`**: AI-powered certificate analysis using bidirectional sampling
    - **Sampling**: Request LLM completions from your AI assistant for collaborative analysis

### Using MCP Sampling for AI Collaboration

The MCP server supports bidirectional communication through sampling, allowing AI assistants to request LLM completions from connected clients:

```javascript
// Example: Server requesting analysis from AI assistant
const result = await mcpServer.requestSampling(ctx, {
  messages: [
    { role: "user", content: "Analyze this certificate chain for security issues" }
  ],
  maxTokens: 1000,
  temperature: 0.7
});
```

This enables collaborative workflows where the MCP server can leverage the AI assistant's reasoning capabilities for complex certificate analysis tasks.

**Consistent User-Agent Headers**
Both the CLI certificate resolver and MCP server use consistent User-Agent headers for all HTTP requests:

- **CLI Tool**: `X.509-Certificate-Chain-Resolver/{version} (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)`
- **MCP Server**: `X.509-Certificate-Chain-Resolver-MCP/{version} (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)`

This ensures proper identification and allows servers to distinguish between different components of the tool.

**Bidirectional AI Communication**
The MCP server supports bidirectional communication through the built-in "sampling" mechanism, allowing AI assistants to request LLM completions from connected clients. This enables:

- Distributed certificate validation across different AI models
- Real-time collaboration between agents on security analysis
- Automated escalation of findings to specialized security AI agents
- Dynamic content generation for certificate analysis reports

**AI API Configuration**
The sampling handler supports multiple AI providers through configurable settings:

- **Default**: xAI (Grok models) - no configuration needed
- **OpenAI**: Configure `endpoint` to `https://api.openai.com/v1` and use GPT models
- **Custom**: Any OpenAI-compatible API endpoint

**New Tool: `analyze_certificate_with_ai`**
This tool demonstrates bidirectional AI communication by:
1. Processing certificate data on the server with comprehensive context engineering
2. Building detailed analysis prompts with rich certificate information including:
   - Complete certificate chain structure and roles
   - Detailed cryptographic properties (algorithms, key sizes, signatures)
   - Validity periods and expiry status
   - Subject/Issuer information and extensions
   - Key usage and extended key usage
   - Subject Alternative Names and authority information
   - Chain validation relationships and security context
3. Requesting intelligent analysis from configured AI API via sampling
4. Combining automated certificate data with AI reasoning


## MCP Server Deployment

### Docker Deployment

Create a `Dockerfile` for the MCP server:

```dockerfile
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o mcp-server ./cmd/mcp-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/mcp-server .
COPY --from=builder /app/src/mcp-server/config.example.json ./config.json

EXPOSE 8080
CMD ["./mcp-server"]
```

Build and run:

```bash
docker build -t tls-cert-mcp-server .
docker run -p 8080:8080 -e MCP_X509_CONFIG_FILE=/root/config.json tls-cert-mcp-server
```

### Systemd Service

Create `/etc/systemd/system/tls-cert-mcp.service`:

```ini
[Unit]
Description=TLS Certificate Chain Resolver MCP Server
After=network.target

[Service]
Type=simple
User=tls-cert
Group=tls-cert
WorkingDirectory=/opt/tls-cert-mcp
ExecStart=/opt/tls-cert-mcp/mcp-server
Environment=MCP_X509_CONFIG_FILE=/opt/tls-cert-mcp/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable tls-cert-mcp
sudo systemctl start tls-cert-mcp
```

### Configuration Examples

#### Basic Configuration

```json
{
  "defaults": {
    "format": "pem",
    "includeSystemRoot": false,
    "intermediateOnly": false,
    "warnDays": 30,
    "port": 443,
    "timeoutSeconds": 10
  }
}
```

#### Advanced Configuration

```json
{
  "defaults": {
    "format": "json",
    "includeSystemRoot": true,
    "intermediateOnly": false,
    "warnDays": 60,
    "port": 443,
    "timeoutSeconds": 30
  }
}
```

### Client Integration Examples

#### Python MCP Client

```python
import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="go",
        args=["run", "/path/to/cmd/mcp-server/run.go"],
        env=None
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Resolve certificate chain
            result = await session.call_tool("resolve_cert_chain", {
                "certificate": "/path/to/cert.pem",
                "format": "json"
            })
            
            print("Certificate chain:", json.dumps(result.content, indent=2))

asyncio.run(main())
```

#### Node.js MCP Client

```javascript
const { Client } = require('@modelcontextprotocol/sdk');

async function main() {
  const client = new Client({
    name: 'cert-resolver-client',
    version: '0.2.9'
  });

  // Connect to MCP server
  await client.connect({
    command: 'go',
    args: ['run', '/path/to/cmd/mcp-server/run.go']
  });

  // Check certificate expiry
  const result = await client.callTool({
    name: 'check_cert_expiry',
    arguments: {
      certificate: '/path/to/cert.pem',
      warn_days: 30
    }
  });

  console.log('Expiry check result:', result);
}

main().catch(console.error);
```

### Troubleshooting

#### Common Issues

**MCP Server Won't Start**
- Check Go version: `go version` (must be 1.25.3+)
- Verify dependencies: `go mod tidy`
- Check config file syntax: `cat config.json | jq .`

**Certificate Resolution Fails**
- Verify certificate file exists and is readable
- Check certificate format (PEM/DER/base64)
- Ensure network connectivity for remote fetching
- Try with `intermediate_only: false` first

**Remote Certificate Fetching Issues**
- Verify hostname is reachable: `ping hostname`
- Check port accessibility: `telnet hostname port`
- Try different ports (443 for HTTPS, 25 for SMTP, etc.)
- Use `timeoutSeconds` config for slow connections

**Large Certificate Chains**
- Increase `timeoutSeconds` in config
- Use `intermediate_only: true` to reduce output size
- Check available memory for large chains

**MCP Tool Not Available**
- Verify server is running and connected
- Check tool names match exactly
- Review MCP client logs for connection errors

#### Debug Mode

Enable verbose logging:

```bash
export MCP_DEBUG=1
go run ./cmd/mcp-server
```

#### Testing MCP Server

Test individual tools:

```bash
# Test certificate resolution
echo '{"method": "tools/call", "params": {"name": "resolve_cert_chain", "arguments": {"certificate": "/path/to/cert.pem"}}}' | go run ./cmd/mcp-server

# Test validation
echo '{"method": "tools/call", "params": {"name": "validate_cert_chain", "arguments": {"certificate": "/path/to/cert.pem"}}}' | go run ./cmd/mcp-server
```

## MCP Server Deployment

### Docker Deployment

Create a `Dockerfile` for the MCP server:

```dockerfile
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o mcp-server ./cmd/mcp-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/mcp-server .
COPY --from=builder /app/src/mcp-server/config.example.json ./config.json

EXPOSE 8080
CMD ["./mcp-server"]
```

Build and run:

```bash
docker build -t tls-cert-mcp-server .
docker run -p 8080:8080 -e MCP_X509_CONFIG_FILE=/root/config.json tls-cert-mcp-server
```

### Systemd Service

Create `/etc/systemd/system/tls-cert-mcp.service`:

```ini
[Unit]
Description=TLS Certificate Chain Resolver MCP Server
After=network.target

[Service]
Type=simple
User=tls-cert
Group=tls-cert
WorkingDirectory=/opt/tls-cert-mcp
ExecStart=/opt/tls-cert-mcp/mcp-server
Environment=MCP_X509_CONFIG_FILE=/opt/tls-cert-mcp/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable tls-cert-mcp
sudo systemctl start tls-cert-mcp
```

### Configuration Examples

#### Basic Configuration

```json
{
  "defaults": {
    "format": "pem",
    "includeSystemRoot": false,
    "intermediateOnly": false,
    "warnDays": 30,
    "port": 443,
    "timeoutSeconds": 10
  }
}
```

#### Advanced Configuration

```json
{
  "defaults": {
    "format": "json",
    "includeSystemRoot": true,
    "intermediateOnly": false,
    "warnDays": 60,
    "port": 443,
    "timeoutSeconds": 30
  }
}
```

### Client Integration Examples

#### Python MCP Client

```python
import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="go",
        args=["run", "/path/to/cmd/mcp-server/run.go"],
        env=None
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Resolve certificate chain
            result = await session.call_tool("resolve_cert_chain", {
                "certificate": "/path/to/cert.pem",
                "format": "json"
            })
            
            print("Certificate chain:", json.dumps(result.content, indent=2))

asyncio.run(main())
```

#### Node.js MCP Client

```javascript
const { Client } = require('@modelcontextprotocol/sdk');

async function main() {
  const client = new Client({
    name: 'cert-resolver-client',
    version: '0.2.9'
  });

  // Connect to MCP server
  await client.connect({
    command: 'go',
    args: ['run', '/path/to/cmd/mcp-server/run.go']
  });

  // Check certificate expiry
  const result = await client.callTool({
    name: 'check_cert_expiry',
    arguments: {
      certificate: '/path/to/cert.pem',
      warn_days: 30
    }
  });

  console.log('Expiry check result:', result);
}

main().catch(console.error);
```

### Troubleshooting

#### Common Issues

**MCP Server Won't Start**
- Check Go version: `go version` (must be 1.25.3+)
- Verify dependencies: `go mod tidy`
- Check config file syntax: `cat config.json | jq .`

**Certificate Resolution Fails**
- Verify certificate file exists and is readable
- Check certificate format (PEM/DER/base64)
- Ensure network connectivity for remote fetching
- Try with `intermediate_only: false` first

**Remote Certificate Fetching Issues**
- Verify hostname is reachable: `ping hostname`
- Check port accessibility: `telnet hostname port`
- Try different ports (443 for HTTPS, 25 for SMTP, etc.)
- Use `timeoutSeconds` config for slow connections

**Large Certificate Chains**
- Increase `timeoutSeconds` in config
- Use `intermediate_only: true` to reduce output size
- Check available memory for large chains

**MCP Tool Not Available**
- Verify server is running and connected
- Check tool names match exactly
- Review MCP client logs for connection errors

#### Debug Mode

Enable verbose logging:

```bash
export MCP_DEBUG=1
go run ./cmd/mcp-server
```

#### Testing MCP Server

Test individual tools:

```bash
# Test certificate resolution
echo '{"method": "tools/call", "params": {"name": "resolve_cert_chain", "arguments": {"certificate": "/path/to/cert.pem"}}}' | go run ./cmd/mcp-server

# Test validation
echo '{"method": "tools/call", "params": {"name": "validate_cert_chain", "arguments": {"certificate": "/path/to/cert.pem"}}}' | go run ./cmd/mcp-server
```

## Motivation

This project was created to provide a more maintainable and actively maintained version of the original [zakjan/cert-chain-resolver](https://github.com/zakjan/cert-chain-resolver.git), which is no longer maintained.

## TODO List

### MCP Integration Enhancements

#### ✅ Completed
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

#### Remaining (Low Priority)
- [x] **Bidirectional AI Communication**: MCP already supports AI-to-AI messaging through the "sampling" mechanism (servers can request LLM completions from clients)
- [ ] Maintain compatibility with `github.com/mark3labs/mcp-go` (ongoing)
- [ ] Create abstraction layer for both MCP libraries
- [ ] Document differences and use cases for each library
- [ ] Implement streaming support for large certificate chains
- [ ] Add metrics and logging for MCP server operations

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](LICENSE) file for details.
