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

This tool can be integrated with [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs/getting-started/intro) servers for automated certificate chain resolution. The MCP integration allows AI assistants and other tools to resolve TLS certificate chains programmatically.

> [!NOTE]
> The examples below use the [`github.com/mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go) library, which is a community-maintained Go implementation of MCP. This is not the official MCP SDK from [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk). Both libraries implement the MCP specification, but they have different APIs and features. Choose the one that best fits your needs.

### MCP Server Example

Here's a complete example of an MCP server that exposes certificate chain resolution as a tool:

```go
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	// Create MCP server
	s := server.NewMCPServer(
		"TLS/SSL Certificate Chain Resolver",
		"0.2.9",
		server.WithToolCapabilities(true),
	)

	// Define certificate chain resolution tool
	resolveCertChainTool := mcp.NewTool("resolve_cert_chain",
		mcp.WithDescription("Resolve TLS certificate chain from a certificate file or base64-encoded certificate data"),
		mcp.WithString("certificate",
			mcp.Required(),
			mcp.Description("Certificate file path or base64-encoded certificate data"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
			mcp.DefaultString("pem"),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA in output (default: false)"),
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates (default: false)"),
		),
	)

	// Register tool handler
	s.AddTool(resolveCertChainTool, handleResolveCertChain)

	// Start server
	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func handleResolveCertChain(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract arguments
	certInput, err := request.RequireString("certificate")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificate parameter required: %v", err)), nil
	}

	format, _ := request.GetString("format", "pem")
	includeSystemRoot, _ := request.GetBool("include_system_root", false)
	intermediateOnly, _ := request.GetBool("intermediate_only", false)

	// Read certificate data
	var certData []byte
	
	// Try to read as file first
	if fileData, err := os.ReadFile(certInput); err == nil {
		certData = fileData
	} else {
		// Try to decode as base64
		if decoded, err := base64.StdEncoding.DecodeString(certInput); err == nil {
			certData = decoded
		} else {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read certificate: not a valid file path or base64 data")), nil
		}
	}

	// Decode certificate
	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to decode certificate: %v", err)), nil
	}

	// Fetch certificate chain
	chain := x509chain.New(cert, "0.2.9")
	if err := chain.FetchCertificate(ctx); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch certificate chain: %v", err)), nil
	}

	// Optionally add system root CA
	if includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to add root CA: %v", err)), nil
		}
	}

	// Filter certificates if needed
	certs := chain.Certs
	if intermediateOnly {
		certs = chain.FilterIntermediates()
	}

	// Format output
	var output string
	switch format {
	case "der":
		derData := certManager.EncodeMultipleDER(certs)
		output = base64.StdEncoding.EncodeToString(derData)
	case "json":
		output = formatJSON(certs, certManager)
	default: // pem
		pemData := certManager.EncodeMultiplePEM(certs)
		output = string(pemData)
	}

	// Build result with chain information
	chainInfo := fmt.Sprintf("Certificate chain resolved successfully:\n")
	for i, c := range certs {
		chainInfo += fmt.Sprintf("%d: %s\n", i+1, c.Subject.CommonName)
	}
	chainInfo += fmt.Sprintf("\nTotal: %d certificate(s)\n\n", len(certs))
	chainInfo += output

	return mcp.NewToolResultText(chainInfo), nil
}

func formatJSON(certs []*x509.Certificate, certManager *x509certs.Certificate) string {
	type CertInfo struct {
		Subject            string `json:"subject"`
		Issuer             string `json:"issuer"`
		Serial             string `json:"serial"`
		SignatureAlgorithm string `json:"signatureAlgorithm"`
		PEM                string `json:"pem"`
	}

	certInfos := make([]CertInfo, len(certs))
	for i, cert := range certs {
		pemData := certManager.EncodePEM(cert)
		certInfos[i] = CertInfo{
			Subject:            cert.Subject.CommonName,
			Issuer:             cert.Issuer.CommonName,
			Serial:             cert.SerialNumber.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PEM:                string(pemData),
		}
	}

	output := map[string]interface{}{
		"title":            "TLS Certificate Chain",
		"totalChained":     len(certs),
		"listCertificates": certInfos,
	}

	jsonData, _ := json.MarshalIndent(output, "", "  ")
	return string(jsonData)
}
```

### Using the MCP Server with Go API

To use this MCP server with an MCP-compatible client (like Claude Desktop or other AI assistants), you need to configure it in your MCP settings:

```json
{
  "mcpServers": {
    "tls-cert-resolver": {
      "command": "go",
      "args": ["run", "path/to/your/mcp-server.go"]
    }
  }
}
```

The tool can then be called by the AI assistant with parameters like:

```json
{
  "name": "resolve_cert_chain",
  "arguments": {
    "certificate": "/path/to/certificate.pem",
    "format": "json",
    "include_system_root": true
  }
}
```

### Using the MCP Server with Binary

You can also integrate with MCP by executing the pre-built binary directly, without using the Go API. This approach is useful when you want to avoid Go dependencies or prefer using the standalone binary in an MCP tool server.

#### MCP Server Example Using CLI Binary

```go
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer(
		"TLS Certificate Chain Resolver CLI",
		"0.2.9",
		server.WithToolCapabilities(true),
	)

	resolveCertChainTool := mcp.NewTool("resolve_cert_chain_cli",
		mcp.WithDescription("Resolve TLS certificate chain using the tls-cert-chain-resolver binary"),
		mcp.WithString("certificate_file",
			mcp.Required(),
			mcp.Description("Path to certificate file"),
		),
		mcp.WithString("output_file",
			mcp.Description("Output file path (optional, defaults to stdout)"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
			mcp.DefaultString("pem"),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA in output"),
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates"),
		),
	)

	s.AddTool(resolveCertChainTool, handleResolveCertChainCLI)

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func handleResolveCertChainCLI(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	certFile, err := request.RequireString("certificate_file")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificate_file parameter required: %v", err)), nil
	}

	outputFile, _ := request.GetString("output_file", "")
	format, _ := request.GetString("format", "pem")
	includeSystemRoot, _ := request.GetBool("include_system_root", false)
	intermediateOnly, _ := request.GetBool("intermediate_only", false)

	args := []string{"-f", certFile}

	if outputFile != "" {
		args = append(args, "-o", outputFile)
	}

	if format == "der" {
		args = append(args, "-d")
	} else if format == "json" {
		args = append(args, "-j")
	}

	if includeSystemRoot {
		args = append(args, "-s")
	}

	if intermediateOnly {
		args = append(args, "-i")
	}

	cmd := exec.CommandContext(ctx, "tls-cert-chain-resolver", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("command failed: %v\nOutput: %s", err, string(output))), nil
	}

	result := string(output)
	if outputFile != "" {
		fileContent, err := os.ReadFile(outputFile)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read output file: %v", err)), nil
		}
		result = fmt.Sprintf("Command output:\n%s\n\nFile content:\n%s", result, string(fileContent))
	}

	return mcp.NewToolResultText(result), nil
}
```

#### Configuration for Claude Desktop

Add this to your Claude Desktop MCP settings:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

> [!NOTE]
> Claude Desktop is currently not available on Linux. For Linux users, you can use other MCP-compatible clients or run the MCP server directly with the stdio transport for testing and development purposes.

```json
{
  "mcpServers": {
    "tls-cert-resolver-cli": {
      "command": "/path/to/tls-cert-chain-mcp-server"
    }
  }
}
```

Make sure the `tls-cert-chain-resolver` binary is in your system PATH, or update the `exec.CommandContext` call to use the full path to the binary.

#### Example Usage in Claude Desktop

Once configured, you can ask Claude to resolve certificate chains:

```
Resolve the certificate chain for example.com certificate at /path/to/cert.pem
```

Claude will call the tool with appropriate parameters:

```json
{
  "name": "resolve_cert_chain_cli",
  "arguments": {
    "certificate_file": "/path/to/cert.pem",
    "format": "json",
    "include_system_root": true
  }
}
```

The tool will execute the binary and return the resolved certificate chain information.



### Programmatic Usage

#### Basic Certificate Chain Resolution

```go
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
)

func main() {
	certData, err := os.ReadFile("test-leaf.cer")
	if err != nil {
		log.Fatal(err)
	}

	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	chain := x509chain.New(cert, "0.2.9")
	
	if err := chain.FetchCertificate(ctx); err != nil {
		log.Fatal(err)
	}

	for i, c := range chain.Certs {
		fmt.Printf("%d: %s\n", i+1, c.Subject.CommonName)
	}
	
	pemOutput := certManager.EncodeMultiplePEM(chain.Certs)
	if err := os.WriteFile("output-bundle.pem", pemOutput, 0644); err != nil {
		log.Fatal(err)
	}
}
```

#### JSON Output Format

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
)

type CertificateInfo struct {
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	Serial             string `json:"serial"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	PEM                string `json:"pem"`
}

type JSONOutput struct {
	Title        string            `json:"title"`
	TotalChained int               `json:"totalChained"`
	Certificates []CertificateInfo `json:"listCertificates"`
}

func main() {
	certData, err := os.ReadFile("test-leaf.cer")
	if err != nil {
		log.Fatal(err)
	}

	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	chain := x509chain.New(cert, "0.2.9")
	
	if err := chain.FetchCertificate(ctx); err != nil {
		log.Fatal(err)
	}

	certInfos := make([]CertificateInfo, len(chain.Certs))
	for i, c := range chain.Certs {
		pemData := certManager.EncodePEM(c)
		certInfos[i] = CertificateInfo{
			Subject:            c.Subject.CommonName,
			Issuer:             c.Issuer.CommonName,
			Serial:             c.SerialNumber.String(),
			SignatureAlgorithm: c.SignatureAlgorithm.String(),
			PEM:                string(pemData),
		}
	}

	output := JSONOutput{
		Title:        "TLS Certificate Resolver",
		TotalChained: len(chain.Certs),
		Certificates: certInfos,
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(jsonData))
}
```

#### Advanced Usage with System Root CAs

```go
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
)

func main() {
	certData, err := os.ReadFile("test-leaf.cer")
	if err != nil {
		log.Fatal(err)
	}

	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	chain := x509chain.New(cert, "0.2.9")
	
	if err := chain.FetchCertificate(ctx); err != nil {
		log.Fatal(err)
	}

	if err := chain.AddRootCA(); err != nil {
		log.Fatal(err)
	}

	for i, c := range chain.Certs {
		fmt.Printf("%d: %s (Root: %v)\n", i+1, c.Subject.CommonName, chain.IsRootNode(c))
	}

	intermediates := chain.FilterIntermediates()
	fmt.Printf("\nFound %d intermediate certificate(s)\n", len(intermediates))
	
	pemOutput := certManager.EncodeMultiplePEM(chain.Certs)
	if err := os.WriteFile("output-bundle-with-root.pem", pemOutput, 0644); err != nil {
		log.Fatal(err)
	}
}
```

#### Decoding Multiple Certificates

```go
package main

import (
	"fmt"
	"log"
	"os"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
)

func main() {
	bundleData, err := os.ReadFile("certificate-bundle.pem")
	if err != nil {
		log.Fatal(err)
	}

	certManager := x509certs.New()
	
	certs, err := certManager.DecodeMultiple(bundleData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d certificate(s) in bundle:\n", len(certs))
	for i, cert := range certs {
		fmt.Printf("%d: %s\n", i+1, cert.Subject.CommonName)
		fmt.Printf("   Issuer: %s\n", cert.Issuer.CommonName)
		fmt.Printf("   Valid: %s to %s\n", cert.NotBefore, cert.NotAfter)
	}
}
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
docker run -p 8080:8080 -e MCP_CONFIG_FILE=/root/config.json tls-cert-mcp-server
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
Environment=MCP_CONFIG_FILE=/opt/tls-cert-mcp/config.json
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
        args=["run", "/path/to/cmd/mcp-server/main.go"],
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
    args: ['run', '/path/to/cmd/mcp-server/main.go']
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

### API Reference

#### Package `x509certs`

- `New() *Certificate`: Create new certificate manager
- `Decode(data []byte) (*x509.Certificate, error)`: Decode single certificate from PEM/DER/PKCS7
- `DecodeMultiple(data []byte) ([]*x509.Certificate, error)`: Decode multiple certificates
- `EncodePEM(cert *x509.Certificate) []byte`: Encode certificate to PEM
- `EncodeDER(cert *x509.Certificate) []byte`: Encode certificate to DER
- `EncodeMultiplePEM(certs []*x509.Certificate) []byte`: Encode multiple certificates to PEM
- `EncodeMultipleDER(certs []*x509.Certificate) []byte`: Encode multiple certificates to DER

#### Package `x509chain`

- `New(cert *x509.Certificate, version string) *Chain`: Create new chain manager
- `FetchCertificate(ctx context.Context) error`: Fetch complete certificate chain
- `AddRootCA() error`: Add system root CA to chain
- `FilterIntermediates() []*x509.Certificate`: Get only intermediate certificates
- `IsRootNode(cert *x509.Certificate) bool`: Check if certificate is root
- `IsSelfSigned(cert *x509.Certificate) bool`: Check if certificate is self-signed
- `VerifyChain() error`: Verify the certificate chain validity

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
docker run -p 8080:8080 -e MCP_CONFIG_FILE=/root/config.json tls-cert-mcp-server
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
Environment=MCP_CONFIG_FILE=/opt/tls-cert-mcp/config.json
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
        args=["run", "/path/to/cmd/mcp-server/main.go"],
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
    args: ['run', '/path/to/cmd/mcp-server/main.go']
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

#### Remaining (Low Priority)
- [ ] Maintain compatibility with `github.com/mark3labs/mcp-go` (ongoing)
- [ ] Create abstraction layer for both MCP libraries
- [ ] Document differences and use cases for each library
- [ ] Implement streaming support for large certificate chains
- [ ] Add metrics and logging for MCP server operations

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](LICENSE) file for details.
