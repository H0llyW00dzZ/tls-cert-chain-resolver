# tls-cert-chain-resolver

Command-line tool for building, validating, and inspecting TLS certificate chains.

## Installation

Install with Go 1.25.5 or later:

```bash
go install github.com/H0llyW00dzZ/tls-cert-chain-resolver/cmd/tls-cert-chain-resolver@latest
```

Or build from source:

```bash
make build-linux      # or build-macos / build-windows
```

## Usage

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

## Examples

Resolve a leaf certificate into a PEM bundle:

```bash
tls-cert-chain-resolver -f cert.pem -o chain.pem
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

Verify the output with OpenSSL:

```bash
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
  -untrusted chain.pem chain.pem
```

## Features

- Deterministic TLS certificate chain resolution with optional system trust roots
- Multiple output formats: PEM, DER, or JSON (structured metadata with PEM payloads)
- Rich certificate chain visualization: ASCII tree diagrams, markdown tables, and JSON exports
- Efficient memory usage via reusable buffer pools

## Related

- [x509-cert-chain-resolver](../x509-cert-chain-resolver/) - MCP server for certificate operations
- [Module Documentation](https://pkg.go.dev/github.com/H0llyW00dzZ/tls-cert-chain-resolver) - Full API reference

## License

BSD 3-Clause License. See [LICENSE](../../LICENSE).
