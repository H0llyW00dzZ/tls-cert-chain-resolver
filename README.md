# TLS Cert Chain Resolver

[![Go Reference](https://pkgo.dev/badge/github.com/H0llyW00dzZ/tls-cert-chain-resolver.svg)](https://pkgo.dev/github.com/H0llyW00dzZ/tls-cert-chain-resolver) [![Go Report Card](https://goreportcard.com/badge/github.com/H0llyW00dzZ/tls-cert-chain-resolver)](https://goreportcard.com/report/github.com/H0llyW00dzZ/tls-cert-chain-resolver)

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

- Go 1.24.2 or later

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

This tool is compatible with Go 1.24.2 or later and works effectively across various clients (e.g., HTTP clients in Go, mobile browsers, OpenSSL). It resolves chaining issues, providing enhanced flexibility and control over certificate chain resolution.

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

## Motivation

This project was created to provide a more maintainable and actively maintained version of the original [zakjan/cert-chain-resolver](https://github.com/zakjan/cert-chain-resolver.git), which is no longer maintained.

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](LICENSE) file for details.
