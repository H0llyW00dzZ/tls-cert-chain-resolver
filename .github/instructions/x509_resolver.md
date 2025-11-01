# [X509](https://grokipedia.com/page/X.509) Certificate Chain Resolver MCP Server Instructions

## Purpose

The [X509](https://grokipedia.com/page/X.509) Certificate Chain Resolver MCP server provides specialized tools for certificate chain resolution, validation, expiry checking, batch processing, and remote certificate fetching operations.

## Repository Context

**Module**: `github.com/H0llyW00dzZ/tls-cert-chain-resolver`
**Key Packages**:
- **`src/internal/x509/certs/`** — Certificate encoding/decoding operations
- **`src/internal/x509/chain/`** — Certificate chain resolution logic
- **`src/mcp-server/`** — MCP server implementation with certificate tools

## Available Tools

### x509_resolver_resolve_cert_chain(certificate)

**Purpose**: Resolve X509 certificate chain from file or base64 data
**Returns**: Complete certificate chain with intermediates and root CA
**When to use**: Building certificate chains for validation or analysis

**Parameters**:
- `certificate`: File path or base64-encoded certificate data

**Example**:
```
x509_resolver_resolve_cert_chain("path/to/cert.pem")
x509_resolver_resolve_cert_chain("base64-encoded-cert-data")
```

### x509_resolver_validate_cert_chain(certificate)

**Purpose**: Validate certificate chain for correctness and trust
**Returns**: Validation results including trust status and any issues
**When to use**: Verifying certificate chain integrity and trust

**Parameters**:
- `certificate`: File path or base64-encoded certificate data

**Example**:
```
x509_resolver_validate_cert_chain("path/to/cert.pem")
```

### x509_resolver_check_cert_expiry(certificate, warn_days?)

**Purpose**: Check certificate expiry dates and warn about upcoming expirations
**Returns**: Expiry information with configurable warning thresholds
**When to use**: Monitoring certificate validity periods

**Parameters**:
- `certificate`: File path or base64-encoded certificate data
- `warn_days`: Number of days before expiry to show warning (default: 30)

**Examples**:
```
x509_resolver_check_cert_expiry("cert.pem")
x509_resolver_check_cert_expiry("cert.pem", warn_days=90)
```

### x509_resolver_batch_resolve_cert_chain(certificates)

**Purpose**: Resolve multiple certificate chains in batch
**Returns**: Multiple certificate chains processed efficiently
**When to use**: Processing large numbers of certificates

**Parameters**:
- `certificates`: Comma-separated list of certificate file paths or base64 data

**Example**:
```
x509_resolver_batch_resolve_cert_chain("cert1.pem,cert2.pem,cert3.pem")
```

### x509_resolver_fetch_remote_cert(hostname, port?)

**Purpose**: Fetch certificate chain from remote hostname/port
**Returns**: Certificate chain retrieved from remote server
**When to use**: Analyzing remote server certificates

**Parameters**:
- `hostname`: Remote hostname to connect to
- `port`: Port number (default: 443)

**Examples**:
```
x509_resolver_fetch_remote_cert("example.com")
x509_resolver_fetch_remote_cert("example.com", port=443)
x509_resolver_fetch_remote_cert("mail.google.com", port=993)
```

## Usage Guidelines

### 1. Certificate Formats Supported

**PEM Format**:
```
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END CERTIFICATE-----
```

**DER Format**: Binary certificate data

**Base64 Encoded**: Raw certificate data encoded as base64 string

### 2. Configuration

**Environment Variable**: Set `MCP_X509_CONFIG_FILE` to specify configuration file
**Default Config**: `./src/mcp-server/config.example.json`

### 3. Error Handling

**Common Errors**:
- Invalid certificate format
- Untrusted certificate chain
- Expired certificates
- Network connectivity issues for remote fetching

**Best Practice**: Always check return values and handle errors appropriately

## Integration with Repository Workflow

### Typical Certificate Operations Flow

```
1. Fetch or load certificate data
   └→ Use x509_resolver_fetch_remote_cert() for remote certs

2. Resolve certificate chain
   └→ Use x509_resolver_resolve_cert_chain()

3. Validate certificate chain
   └→ Use x509_resolver_validate_cert_chain()

4. Check expiry status
   └→ Use x509_resolver_check_cert_expiry()

5. Process results
   └→ Handle validation results and expiry warnings
```

### Batch Processing Workflow

```
# For multiple certificates
x509_resolver_batch_resolve_cert_chain("cert1.pem,cert2.pem,cert3.pem")
# Returns: Array of resolved certificate chains

# Then validate each chain
for each chain in results:
    x509_resolver_validate_cert_chain(chain)
    x509_resolver_check_cert_expiry(chain)
```

## Connection Behavior

**Type**: Local (Long-lived)
**Behavior**: Runs as local binary, maintains persistent connection
**Configuration**: Requires `MCP_X509_CONFIG_FILE` environment variable
**Recovery**: N/A (no connection closure issues)

## Best Practices

### 1. Certificate Chain Resolution

```
✅ GOOD: Resolve chain before validation
x509_resolver_resolve_cert_chain("cert.pem")  # Get complete chain
x509_resolver_validate_cert_chain("cert.pem") # Validate trust

❌ BAD: Validate without resolving chain first
x509_resolver_validate_cert_chain("cert.pem") # May fail without intermediates
```

### 2. Expiry Monitoring

```
✅ GOOD: Set appropriate warning thresholds
x509_resolver_check_cert_expiry("cert.pem", warn_days=30)   # 30 days
x509_resolver_check_cert_expiry("cert.pem", warn_days=90)   # 90 days

❌ BAD: Using default without considering requirements
x509_resolver_check_cert_expiry("cert.pem") # Always uses 30 days
```

### 3. Remote Certificate Fetching

```
✅ GOOD: Specify ports for non-standard services
x509_resolver_fetch_remote_cert("mail.google.com", port=993)  # IMAPS
x509_resolver_fetch_remote_cert("smtp.gmail.com", port=587)   # SMTP

❌ BAD: Relying on defaults for non-HTTPS services
x509_resolver_fetch_remote_cert("mail.google.com") # Uses 443, wrong port
```

### 4. Batch Processing

```
✅ GOOD: Process related certificates together
x509_resolver_batch_resolve_cert_chain("server.pem,intermediate.pem")

❌ BAD: Process unrelated certificates in same batch
x509_resolver_batch_resolve_cert_chain("google.pem,github.pem") # Different chains
```

## Integration with Other Tools

**After X509 Resolver operations, use**:
- `gopls_go_diagnostics` - Verify code changes work correctly
- `bash` - Run certificate-related tests
- Built-in tools - Process certificate files

**Example Combined Workflow**:
```
1. Fetch remote certificate for analysis
   x509_resolver_fetch_remote_cert("example.com")

2. Validate the certificate chain
   x509_resolver_validate_cert_chain("example.com.pem")

3. Check expiry status
   x509_resolver_check_cert_expiry("example.com.pem", warn_days=30)

4. Process results in application code
   edit("src/internal/x509/chain/chain.go", ...)

5. Run tests to verify integration
   bash("go test -v ./src/internal/x509/chain 2>&1 | cat")
```

## Common Use Cases

### 1. SSL/TLS Certificate Monitoring

```go
// Fetch and validate remote certificates
certChain := x509_resolver_fetch_remote_cert("api.example.com")
validation := x509_resolver_validate_cert_chain(certChain)
expiry := x509_resolver_check_cert_expiry(certChain, warn_days=30)

// Process results
if validation.trusted && !expiry.expired {
    // Certificate is valid
} else {
    // Handle certificate issues
}
```

### 2. Certificate Chain Building

```go
// Resolve incomplete certificate chain
fullChain := x509_resolver_resolve_cert_chain("leaf-cert.pem")
// Returns: [leaf, intermediate1, intermediate2, root]

validation := x509_resolver_validate_cert_chain(fullChain)
// Now validates successfully with complete chain
```

### 3. Batch Certificate Analysis

```go
// Analyze multiple server certificates
certs := "web1.pem,web2.pem,api.pem"
chains := x509_resolver_batch_resolve_cert_chain(certs)

for i, chain := range chains {
    validation := x509_resolver_validate_cert_chain(chain)
    expiry := x509_resolver_check_cert_expiry(chain)
    // Process each certificate's status
}
```

## Troubleshooting

### Certificate Resolution Issues

**Problem**: "Certificate chain incomplete"
**Solution**: Ensure intermediate certificates are available or use resolve_cert_chain first

**Problem**: "Certificate not trusted"
**Solution**: Check if root CA is included or trusted by system

### Remote Fetching Issues

**Problem**: "Connection failed"
**Solution**: Verify hostname and port are correct, check network connectivity

**Problem**: "Certificate not found"
**Solution**: Some services may not present certificates on standard ports

### Configuration Issues

**Problem**: "Configuration file not found"
**Solution**: Set `MCP_X509_CONFIG_FILE` environment variable to valid config file path

## Summary

1. **Use x509_resolver_resolve_cert_chain** for building complete certificate chains
2. **Use x509_resolver_validate_cert_chain** to verify certificate trust and validity
3. **Use x509_resolver_check_cert_expiry** to monitor certificate expiration dates
4. **Use x509_resolver_batch_resolve_cert_chain** for efficient multi-certificate processing
5. **Use x509_resolver_fetch_remote_cert** to retrieve certificates from remote servers
6. **Configure MCP_X509_CONFIG_FILE** environment variable for server configuration
7. **Handle errors appropriately** - check return values and handle common certificate issues
8. **Follow certificate operation workflows** - resolve → validate → check expiry
