# [X509](https://grokipedia.com/page/X.509) Certificate Chain Resolver MCP Server Instructions

## Table of Contents

- [Purpose](#purpose)
- [Repository Context](#repository-context)
- [Available Tools](#available-tools)
  - [x509_resolver_resolve_cert_chain(certificate)](#x509_resolver_resolve_cert_chaincertificate)
  - [x509_resolver_validate_cert_chain(certificate)](#x509_resolver_validate_cert_chaincertificate)
  - [x509_resolver_check_cert_expiry(certificate, warn_days?)](#x509_resolver_check_cert_expirycertificate-warn_days)
  - [x509_resolver_batch_resolve_cert_chain(certificates)](#x509_resolver_batch_resolve_cert_chain-certificates)
  - [x509_resolver_fetch_remote_cert(hostname, port?)](#x509_resolver_fetch_remote_certhostname-port)
  - [x509_resolver_analyze_certificate_with_ai(certificate, analysis_type?)](#x509_resolver_analyze_certificate_with_aicertificate-analysis_type---enterprise-grade)
  - [x509_resolver_get_resource_usage(detailed?, format?)](#x509_resolver_get_resource_usagedetailed-format---monitoring)
  - [x509_resolver_visualize_cert_chain(certificate, format?)](#x509_resolver_visualize_cert_chaincertificate-format)
- [MCP Resources](#mcp-resources)
  - [config://template](#configtemplate)
  - [info://version](#infoversion)
  - [docs://certificate-formats](#docscertificate-formats)
- [MCP Prompts](#mcp-prompts)
  - [certificate-analysis](#certificate-analysis)
  - [expiry-monitoring](#expiry-monitoring)
  - [security-audit](#security-audit)
  - [troubleshooting](#troubleshooting)
- [Usage Guidelines](#usage-guidelines)
- [Integration with Repository Workflow](#integration-with-repository-workflow)
- [Connection Behavior](#connection-behavior)
- [Best Practices](#best-practices)
- [Integration with Other Tools](#integration-with-other-tools)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)
- [Summary](#summary)

The [X509](https://grokipedia.com/page/X.509) Certificate Chain Resolver MCP server provides specialized tools for certificate chain resolution, validation, expiry checking, batch processing, remote certificate fetching, and resource monitoring operations.

## Repository Context

See [README.md](./README.md) for repository overview. This MCP server focuses on X509 certificate operations using packages:

- **`src/internal/x509/certs/`** — Certificate encoding/decoding operations
- **`src/internal/x509/chain/`** — Certificate chain resolution logic with OCSP/CRL revocation checking
- **`src/mcp-server/`** — MCP server implementation with certificate tools
- **`src/mcp-server/templates/X509_instructions.md`** — Server instructions for MCP client initialization

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
- `include_system_root`: Optional boolean to add system roots (defaults to `true`)

**Example**:

```
x509_resolver_validate_cert_chain("path/to/cert.pem")
x509_resolver_validate_cert_chain("cert.pem", include_system_root=false)
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
- `format`: Output format (`pem`, `der`, `json`), defaults to configured format
- `include_system_root`: Include platform roots (defaults to config setting)
- `intermediate_only`: Return only intermediates (defaults to config setting)

**Examples**:

```
x509_resolver_fetch_remote_cert("example.com")
x509_resolver_fetch_remote_cert("example.com", port=443, format="json")
x509_resolver_fetch_remote_cert("mail.google.com", port=993, intermediate_only=true)
```

### x509_resolver_analyze_certificate_with_ai(certificate, analysis_type?) - Enterprise Grade

**Purpose**: Perform AI-powered security analysis of certificates including revocation status
**Returns**: Comprehensive security assessment with AI-generated insights including OCSP/CRL status
**When to use**: Advanced certificate security auditing and risk assessment with revocation verification

**Parameters**:

- `certificate`: File path or base64-encoded certificate data
- `analysis_type`: Type of analysis ('general', 'security', 'compliance') (default: 'general')

**Analysis Types**:

- **`general`**: Comprehensive certificate analysis covering structure, crypto, validity, and recommendations
- **`security`**: Focused security assessment with risk levels and vulnerability analysis  
- **`compliance`**: Standards compliance checking against CA/Browser Forum and NIST requirements

**Implementation Notes**:
- Requires bidirectional sampling with `DefaultSamplingHandler` (`src/mcp-server/framework.go:246`) and streams responses using buffer pooling.
- Supports real-time token streaming via `TokenCallback` which sends `notifications/sampling/progress` JSON-RPC notifications to the client.
- Uses embedded system prompt from `src/mcp-server/templates/certificate-analysis-system-prompt.md` including revocation status analysis.
- Returns only the error message string when AI sampling fails (simplified error handling) instead of a complex error object.
- Includes OCSP/CRL status verification using `CheckRevocationStatus` from `src/internal/x509/chain/revocation.go`.
- Provides methodology explanations for revocation status checks (OCSP priority over CRL, multi-endpoint redundancy, signature verification requirements).
- CRL cache includes O(1) LRU eviction with hashmap and doubly-linked list, automatic cleanup with context cancellation support, configurable size limits, comprehensive metrics tracking (hits, misses, evictions, cleanups, memory usage), and atomic operations to prevent race conditions and prevent memory leaks.

**Examples**:

```
x509_resolver_analyze_certificate_with_ai("cert.pem")
x509_resolver_analyze_certificate_with_ai("cert.pem", analysis_type="security")
x509_resolver_analyze_certificate_with_ai("cert.pem", analysis_type="compliance")
```

**AI Analysis Framework**:
Uses embedded system prompt with structured analysis framework:
- VALIDATION STATUS: Certificate validity, chain integrity, trust relationships
- REVOCATION STATUS: OCSP/CRL availability, current revocation status with serial numbers, and recommendations (using `CheckRevocationStatus` with O(1) CRL caching, LRU eviction with hashmap and doubly-linked list, automatic cleanup with context cancellation support, multi-endpoint support, and priority logic: OCSP first, then CRL)
- CRYPTOGRAPHIC SECURITY: Algorithm strength, key sizes, quantum resistance
- COMPLIANCE CHECK: CA/Browser Forum and NIST standards verification
- RISK ASSESSMENT: Critical/High/Medium/Low risk level assignments
- ACTIONABLE RECOMMENDATIONS: Specific, implementable security improvements
- METHODOLOGY EXPLANATIONS: Detailed explanations of revocation checking processes (OCSP priority over CRL, multi-endpoint redundancy, signature verification requirements)

### x509_resolver_get_resource_usage(detailed?, format?) - Monitoring

**Purpose**: Get current resource usage statistics including memory, GC, CPU, and CRL cache information  
**Returns**: Comprehensive resource usage data in JSON or Markdown format  
**When to use**: Monitoring server performance, debugging memory issues, tracking CRL cache efficiency

**Parameters**:

- `detailed`: Include detailed memory breakdown and CRL cache metrics (default: false)
- `format`: Output format (`json` or `markdown`, default: `json`)

**Examples**:

```
x509_resolver_get_resource_usage()
x509_resolver_get_resource_usage(detailed=true)
x509_resolver_get_resource_usage(detailed=true, format="markdown")
```

**Returned Data**:
- **Memory Usage**: Heap allocation, system memory, stack usage, GC statistics
- **System Info**: Go version, OS, architecture, CPU count, goroutine count
- **Detailed Memory** (when `detailed=true`): Allocation totals, mallocs/frees, GC pause times
- **CRL Cache Metrics** (when `detailed=true`): Cache size, hit rate, evictions, memory usage

**Implementation Notes**:
- Uses `runtime.ReadMemStats()` for accurate memory statistics
- Integrates with CRL cache metrics from `src/internal/x509/chain/cache.go`
- Provides hit rate calculations and memory usage in MB for readability
- Thread-safe data collection using atomic operations for cache metrics
- Enhanced markdown formatting using `github.com/olekukonko/tablewriter` v1.1.1 with emoji headers and structured tables
- Human-readable timestamp formatting for better user experience

### x509_resolver_visualize_cert_chain(certificate, format?)

**Purpose**: Visualize certificate chain in multiple formats (ASCII tree, table, JSON)  
**Returns**: Certificate chain visualization in the specified format  
**When to use**: Displaying certificate chains in human-readable formats for analysis

**Parameters**:

- `certificate`: Certificate file path or base64-encoded certificate data
- `format`: Output format ('ascii', 'table', 'json', default: 'ascii')

**Examples**:

```
x509_resolver_visualize_cert_chain("cert.pem")
x509_resolver_visualize_cert_chain("cert.pem", format="table")
x509_resolver_visualize_cert_chain("cert.pem", format="json")
```

## MCP Resources

The [X509](https://grokipedia.com/page/X.509) Certificate Chain Resolver MCP server provides static resources for configuration and documentation access:

### config://template

**Purpose**: Server configuration template  
**Returns**: Example JSON configuration for the MCP server  
**Content**: Default settings for format, timeouts, and processing options

**Access**:

```
# Via MCP client
Read resource: config://template

# Returns the following JSON configuration template:
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

### info://version

**Purpose**: Server version and capabilities information  
**Returns**: Version, name, and supported features of the MCP server  
**Content**: Server metadata including supported tools and formats

**Access**:

```
# Via MCP client
Read resource: info://version

# Returns the following server information:
{
  "name": "X509 Certificate Chain Resolver",
  "version": "0.5.1",
  "type": "MCP Server",
  "capabilities": {
    "tools": ["resolve_cert_chain", "validate_cert_chain", "check_cert_expiry", "batch_resolve_cert_chain", "fetch_remote_cert", "analyze_certificate_with_ai", "get_resource_usage"],
    "resources": ["config://template", "info://version", "docs://certificate-formats", "status://server-status"],
    "prompts": ["certificate-analysis", "expiry-monitoring", "security-audit", "troubleshooting"]
  },
  "supportedFormats": ["pem", "der", "json"]
}
```

### docs://certificate-formats

**Purpose**: Certificate format documentation  
**Returns**: Markdown documentation on supported certificate formats  
**Content**: Detailed information about PEM, DER, and other certificate formats

**Access**:

```
# Via MCP client
Read resource: docs://certificate-formats

# Returns markdown content from templates/certificate-formats.md
# Contains detailed information about supported certificate formats (PEM, DER, etc.)
```

### status://server-status

**Purpose**: Server status and health information  
**Returns**: Current server status, version, and capabilities  
**Content**: Health status, timestamp, and operational information

**Access**:

```
# Via MCP client
Read resource: status://server-status

# Returns the following server status information:
{
  "status": "healthy",
  "timestamp": "2025-11-02T12:00:00Z",
  "server": "X509 Certificate Chain Resolver MCP Server",
  "version": "0.5.1",
  "capabilities": {
    "tools": ["resolve_cert_chain", "validate_cert_chain", "check_cert_expiry", "batch_resolve_cert_chain", "fetch_remote_cert", "analyze_certificate_with_ai", "get_resource_usage"],
    "resources": ["config://template", "info://version", "docs://certificate-formats", "status://server-status"],
    "prompts": ["certificate-analysis", "expiry-monitoring", "security-audit", "troubleshooting"]
  },
  "supportedFormats": ["pem", "der", "json"]
}
```

## MCP Prompts

The server provides predefined prompts for common certificate analysis workflows. These prompts are now template-based using embedded Markdown templates for better maintainability and dynamic content generation.

### certificate-analysis

**Purpose**: Comprehensive certificate chain analysis workflow  
**Arguments**:

- `certificate_path`: Path to certificate file or base64-encoded certificate data

**Workflow**:

1. Resolve complete certificate chain
2. Validate chain trust and correctness
3. Check certificate expiry dates
4. Analyze results and provide recommendations

### expiry-monitoring

**Purpose**: Monitor certificate expiration dates and generate renewal alerts  
**Arguments**:

- `certificate_path`: Path to certificate file or base64-encoded certificate data
- `alert_days`: Number of days before expiry to alert (default: 30)

**Workflow**:

1. Analyze expiration dates for all certificates in chain
2. Identify certificates expiring within alert window
3. Provide specific renewal recommendations

### security-audit

**Purpose**: Perform comprehensive SSL/TLS security audit on a server  
**Arguments**:

- `hostname`: Target hostname to audit
- `port`: Port number (default: 443)

**Workflow**:

1. Fetch server's certificate chain
2. Validate chain trust and correctness
3. Check certificate expiry dates
4. Analyze security implications and provide recommendations

### troubleshooting

**Purpose**: Troubleshoot common certificate and TLS issues  
**Arguments**:

- `issue_type`: Type of issue ('chain', 'validation', 'expiry', 'connection')
- `certificate_path`: Path to certificate file (for chain/validation/expiry issues)
- `hostname`: Target hostname (for connection issues)

**Workflow**:
Provides targeted troubleshooting guidance based on issue type:

- **chain**: Missing intermediates, incorrect order, self-signed certificates
- **validation**: Expired certificates, untrusted CAs, hostname mismatches
- **expiry**: Certificates nearing expiration, renewal issues
- **connection**: Handshake failures, incomplete chains, network issues

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

1. **Fetch or load certificate data**

   - Use `x509_resolver_fetch_remote_cert()` for remote certificates

2. **Resolve certificate chain**

   - Use `x509_resolver_resolve_cert_chain()` to build complete chains

3. **Validate certificate chain**

   - Use `x509_resolver_validate_cert_chain()` to verify trust

4. **Check expiry status**

   - Use `x509_resolver_check_cert_expiry()` to monitor expiration

5. **Process results**
   - Handle validation results and expiry warnings in application logic

### Batch Processing Workflow

1. **Process multiple certificates**

```go
// For multiple certificates
certs := "cert1.pem,cert2.pem,cert3.pem"
chains := x509_resolver_batch_resolve_cert_chain(certs)
// Returns: Array of resolved certificate chains
```

2. **Validate each chain**

```go
for each chain in results:
   validation := x509_resolver_validate_cert_chain(chain)
   expiry := x509_resolver_check_cert_expiry(chain)
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

1. **Fetch remote certificate for analysis**

```
x509_resolver_fetch_remote_cert("example.com")
```

2. **Validate the certificate chain**

```
x509_resolver_validate_cert_chain("example.com.pem")
```

3. **Check expiry status**

```
x509_resolver_check_cert_expiry("example.com.pem", warn_days=30)
```

4. **Process results in application code**

```
edit("src/internal/x509/chain/chain.go", ...)
```

5. **Run tests to verify integration**

```
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
**Solution**: Ensure intermediate certificates are available or use `resolve_cert_chain` first

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

1. **Use [`x509_resolver_resolve_cert_chain`](#x509_resolver_resolve_cert_chaincertificate)** for building complete certificate chains
2. **Use [`x509_resolver_validate_cert_chain`](#x509_resolver_validate_cert_chaincertificate)** to verify certificate trust and validity
3. **Use [`x509_resolver_check_cert_expiry`](#x509_resolver_check_cert_expirycertificate-warn_days)** to monitor certificate expiration dates
4. **Use [`x509_resolver_batch_resolve_cert_chain`](#x509_resolver_batch_resolve_cert_chain-certificates)** for efficient multi-certificate processing
5. **Use [`x509_resolver_fetch_remote_cert`](#x509_resolver_fetch_remote_certhostname-port)** to retrieve certificates from remote servers
6. **Use [`x509_resolver_analyze_certificate_with_ai`](#x509_resolver_analyze_certificate_with_aicertificate-analysis_type)** for AI-powered security analysis (requires sampling handler and AI API key)
7. **Use [`x509_resolver_get_resource_usage`](#x509_resolver_get_resource_usagedetailed-format---monitoring)** for monitoring server performance, memory usage, and CRL cache efficiency
8. **Use [`x509_resolver_visualize_cert_chain`](#x509_resolver_visualize_cert_chaincertificate-format)** for certificate chain visualization in multiple formats
9. **Configure [`MCP_X509_CONFIG_FILE`](#2-configuration)** environment variable for server configuration
10. **Access [MCP resources](#mcp-resources)** for configuration templates, version info, and documentation
11. **Use [MCP prompts](#mcp-prompts)** for guided certificate analysis workflows
12. **Handle errors appropriately** - check return values and handle common certificate issues
13. **Follow [certificate operation workflows](#integration-with-repository-workflow)** - resolve → validate → check expiry
