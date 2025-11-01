# Certificate Formats Supported

This MCP server supports multiple certificate formats for input and output operations.

## Input Formats

### PEM Format
- **Description**: Base64-encoded certificate data with header/footer markers
- **Headers**: -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
- **Usage**: Most common format for certificate files
- **Example**:
  -----BEGIN CERTIFICATE-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
  -----END CERTIFICATE-----

### DER Format
- **Description**: Binary DER-encoded certificate data
- **Usage**: Raw binary format, often used in binary protocols
- **Input**: Can be provided as base64-encoded string for tools

### Base64-Encoded Data
- **Description**: Raw certificate data encoded in base64
- **Usage**: For programmatic certificate handling
- **Tools**: All tools accept base64-encoded certificate data

## Output Formats

### PEM (default)
- **Description**: Human-readable PEM format
- **Usage**: Default output format, suitable for files and configuration

### DER
- **Description**: Binary DER format (base64-encoded in output)
- **Usage**: For binary certificate handling

### JSON
- **Description**: Structured JSON format with certificate metadata
- **Fields**: subject, issuer, serial, signatureAlgorithm, pem
- **Usage**: For programmatic processing and analysis

## Certificate Chain Resolution

The server can resolve complete certificate chains by:
1. Starting with a leaf certificate
2. Fetching intermediate certificates from issuer URLs
3. Optionally including system root CA certificates
4. Filtering to show only intermediate certificates if requested

## Validation Features

- **Chain Validation**: Verifies certificate chain integrity
- **Trust Verification**: Checks against system root CAs
- **Expiry Checking**: Monitors certificate expiration dates
- **Batch Processing**: Handles multiple certificates simultaneously
