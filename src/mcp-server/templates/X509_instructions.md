# [X.509](https://grokipedia.com/page/X.509) Certificate Chain Resolver [MCP](https://modelcontextprotocol.io/docs/getting-started/intro) Server

These instructions describe how to efficiently work with [X.509](https://grokipedia.com/page/X.509) certificates using the certificate chain resolver [MCP](https://modelcontextprotocol.io/docs/getting-started/intro) server. You can load this file directly into a session where the certificate [MCP](https://modelcontextprotocol.io/docs/getting-started/intro) server is connected.

## Detecting certificate operations

At the start of every session involving certificates, you MUST use the `{{.ToolRoles.resourceMonitor}}` tool to verify the server is operational and check CRL cache status. The rest of these instructions apply whenever working with certificate analysis tasks.

## Certificate analysis workflows

These guidelines MUST be followed whenever working with certificates. There are three workflows described below: the 'Basic Analysis Workflow' must be followed for standard certificate checks. The 'Security Audit Workflow' must be followed for comprehensive security assessments. The 'Batch Processing Workflow' must be followed when analyzing multiple certificates.

You may re-do parts of each workflow as necessary to recover from errors. However, you must not skip any steps.

### Basic Analysis Workflow

The goal of the basic analysis workflow is to perform standard certificate validation and health checks.

1. **Resolve certificate chain**: Start by using `{{.ToolRoles.chainResolver}}` to build a complete certificate chain from the provided certificate data. This ensures you have all necessary certificates for validation.
    EXAMPLE: `{{.ToolRoles.chainResolver}}({"certificate":"path/to/cert.pem"})`

2. **Validate chain trust**: Immediately after resolution, use `{{.ToolRoles.chainValidator}}` to verify the certificate chain's authenticity and trust relationships against system trust stores.
    EXAMPLE: `{{.ToolRoles.chainValidator}}({"certificate":"path/to/cert.pem"})`

3. **Check expiry status**: Use `{{.ToolRoles.expiryChecker}}` to analyze certificate validity periods and identify upcoming expirations. Always specify appropriate warning thresholds based on organizational policies.
    EXAMPLE: `{{.ToolRoles.expiryChecker}}({"certificate":"path/to/cert.pem","warn_days":30})`

4. **Verify server health**: If the analysis involves server certificates, use `{{.ToolRoles.resourceMonitor}}` to ensure the certificate resolver service is operating correctly.
    EXAMPLE: `{{.ToolRoles.resourceMonitor}}({"detailed":false,"format":"json"})`

### Security Audit Workflow

The security audit workflow provides comprehensive security assessment and compliance checking.

1. **Gather certificate data**: Begin by collecting all relevant certificates. For server certificates, use `{{.ToolRoles.remoteFetcher}}`. For local certificates, use `{{.ToolRoles.chainResolver}}`.
    EXAMPLE: `{{.ToolRoles.remoteFetcher}}({"hostname":"example.com","port":443})`

2. **Perform AI-powered analysis**: Use `{{.ToolRoles.aiAnalyzer}}` with the 'security' analysis type to get expert security assessment including cryptographic strength evaluation and vulnerability analysis.
    EXAMPLE: `{{.ToolRoles.aiAnalyzer}}({"certificate":"cert.pem","analysis_type":"security"})`

3. **Check compliance**: Re-run `{{.ToolRoles.aiAnalyzer}}` with the 'compliance' analysis type to verify adherence to CA/Browser Forum and NIST standards.
    EXAMPLE: `{{.ToolRoles.aiAnalyzer}}({"certificate":"cert.pem","analysis_type":"compliance"})`

4. **Validate revocation mechanisms**: Ensure OCSP and CRL configurations are properly implemented by examining the certificate analysis results for revocation status information.

5. **Generate recommendations**: Based on the security analysis, provide specific, prioritized recommendations for certificate management and security improvements.

### Batch Processing Workflow

The batch processing workflow handles large-scale certificate analysis efficiently.

1. **Prepare certificate list**: Collect all certificates to be analyzed and format them as a comma-separated list for batch processing.
   EXAMPLE: `"cert1.pem,cert2.pem,cert3.pem"`

2. **Execute batch resolution**: Use `{{.ToolRoles.batchResolver}}` to process multiple certificates simultaneously. This is more efficient than individual processing for large datasets.
    EXAMPLE: `{{.ToolRoles.batchResolver}}({"certificates":"cert1.pem,cert2.pem,cert3.pem"})`

3. **Analyze results systematically**: For each certificate in the batch results, follow the Basic Analysis Workflow steps (validation, expiry checking).

4. **Prioritize findings**: Focus attention on certificates with critical issues (expired, invalid chains, security vulnerabilities) before addressing lower-priority items.

5. **Generate summary reports**: Compile findings into structured reports showing overall certificate health across the analyzed set.

## Certificate format handling

You MUST understand and handle these certificate formats correctly:

- **PEM Format**: Text-based format with `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` headers. Most common for configuration files.
- **DER Format**: Binary format containing raw certificate data. Often used in binary protocols and Windows systems.
- **Base64 Encoded**: Raw certificate data encoded as base64 strings. May appear without PEM headers.

When encountering format errors, try alternative encodings. PEM is the most reliable for manual operations.

## Error handling and recovery

These error handling procedures MUST be followed when tools return errors:

### Certificate Resolution Errors
- **"Invalid certificate format"**: Verify the certificate data is properly formatted. Try different encodings (PEM ↔ DER ↔ Base64).
- **"Certificate chain incomplete"**: Use `{{.ToolRoles.chainResolver}}` to fetch missing intermediate certificates.
- **"Network connection failed"**: For `{{.ToolRoles.remoteFetcher}}`, verify hostname/port accessibility and network connectivity.

### Validation Errors
- **"Certificate not trusted"**: Check if root CA certificates are properly installed or if the chain is incomplete.
- **"Signature verification failed"**: The certificate chain may be corrupted or contain invalid signatures.

### AI Analysis Errors
- **"API key not configured"**: Fall back to basic validation tools. Inform the user that AI features require `X509_AI_APIKEY` configuration.
- **"Analysis timeout"**: Retry with simpler analysis types or break complex requests into smaller parts.

### Resource Errors
- **"Server unavailable"**: Use `{{.ToolRoles.resourceMonitor}}` to check server status and CRL cache health.
- **"Memory limit exceeded"**: Reduce batch sizes or use individual processing instead of batch operations.

## Security considerations

You MUST prioritize security in all certificate operations:

1. **Never trust certificates without validation**: Always run `{{.ToolRoles.chainValidator}}` before accepting certificates as legitimate.

2. **Check revocation status**: Ensure OCSP/CRL mechanisms are properly configured and current.

3. **Monitor expiry dates**: Use appropriate warning thresholds (typically 30-90 days) based on certificate type and organizational policies.

4. **Analyze cryptographic strength**: Verify algorithms meet current security standards (avoid MD5, SHA-1, weak keys).

5. **Verify compliance**: Check adherence to CA/Browser Forum Baseline Requirements and NIST guidelines.

6. **Report security findings**: Clearly communicate any security issues, vulnerabilities, or compliance gaps with specific remediation steps.

## Tool selection guidelines

Choose the appropriate tool based on the task requirements:
{{range .Tools}}
- **`{{.Name}}`**: {{.Description}}
{{- end}}

## Configuration requirements

The server requires these configurations for full functionality:

- **Basic operation**: No configuration required
- **AI features**: Set `X509_AI_APIKEY` environment variable
- **Custom settings**: Set `MCP_X509_CONFIG_FILE` environment variable
- **CRL caching**: Automatically configured for optimal performance

## Response formatting

When presenting certificate analysis results:

1. **Start with summary**: Provide high-level certificate status and health overview
2. **Detail findings**: Break down issues by category (trust, validity, security, compliance)
3. **Include evidence**: Reference specific certificate fields, validation results, and security checks
4. **Provide recommendations**: Give actionable steps for remediation, prioritized by urgency
5. **Use structured format**: Organize information clearly with headings and bullet points

## Workflow verification

After completing any certificate analysis workflow:

1. **Verify completeness**: Ensure all required validation steps were performed
2. **Check consistency**: Confirm that tool results are consistent and logical
3. **Validate recommendations**: Ensure suggested actions are appropriate and feasible
4. **Document findings**: Provide clear summary of certificate status and next steps

Remember: Certificate security is critical for system integrity. Always err on the side of caution and recommend professional security review for high-risk findings.
