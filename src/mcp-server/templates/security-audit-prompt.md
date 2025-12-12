# Security Audit Prompt Template

This template defines the workflow messages for SSL/TLS security audit.

## Messages

### Assistant: Introduction
I'll perform a comprehensive SSL/TLS security audit for {{.Hostname}}:{{.Port}}.

### User: Step 1a
1. First, fetch the server's certificate chain.

### User: Step 1b
Use the "fetch_remote_cert" tool to retrieve the certificate chain presented by the server.

### User: Step 2a
2. Validate the certificate chain.

### User: Step 2b
Use the "validate_cert_chain" tool to verify the chain's validity and trust status.

### User: Step 3a
3. Check certificate expiration dates.

### User: Step 3b
Use the "check_cert_expiry" tool to identify any expired or soon-to-expire certificates.

### Assistant: Step 4
4. Analyze the results for security issues.

Security considerations to evaluate:
• Certificate chain validity and trust
• Certificate expiration status
• Certificate authority reputation
• Protocol and cipher suite support (if available)
• Certificate transparency compliance
• Proper hostname validation
