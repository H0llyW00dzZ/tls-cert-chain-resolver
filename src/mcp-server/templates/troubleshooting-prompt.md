# Troubleshooting Prompt Template

This template defines the workflow messages for certificate troubleshooting.

## Messages
{{if eq .IssueType "chain"}}
##### Assistant: Introduction
Troubleshooting certificate chain issues for: {{.CertificatePath}}

##### Assistant: Common Issues
Common chain issues:
• Missing intermediate certificates
• Incorrect certificate order
• Self-signed certificates in production
• Certificate authority not recognized

##### User: Resolution
Let's resolve the certificate chain to see what's available.
{{else if eq .IssueType "validation"}}
##### Assistant: Introduction
Troubleshooting certificate validation issues for: {{.CertificatePath}}

##### Assistant: Common Issues
Common validation issues:
• Certificate expired
• Certificate not yet valid
• Certificate revoked
• Untrusted certificate authority
• Hostname mismatch
• Invalid certificate signature

##### User: Validation
Let's validate the certificate chain to identify specific issues.
{{else if eq .IssueType "expiry"}}
##### Assistant: Introduction
Troubleshooting certificate expiry issues for: {{.CertificatePath}}

##### Assistant: Common Issues
Common expiry issues:
• Certificate already expired
• Certificate expiring soon
• Renewal process not completed
• Certificate not updated after renewal

##### User: Expiry Check
Let's check the expiration dates to identify certificates needing attention.
{{else if eq .IssueType "connection"}}
##### Assistant: Introduction
Troubleshooting TLS connection issues for: {{.Hostname}}

##### Assistant: Common Issues
Common connection issues:
• SSL/TLS handshake failure
• Certificate chain incomplete
• Server not presenting certificate
• Network connectivity issues
• Firewall blocking connections
• Incorrect port number

##### User: Connection Test
Let's try to fetch the certificate chain from the remote server.
{{else}}
##### Assistant: Error
Please specify a valid issue type: 'chain', 'validation', 'expiry', or 'connection'.
{{end}}
