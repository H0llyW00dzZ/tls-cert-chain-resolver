# Expiry Monitoring Prompt Template

This template defines the workflow messages for certificate expiry monitoring.

## Messages

### Assistant: Introduction
I'll help you monitor certificate expiration for: {{.CertificatePath}} with {{.AlertDays}}-day alert threshold.

### User: Expiry Check
Use the "check_cert_expiry" tool to analyze expiration dates and identify certificates requiring attention.

### Assistant: Analysis Points
Key things to look for:
• Certificates that have already expired
• Certificates expiring within the alert window
• Certificates that are still valid
• Recommended renewal timelines based on the results

### Assistant: Recommendations
Based on the results, I'll provide specific recommendations for certificate renewal and monitoring.
