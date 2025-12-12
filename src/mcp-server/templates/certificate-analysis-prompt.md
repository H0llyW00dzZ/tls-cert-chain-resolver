# Certificate Analysis Prompt Template

This template defines the workflow messages for comprehensive certificate chain analysis.

## Messages

### Assistant: Introduction
I'll guide you through a systematic analysis of the certificate chain for: {{.CertificatePath}}

This comprehensive workflow will help you:
• Understand the complete certificate hierarchy
• Verify trust relationships and validity
• Identify expiration risks
• Receive actionable recommendations

Let's begin with chain resolution to establish the foundation:

### User: Step 1a
**Chain Resolution**: We need to resolve the complete certificate chain to see all certificates in the hierarchy, from the end-entity certificate through all intermediates to the root CA.

### User: Step 1b
Use the "resolve_cert_chain" tool to fetch and assemble the full certificate chain. This tool will automatically retrieve any missing intermediate certificates and present the complete hierarchy.

### User: Step 2a
**Chain Validation**: Now that we have the complete chain, let's validate it to ensure proper cryptographic relationships and trust status.

### User: Step 2b
Use the "validate_cert_chain" tool to perform comprehensive validation including:
• Signature verification for each certificate
• Proper chain ordering and relationships
• Trust anchor verification against system root stores
• Detection of any certificate issues

### User: Step 3a
**Expiration Analysis**: Certificate expiration is critical for maintaining secure communications. Let's check all certificates in the chain for expiration status.

### User: Step 3b
Use the "check_cert_expiry" tool to analyze expiration dates and identify:
• Certificates that have already expired
• Certificates expiring within warning periods
• Long-term expiration outlook for the entire chain

### Assistant: Step 4
**Analysis & Recommendations**: Now that we have complete chain, validation, and expiration information, let's analyze the results and provide specific recommendations.

**Key Analysis Points:**
• **Chain Completeness**: Are all required intermediate certificates present?
• **Trust Status**: Is the chain trusted by standard root stores?
• **Expiration Timeline**: What certificates need renewal and when?
• **Security Posture**: Any immediate security concerns?

**Next Steps:**
• Address any validation failures identified
• Plan certificate renewals based on expiration analysis
• Consider certificate authority changes if trust issues exist
• Implement monitoring for upcoming expirations

Please review the results from each step above and let me know what specific aspects you'd like to focus on or if you need help implementing any recommendations.
