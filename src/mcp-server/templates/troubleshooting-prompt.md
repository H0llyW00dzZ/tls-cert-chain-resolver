### Assistant: Certificate & TLS Troubleshooting Guide Overview
This conversation provides targeted diagnostic workflows for common certificate and TLS issues, with step-by-step troubleshooting procedures and resolution strategies.

**Issue Type**: {{.IssueType}}
**Certificate Path**: {{.CertificatePath}}
**Target Hostname**: {{.Hostname}}
**Diagnostic Approach**: Systematic problem isolation and resolution

{{if eq .IssueType "chain"}}
### Assistant: Certificate Chain Issues - Troubleshooting Workflow

**Problem Description:**
Certificate chain problems occur when the complete hierarchy of certificates (end-entity → intermediates → root) is not properly assembled or configured. This leads to trust failures and connection errors.

**Common Symptoms:**
- Browser shows "certificate not trusted" errors
- TLS handshake failures with "chain incomplete" messages
- Certificate validation errors in applications
- Intermediate certificate warnings in certificate tools

**Root Causes:**
- Missing intermediate certificates in server configuration
- Incorrect certificate chain ordering
- Self-signed certificates in production environments
- Certificate authority certificates not included
- Incomplete certificate bundle from CA

**Diagnostic Steps:**

**Step 1: Chain Resolution Analysis**
**Objective**: Determine what certificates are actually available

**Action Required**:
Use the `resolve_cert_chain` tool with certificate path `{{.CertificatePath}}` to:
- Load the provided certificate
- Attempt to fetch missing intermediates
- Assemble the complete chain if possible
- Identify missing certificates

**Expected Results**:
- Complete certificate chain (if resolvable)
- List of missing intermediate certificates
- Chain validation status

**Step 2: Chain Completeness Verification**
**Objective**: Verify all required certificates are present

**Analysis Questions**:
- Are all intermediate certificates included?
- Is the chain properly ordered (end-entity first)?
- Does the chain terminate at a trusted root?
- Are there any self-signed certificates inappropriately used?

**Step 3: Configuration Review**
**Objective**: Check server certificate configuration

**Server Configuration Checks**:
- Verify certificate bundle includes all intermediates
- Confirm certificate file contains full chain
- Check web server configuration for certificate directives
- Validate certificate installation process

**Resolution Strategies:**

**For Missing Intermediates:**
- Obtain complete certificate bundle from Certificate Authority
- Concatenate certificates in correct order: end-entity + intermediates
- Update server configuration with complete chain
- Restart services to load new certificate configuration

**For Ordering Issues:**
- Ensure end-entity certificate comes first in the bundle
- Follow intermediate certificate hierarchy order
- Verify concatenation doesn't include root certificates
- Test chain validation after reordering

**For Self-Signed Certificates:**
- Replace self-signed certificates with CA-issued certificates
- Implement proper certificate authority trust
- Update client trust stores if necessary
- Document exceptions for development environments

**Prevention Measures:**
- Always request complete certificate bundles from CAs
- Implement certificate chain validation in deployment pipelines
- Document certificate installation procedures
- Set up monitoring for certificate chain completeness

**Verification Steps:**
After implementing fixes:
1. Use `validate_cert_chain` tool to confirm chain validity
2. Test TLS connections from multiple clients
3. Verify certificate transparency logs
4. Monitor for recurring issues
{{else if eq .IssueType "validation"}}
### Assistant: Certificate Validation Issues - Troubleshooting Workflow

**Problem Description:**
Certificate validation failures occur when certificates cannot be cryptographically verified or don't meet trust requirements, preventing secure connections.

**Common Symptoms:**
- "Certificate verification failed" errors
- TLS handshake failures
- Application connection errors
- Certificate warning dialogs in browsers

**Root Causes:**
- Expired certificates
- Certificates not yet valid
- Revoked certificates
- Untrusted certificate authorities
- Hostname mismatches
- Invalid certificate signatures
- Cryptographic algorithm issues

**Diagnostic Steps:**

**Step 1: Comprehensive Validation**
**Objective**: Identify specific validation failures

**Action Required**:
Use the `validate_cert_chain` tool with certificate path `{{.CertificatePath}}` to:
- Perform complete cryptographic validation
- Check certificate validity periods
- Verify signature chains
- Assess trust relationships
- Identify specific failure points

**Expected Results**:
- Detailed validation report
- Specific error messages for each failure
- Certificate status information

**Step 2: Certificate Status Analysis**
**Objective**: Check certificate lifecycle status

**Status Checks**:
- Current date vs certificate validity period
- Certificate revocation status (OCSP/CRL)
- Certificate authority trust status
- Hostname validation requirements

**Step 3: Cryptographic Assessment**
**Objective**: Evaluate cryptographic strength and correctness

**Algorithm Verification**:
- Signature algorithm compatibility
- Key strength requirements
- Hash function security
- Certificate format correctness

**Resolution Strategies:**

**For Expired Certificates:**
- Immediately renew expired certificates
- Implement certificate expiry monitoring
- Set up automated renewal alerts
- Prepare emergency certificate procedures

**For Revoked Certificates:**
- Remove revoked certificates from service
- Obtain new certificates from CA
- Update certificate revocation lists
- Implement revocation checking

**For Trust Issues:**
- Verify certificate authority is trusted
- Update client trust stores if needed
- Consider certificate authority changes
- Implement certificate pinning strategies

**For Hostname Mismatches:**
- Verify certificate contains correct domain names
- Check Subject Alternative Name (SAN) extensions
- Update certificates with correct hostnames
- Implement proper wildcard certificate usage

**Advanced Analysis:**
For complex validation issues:
- Use `analyze_certificate_with_ai` tool with `security` analysis type
- Review certificate transparency logs
- Check certificate authority status
- Analyze cryptographic parameters

**Prevention Measures:**
- Implement automated certificate validation testing
- Set up certificate expiry monitoring
- Regular security audits of certificate configurations
- Maintain updated certificate authority trust stores
{{else if eq .IssueType "expiry"}}
### Assistant: Certificate Expiration Issues - Troubleshooting Workflow

**Problem Description:**
Certificate expiration issues cause service outages and security gaps when certificates are not renewed before their validity periods end.

**Common Symptoms:**
- Sudden TLS connection failures
- Certificate expiry warnings in browsers
- Application connectivity issues
- Security monitoring alerts

**Root Causes:**
- Missed renewal deadlines
- Incomplete renewal processes
- Certificate authority delays
- Lack of expiry monitoring
- Manual renewal process failures

**Diagnostic Steps:**

**Step 1: Expiration Timeline Analysis**
**Objective**: Determine certificate expiration status and timelines

**Action Required**:
Use the `check_cert_expiry` tool with certificate path `{{.CertificatePath}}` to:
- Analyze expiration dates for all certificates in chain
- Identify certificates already expired
- Flag certificates expiring soon
- Assess renewal urgency levels

**Expected Results**:
- Detailed expiration report
- Days remaining for each certificate
- Renewal priority recommendations

**Step 2: Renewal Process Review**
**Objective**: Evaluate renewal procedures and timelines

**Process Analysis**:
- Certificate authority renewal procedures
- Required documentation and validation
- Processing timeframes
- Cost and budget considerations

**Step 3: Impact Assessment**
**Objective**: Evaluate business and security impact of expirations

**Impact Evaluation**:
- Service availability risks
- Customer experience impact
- Compliance requirements
- Security vulnerability windows

**Resolution Strategies:**

**Emergency Renewal (Expired Certificates):**
- Contact certificate authority immediately
- Request expedited certificate issuance
- Prepare emergency certificate installation
- Implement temporary security measures

**Urgent Renewal (Expiring < 30 days):**
- Initiate renewal process immediately
- Gather all required documentation
- Coordinate with certificate authority
- Schedule maintenance windows

**Planned Renewal (Expiring 30-90 days):**
- Follow standard renewal procedures
- Prepare documentation in advance
- Coordinate with stakeholders
- Plan for minimal service disruption

**Scheduled Renewal (Expiring > 90 days):**
- Add to regular maintenance schedule
- Monitor expiration approach
- Prepare renewal materials

**Automation Recommendations:**
- Implement automated expiry monitoring
- Set up renewal alerts (90, 60, 30, 14, 7 days)
- Consider automated renewal services
- Establish certificate lifecycle management

**Prevention Measures:**
- Certificate expiry monitoring and alerting
- Automated renewal workflows
- Certificate inventory management
- Regular renewal schedule planning
- Backup certificate procedures
{{else if eq .IssueType "connection"}}
### Assistant: TLS Connection Issues - Troubleshooting Workflow

**Problem Description:**
TLS connection failures occur when clients cannot establish secure connections to servers, often due to certificate or TLS configuration problems.

**Common Symptoms:**
- Connection timeout errors
- SSL/TLS handshake failures
- Certificate-related error messages
- Browser security warnings
- Application connection failures

**Root Causes:**
- Certificate chain issues
- Server configuration problems
- Network connectivity issues
- Firewall blocking TLS traffic
- Incorrect port configurations
- Client trust store issues

**Diagnostic Steps:**

**Step 1: Certificate Chain Retrieval**
**Objective**: Obtain server's certificate configuration

**Action Required**:
Use the `fetch_remote_cert` tool to retrieve certificate information:
- Hostname: `{{.Hostname}}`
- Port: 443 (or specified port)

**Expected Results**:
- Server's presented certificate chain
- Connection status and errors
- Certificate details and validity

**Step 2: Chain Validation**
**Objective**: Verify certificate chain integrity

**Action Required**:
Use the `validate_cert_chain` tool on the retrieved certificates to:
- Check cryptographic validity
- Verify trust relationships
- Identify validation failures
- Assess chain completeness

**Step 3: Connection Testing**
**Objective**: Test actual TLS connection behavior

**Testing Methods**:
- Use different TLS client tools
- Test from multiple network locations
- Verify port accessibility
- Check firewall configurations

**Step 4: Server Configuration Review**
**Objective**: Verify server TLS configuration

**Configuration Checks**:
- Certificate file paths and permissions
- TLS protocol versions supported
- Cipher suite configurations
- Server software version and patches

**Resolution Strategies:**

**For Certificate Chain Issues:**
- Ensure complete certificate chain is configured
- Verify certificate file contains all required certificates
- Check certificate file permissions
- Restart server services after configuration changes

**For Server Configuration Problems:**
- Verify TLS configuration syntax
- Check certificate file paths
- Validate certificate file formats
- Review server logs for TLS errors

**For Network and Firewall Issues:**
- Verify port accessibility (usually 443 for HTTPS)
- Check firewall rules for TLS traffic
- Test connectivity from different networks
- Review proxy server configurations

**For Client Trust Issues:**
- Update client trust stores
- Verify certificate authority trust
- Check for certificate pinning conflicts
- Review client TLS configuration

**Advanced Diagnostics:**
For complex connection issues:
- Use network packet capture tools
- Analyze TLS handshake messages
- Check certificate transparency logs
- Review server access logs

**Prevention Measures:**
- Regular certificate validation testing
- Automated monitoring of TLS configurations
- Certificate expiry alerting
- Regular security configuration reviews
- Documentation of TLS troubleshooting procedures
{{else}}
### Assistant: Invalid Issue Type Specified

**Error: Unrecognized Issue Type**
The specified issue type `{{.IssueType}}` is not recognized.

**Valid Issue Types:**
Please specify one of the following issue types:
- `chain` - Certificate chain completeness and ordering issues
- `validation` - Certificate cryptographic validation failures
- `expiry` - Certificate expiration and renewal problems
- `connection` - TLS connection establishment failures

**How to Use This Troubleshooting Guide:**
1. Identify your specific certificate or TLS issue
2. Choose the most appropriate issue type from the list above
3. Provide the relevant certificate path or hostname
4. Follow the systematic troubleshooting workflow
{{end}}

### Assistant: General Troubleshooting Best Practices

**Documentation & Communication:**
- Document all troubleshooting steps and findings
- Communicate issues and resolutions to stakeholders
- Maintain incident response records
- Update knowledge base with new issues encountered

**Testing & Verification:**
- Always test fixes in staging environments first
- Verify resolutions work from multiple client types
- Monitor systems after implementing fixes
- Validate that issues don't recur

**Prevention & Monitoring:**
- Implement proactive certificate monitoring
- Set up automated validation checks
- Regular security audits and reviews
- Maintain updated incident response procedures

### Assistant: Next Steps
Please provide the results from the diagnostic steps above, and I'll help you:
- Interpret the findings
- Develop specific resolution plans
- Implement fixes and workarounds
- Prevent similar issues in the future

If you need help with any specific step or have additional context about your issue, please let me know.
