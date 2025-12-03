// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// handleCertificateAnalysisPrompt handles the certificate analysis workflow prompt.
//
// This function implements the certificate-analysis prompt, which provides
// a comprehensive workflow for analyzing certificate chains. It guides users
// through systematic steps including chain resolution, validation, expiry checking,
// and result analysis.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - request: The MCP get prompt request containing arguments
//
// Returns:
//   - *mcp.GetPromptResult: The prompt result with workflow messages
//   - error: Any error that occurred during prompt handling
//
// The workflow includes:
//  1. Certificate chain resolution using resolve_cert_chain tool
//  2. Chain validation using validate_cert_chain tool
//  3. Expiry checking using check_cert_expiry tool
//  4. Result analysis and recommendations
//
// Expected arguments in request.Params.Arguments:
//   - certificate_path: Path to certificate file or base64-encoded certificate data
func handleCertificateAnalysisPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	certPath := request.Params.Arguments["certificate_path"]

	messages := []mcp.PromptMessage{
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(fmt.Sprintf(`I'll help you perform a comprehensive analysis of the certificate chain for: %s

Let's start with the basic chain resolution:`, certPath)),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`1. First, let's resolve the complete certificate chain to see all certificates in the hierarchy.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`Use the "resolve_cert_chain" tool to get the full certificate chain including all intermediates and optionally the root CA.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`2. Next, validate the certificate chain to ensure it's properly formed and trusted.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`Use the "validate_cert_chain" tool to check the chain's validity and trust status.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`3. Check for upcoming certificate expirations.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`Use the "check_cert_expiry" tool to identify certificates that are expired or expiring soon.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(`4. Analyze the results and provide recommendations for any issues found.`),
		),
	}

	return mcp.NewGetPromptResult(
		"Certificate Chain Analysis Workflow",
		messages,
	), nil
}

// handleExpiryMonitoringPrompt handles the expiry monitoring prompt.
//
// This function implements the expiry-monitoring prompt, which provides
// guidance for monitoring certificate expiration dates and generating
// renewal alerts based on configurable thresholds.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - request: The MCP get prompt request containing arguments
//
// Returns:
//   - *mcp.GetPromptResult: The prompt result with monitoring guidance
//   - error: Any error that occurred during prompt handling
//
// The prompt helps users:
//   - Identify certificates that have expired
//   - Find certificates expiring within the alert window
//   - Understand renewal timelines and recommendations
//
// Expected arguments in request.Params.Arguments:
//   - certificate_path: Path to certificate file or base64-encoded certificate data
//   - alert_days: Number of days before expiry to alert (default: 30)
func handleExpiryMonitoringPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	certPath := request.Params.Arguments["certificate_path"]
	alertDays := request.Params.Arguments["alert_days"]
	if alertDays == "" {
		alertDays = "30"
	}

	messages := []mcp.PromptMessage{
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(fmt.Sprintf(`I'll help you monitor certificate expiration for: %s with %s-day alert threshold.`, certPath, alertDays)),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`Use the "check_cert_expiry" tool to analyze expiration dates and identify certificates requiring attention.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(`Key things to look for:
• Certificates that have already expired
• Certificates expiring within the alert window
• Certificates that are still valid
• Recommended renewal timelines based on the results`),
		),
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(`Based on the results, I'll provide specific recommendations for certificate renewal and monitoring.`),
		),
	}

	return mcp.NewGetPromptResult(
		"Certificate Expiry Monitoring",
		messages,
	), nil
}

// handleSecurityAuditPrompt handles the security audit prompt.
//
// This function implements the security-audit prompt, which provides
// a comprehensive SSL/TLS security audit workflow for remote servers.
// It guides users through systematic security assessment including
// certificate chain validation, expiry checking, and security analysis.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - request: The MCP get prompt request containing arguments
//
// Returns:
//   - *mcp.GetPromptResult: The prompt result with audit workflow
//   - error: Any error that occurred during prompt handling
//
// The audit covers:
//   - Certificate chain validity and trust
//   - Certificate expiration status
//   - Certificate authority reputation
//   - Protocol and cipher suite support
//   - Certificate transparency compliance
//   - Proper hostname validation
//
// Expected arguments in request.Params.Arguments:
//   - hostname: Target hostname to audit
//   - port: Port number (default: 443)
func handleSecurityAuditPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	hostname := request.Params.Arguments["hostname"]
	port := request.Params.Arguments["port"]
	if port == "" {
		port = "443"
	}

	messages := []mcp.PromptMessage{
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(fmt.Sprintf(`I'll perform a comprehensive SSL/TLS security audit for %s:%s.`, hostname, port)),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`1. First, fetch the server's certificate chain.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`Use the "fetch_remote_cert" tool to retrieve the certificate chain presented by the server.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`2. Validate the certificate chain.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`Use the "validate_cert_chain" tool to verify the chain's validity and trust status.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`3. Check certificate expiration dates.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleUser,
			mcp.NewTextContent(`Use the "check_cert_expiry" tool to identify any expired or soon-to-expire certificates.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(`4. Analyze the results for security issues.`),
		),
		mcp.NewPromptMessage(
			mcp.RoleAssistant,
			mcp.NewTextContent(`Security considerations to evaluate:
• Certificate chain validity and trust
• Certificate expiration status
• Certificate authority reputation
• Protocol and cipher suite support (if available)
• Certificate transparency compliance
• Proper hostname validation`),
		),
	}

	return mcp.NewGetPromptResult(
		"SSL/TLS Security Audit",
		messages,
	), nil
}

// handleTroubleshootingPrompt handles the troubleshooting prompt.
//
// This function implements the troubleshooting prompt, which provides
// targeted guidance for common certificate and TLS issues based on
// the specified issue type. It offers context-specific troubleshooting
// steps and common solutions for different problem categories.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - request: The MCP get prompt request containing arguments
//
// Returns:
//   - *mcp.GetPromptResult: The prompt result with troubleshooting guidance
//   - error: Any error that occurred during prompt handling
//
// Supported issue types:
//   - chain: Missing intermediates, incorrect order, self-signed certificates
//   - validation: Expired certificates, untrusted CAs, hostname mismatches
//   - expiry: Certificates nearing expiration, renewal issues
//   - connection: Handshake failures, incomplete chains, network issues
//
// Expected arguments in request.Params.Arguments:
//   - issue_type: Type of issue ('chain', 'validation', 'expiry', 'connection')
//   - certificate_path: Path to certificate file (for chain/validation/expiry issues)
//   - hostname: Target hostname (for connection issues)
func handleTroubleshootingPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	issueType := request.Params.Arguments["issue_type"]
	certPath := request.Params.Arguments["certificate_path"]
	hostname := request.Params.Arguments["hostname"]

	var messages []mcp.PromptMessage

	switch issueType {
	case "chain":
		messages = []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(fmt.Sprintf(`Troubleshooting certificate chain issues for: %s`, certPath)),
			),
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(`Common chain issues:
• Missing intermediate certificates
• Incorrect certificate order
• Self-signed certificates in production
• Certificate authority not recognized`),
			),
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(`Let's resolve the certificate chain to see what's available.`),
			),
		}
	case "validation":
		messages = []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(fmt.Sprintf(`Troubleshooting certificate validation issues for: %s`, certPath)),
			),
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(`Common validation issues:
• Certificate expired
• Certificate not yet valid
• Certificate revoked
• Untrusted certificate authority
• Hostname mismatch
• Invalid certificate signature`),
			),
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(`Let's validate the certificate chain to identify specific issues.`),
			),
		}
	case "expiry":
		messages = []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(fmt.Sprintf(`Troubleshooting certificate expiry issues for: %s`, certPath)),
			),
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(`Common expiry issues:
• Certificate already expired
• Certificate expiring soon
• Renewal process not completed
• Certificate not updated after renewal`),
			),
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(`Let's check the expiration dates to identify certificates needing attention.`),
			),
		}
	case "connection":
		messages = []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(fmt.Sprintf(`Troubleshooting TLS connection issues for: %s`, hostname)),
			),
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(`Common connection issues:
• SSL/TLS handshake failure
• Certificate chain incomplete
• Server not presenting certificate
• Network connectivity issues
• Firewall blocking connections
• Incorrect port number`),
			),
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(`Let's try to fetch the certificate chain from the remote server.`),
			),
		}
	default:
		messages = []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(`Please specify a valid issue type: 'chain', 'validation', 'expiry', or 'connection'.`),
			),
		}
	}

	return mcp.NewGetPromptResult(
		"Certificate Troubleshooting Guide",
		messages,
	), nil
}
