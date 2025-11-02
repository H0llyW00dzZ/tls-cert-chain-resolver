// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// createPrompts creates and returns all MCP prompt definitions with their handlers
func createPrompts() []server.ServerPrompt {
	return []server.ServerPrompt{
		{
			Prompt: mcp.NewPrompt("certificate-analysis",
				mcp.WithPromptDescription("Comprehensive certificate chain analysis workflow"),
				mcp.WithArgument("certificate_path",
					mcp.ArgumentDescription("Path to certificate file or base64-encoded certificate data"),
				),
			),
			Handler: handleCertificateAnalysisPrompt,
		},
		{
			Prompt: mcp.NewPrompt("expiry-monitoring",
				mcp.WithPromptDescription("Monitor certificate expiration dates and generate renewal alerts"),
				mcp.WithArgument("certificate_path",
					mcp.ArgumentDescription("Path to certificate file or base64-encoded certificate data"),
				),
				mcp.WithArgument("alert_days",
					mcp.ArgumentDescription("Number of days before expiry to alert (default: 30)"),
				),
			),
			Handler: handleExpiryMonitoringPrompt,
		},
		{
			Prompt: mcp.NewPrompt("security-audit",
				mcp.WithPromptDescription("Perform comprehensive SSL/TLS security audit on a server"),
				mcp.WithArgument("hostname",
					mcp.ArgumentDescription("Target hostname to audit"),
				),
				mcp.WithArgument("port",
					mcp.ArgumentDescription("Port number (default: 443)"),
				),
			),
			Handler: handleSecurityAuditPrompt,
		},
		{
			Prompt: mcp.NewPrompt("troubleshooting",
				mcp.WithPromptDescription("Troubleshoot common certificate and TLS issues"),
				mcp.WithArgument("issue_type",
					mcp.ArgumentDescription("Type of issue: 'chain', 'validation', 'expiry', 'connection'"),
				),
				mcp.WithArgument("certificate_path",
					mcp.ArgumentDescription("Path to certificate file or base64-encoded certificate data (for chain/validation/expiry issues)"),
				),
				mcp.WithArgument("hostname",
					mcp.ArgumentDescription("Target hostname (for connection issues)"),
				),
			),
			Handler: handleTroubleshootingPrompt,
		},
	}
}

// handleCertificateAnalysisPrompt handles the certificate analysis workflow prompt
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

// handleExpiryMonitoringPrompt handles the expiry monitoring prompt
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

// handleSecurityAuditPrompt handles the security audit prompt
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

// handleTroubleshootingPrompt handles the troubleshooting prompt
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
