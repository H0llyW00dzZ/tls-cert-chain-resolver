// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"
	"html/template"
	"strings"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/mark3labs/mcp-go/mcp"
)

// promptTemplateData holds the data used to populate prompt templates.
type promptTemplateData struct {
	CertificatePath string
	AlertDays       string
	Hostname        string
	Port            string
	IssueType       string
}

// parsePromptTemplate parses a prompt template file and converts it to MCP messages.
//
// This function reads a template file from the embedded filesystem, executes
// it with the provided data, and converts the structured content into MCP prompt messages.
// The template-based approach enables dynamic content generation instead of hardcoded values,
// making prompts more maintainable and flexible.
//
// Parameters:
//   - templateName: Name of the template file (without .md extension)
//   - data: Template data to populate placeholders
//
// Returns:
//   - []mcp.PromptMessage: Parsed MCP messages
//   - error: Any error during template execution or parsing
func parsePromptTemplate(templateName string, data promptTemplateData) ([]mcp.PromptMessage, error) {
	// Read the template file
	templateContent, err := templates.MagicEmbed.ReadFile(templateName + ".md")
	if err != nil {
		return nil, fmt.Errorf("failed to read template %s: %w", templateName, err)
	}

	// Parse the template
	tmpl, err := template.New(templateName).Parse(string(templateContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %w", templateName, err)
	}

	// Execute the template
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	content := buf.String()

	// Parse the executed content into MCP messages
	var messages []mcp.PromptMessage
	lines := strings.Split(content, "\n")
	var currentRole mcp.Role
	var currentContent strings.Builder

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for role markers first (before skipping headers)
		if strings.HasPrefix(line, "### Assistant:") || strings.HasPrefix(line, "##### Assistant:") {
			// Save previous message if any
			if currentContent.Len() > 0 {
				messages = append(messages, mcp.NewPromptMessage(
					currentRole,
					mcp.NewTextContent(strings.TrimSpace(currentContent.String())),
				))
				currentContent.Reset()
			}
			currentRole = mcp.RoleAssistant
			continue
		}

		if strings.HasPrefix(line, "### User:") || strings.HasPrefix(line, "##### User:") {
			// Save previous message if any
			if currentContent.Len() > 0 {
				messages = append(messages, mcp.NewPromptMessage(
					currentRole,
					mcp.NewTextContent(strings.TrimSpace(currentContent.String())),
				))
				currentContent.Reset()
			}
			currentRole = mcp.RoleUser
			continue
		}

		// Skip empty lines and headers
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Add line to current content if we have a role
		if currentRole != "" {
			if currentContent.Len() > 0 {
				currentContent.WriteString("\n")
			}
			currentContent.WriteString(line)
		}
	}

	// Add final message if any
	if currentContent.Len() > 0 {
		messages = append(messages, mcp.NewPromptMessage(
			currentRole,
			mcp.NewTextContent(strings.TrimSpace(currentContent.String())),
		))
	}

	return messages, nil
}

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

	messages, err := parsePromptTemplate("certificate-analysis-prompt", promptTemplateData{
		CertificatePath: certPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate analysis template: %w", err)
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

	messages, err := parsePromptTemplate("expiry-monitoring-prompt", promptTemplateData{
		CertificatePath: certPath,
		AlertDays:       alertDays,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry monitoring template: %w", err)
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

	messages, err := parsePromptTemplate("security-audit-prompt", promptTemplateData{
		Hostname: hostname,
		Port:     port,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse security audit template: %w", err)
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

	messages, err := parsePromptTemplate("troubleshooting-prompt", promptTemplateData{
		IssueType:       issueType,
		CertificatePath: certPath,
		Hostname:        hostname,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse troubleshooting template: %w", err)
	}

	return mcp.NewGetPromptResult(
		"Certificate Troubleshooting Guide",
		messages,
	), nil
}
