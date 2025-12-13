// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/mark3labs/mcp-go/mcp"
)

// promptTemplateData holds the data used to populate prompt templates.
// Using map[string]any for maximum flexibility, type safety, and cleaner field naming.
// This allows different prompts to use different field names without struct field reuse.
type promptTemplateData map[string]any

// templateCache provides thread-safe caching of parsed templates to improve performance.
// Templates are parsed once and reused across multiple calls.
var templateCache sync.Map // map[string]*template.Template

// detectRoleMarker checks if a line starts with a role marker and returns the role.
func detectRoleMarker(line string) mcp.Role {
	if strings.HasPrefix(line, "### Assistant:") || strings.HasPrefix(line, "##### Assistant:") {
		return mcp.RoleAssistant
	}
	if strings.HasPrefix(line, "### User:") || strings.HasPrefix(line, "##### User:") {
		return mcp.RoleUser
	}
	return ""
}

// parsePromptTemplate parses a prompt template file and converts it to MCP messages.
//
// This function reads a template file from the embedded filesystem, executes
// it with the provided data, and converts the structured content into MCP prompt messages.
// The template-based approach enables dynamic content generation instead of hardcoded values,
// making prompts more maintainable and flexible.
//
// Templates are cached for performance and thread safety. Each execution uses a cloned
// template to avoid sharing state between concurrent calls.
//
// Parameters:
//   - templateName: Name of the template file (without .md extension)
//   - data: Template data to populate placeholders (map[string]any)
//
// Returns:
//   - []mcp.PromptMessage: Parsed MCP messages
//   - error: Any error during template execution or parsing
func parsePromptTemplate(templateName string, data promptTemplateData) ([]mcp.PromptMessage, error) {
	// Try to get cached template first
	cachedTmpl, found := templateCache.Load(templateName)
	var tmpl *template.Template

	if found {
		// Clone the cached template for thread safety
		tmpl = cachedTmpl.(*template.Template)
		cloned, err := tmpl.Clone()
		if err != nil {
			return nil, fmt.Errorf("failed to clone cached template %s: %w", templateName, err)
		}
		tmpl = cloned
	} else {
		// Read and parse template, then cache it
		templateContent, err := templates.MagicEmbed.ReadFile(templateName + ".md")
		if err != nil {
			return nil, fmt.Errorf("failed to read template %s: %w", templateName, err)
		}

		tmpl, err = template.New(templateName).Parse(string(templateContent))
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", templateName, err)
		}

		// Cache the parsed template for future use
		templateCache.Store(templateName, tmpl)

		// Clone for this execution to avoid sharing state
		cloned, err := tmpl.Clone()
		if err != nil {
			return nil, fmt.Errorf("failed to clone template %s: %w", templateName, err)
		}
		tmpl = cloned
	}

	// Execute the template
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	content := buf.String()

	// Parse the executed content into MCP messages using efficient line-by-line processing
	var messages []mcp.PromptMessage
	contentLen := len(content)
	pos := 0
	var currentRole mcp.Role
	var currentContent strings.Builder

	for pos < contentLen {
		// Find the next newline
		lineEnd := strings.Index(content[pos:], "\n")
		if lineEnd == -1 {
			lineEnd = contentLen - pos
		}

		// Extract the line
		line := content[pos : pos+lineEnd]
		line = strings.TrimSpace(line)
		pos += lineEnd + 1 // +1 for the newline character

		// Check for role markers first (before skipping headers)
		if role := detectRoleMarker(line); role != "" {
			// Save previous message if any
			if currentContent.Len() > 0 {
				messages = append(messages, mcp.NewPromptMessage(
					currentRole,
					mcp.NewTextContent(strings.TrimSpace(currentContent.String())),
				))
				currentContent.Reset()
			}
			currentRole = role
			continue
		}

		// Skip headers only (preserve empty lines for markdown formatting)
		if strings.HasPrefix(line, "#") {
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
		"CertificatePath": certPath,
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
	alertDaysStr := request.Params.Arguments["alert_days"]

	// Convert to int for type flexibility (template will convert back to string)
	alertDays := 30 // default
	if alertDaysStr != "" {
		if parsed, err := strconv.Atoi(alertDaysStr); err == nil {
			alertDays = parsed
		}
	}

	messages, err := parsePromptTemplate("expiry-monitoring-prompt", promptTemplateData{
		"CertificatePath": certPath,
		"AlertDays":       alertDays, // Now passing int instead of string
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
	portStr := request.Params.Arguments["port"]

	// Convert to int for type flexibility (template will convert back to string)
	port := 443 // default
	if portStr != "" {
		if parsed, err := strconv.Atoi(portStr); err == nil {
			port = parsed
		}
	}

	messages, err := parsePromptTemplate("security-audit-prompt", promptTemplateData{
		"Hostname": hostname,
		"Port":     port, // Now passing int instead of string
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
		"IssueType":       issueType,
		"CertificatePath": certPath,
		"Hostname":        hostname,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse troubleshooting template: %w", err)
	}

	return mcp.NewGetPromptResult(
		"Certificate Troubleshooting Guide",
		messages,
	), nil
}

// handleResourceMonitoringPrompt handles the resource monitoring prompt.
//
// This function implements the resource-monitoring prompt, which provides
// comprehensive guidance for monitoring server resource usage and performance
// metrics in the context of certificate operations. It helps users understand
// when and how to monitor resources, interpret metrics, and optimize performance.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - request: The MCP get prompt request containing arguments
//
// Returns:
//   - *mcp.GetPromptResult: The prompt result with resource monitoring guidance
//   - error: Any error that occurred during prompt handling
//
// The prompt covers:
//   - When to monitor resources (performance issues, memory leaks, optimization)
//   - How to interpret memory, GC, and CRL cache metrics
//   - Best practices for resource management in certificate operations
//   - Format preferences for different monitoring contexts
//
// Expected arguments in request.Params.Arguments:
//   - monitoring_context: Context for monitoring ('debugging', 'optimization', 'routine', 'troubleshooting') - maps to MonitoringContext in template
//   - format_preference: Preferred output format ('json' or 'markdown', default: json) - maps to FormatPreference in template
func handleResourceMonitoringPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	monitoringContext := request.Params.Arguments["monitoring_context"]
	formatPreference := request.Params.Arguments["format_preference"]
	if formatPreference == "" {
		formatPreference = "json"
	}

	messages, err := parsePromptTemplate("resource-monitoring-prompt", promptTemplateData{
		"MonitoringContext": monitoringContext, // Clear field name
		"FormatPreference":  formatPreference,  // Clear field name
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse resource monitoring template: %w", err)
	}

	return mcp.NewGetPromptResult(
		"Resource Monitoring and Performance Analysis",
		messages,
	), nil
}
