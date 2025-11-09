// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// MagicEmbed provides access to embedded template files
//
//go:embed templates
var MagicEmbed embed.FS

func handleResolveCertChain(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract arguments
	certInput, err := request.RequireString("certificate")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificate parameter required: %v", err)), nil
	}

	format := request.GetString("format", "pem")
	includeSystemRoot := request.GetBool("include_system_root", false)
	intermediateOnly := request.GetBool("intermediate_only", false)

	// Read certificate data
	var certData []byte

	// Try to read as file first
	if fileData, err := os.ReadFile(certInput); err == nil {
		certData = fileData
	} else {
		// Try to decode as base64
		if decoded, err := base64.StdEncoding.DecodeString(certInput); err == nil {
			certData = decoded
		} else {
			return mcp.NewToolResultError("failed to read certificate: not a valid file path or base64 data"), nil
		}
	}

	// Decode certificate
	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to decode certificate: %v", err)), nil
	}

	// Fetch certificate chain
	chain := x509chain.New(cert, version.Version)
	if err := chain.FetchCertificate(ctx); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch certificate chain: %v", err)), nil
	}

	// Optionally add system root CA
	if includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to add root CA: %v", err)), nil
		}
	}

	// Filter certificates if needed
	certs := chain.Certs
	if intermediateOnly {
		certs = chain.FilterIntermediates()
	}

	// Format output
	var output string
	switch format {
	case "der":
		derData := certManager.EncodeMultipleDER(certs)
		output = base64.StdEncoding.EncodeToString(derData)
	case "json":
		output = formatJSON(certs, certManager)
	default: // pem
		pemData := certManager.EncodeMultiplePEM(certs)
		output = string(pemData)
	}

	// Build result with chain information
	chainInfo := "Certificate chain resolved successfully:\n"
	for i, c := range certs {
		chainInfo += fmt.Sprintf("%d: %s\n", i+1, c.Subject.CommonName)
	}
	chainInfo += fmt.Sprintf("\nTotal: %d certificate(s)\n\n", len(certs))
	chainInfo += output

	return mcp.NewToolResultText(chainInfo), nil
}

func handleValidateCertChain(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract arguments
	certInput, err := request.RequireString("certificate")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificate parameter required: %v", err)), nil
	}

	includeSystemRoot := request.GetBool("include_system_root", true)

	// Read certificate data
	var certData []byte

	// Try to read as file first
	if fileData, err := os.ReadFile(certInput); err == nil {
		certData = fileData
	} else {
		// Try to decode as base64
		if decoded, err := base64.StdEncoding.DecodeString(certInput); err == nil {
			certData = decoded
		} else {
			return mcp.NewToolResultError("failed to read certificate: not a valid file path or base64 data"), nil
		}
	}

	// Decode certificate
	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to decode certificate: %v", err)), nil
	}

	// Create chain and fetch certificates
	chain := x509chain.New(cert, version.Version)
	if err := chain.FetchCertificate(ctx); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch certificate chain: %v", err)), nil
	}

	// Add system root if requested
	if includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to add root CA: %v", err)), nil
		}
	}

	// Validate the chain
	if err := chain.VerifyChain(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificate chain validation failed: %v", err)), nil
	}

	// Check revocation status
	revocationStatus, err := chain.CheckRevocationStatus(ctx)
	if err != nil {
		// Log error but don't fail - revocation checking is optional
		revocationStatus = fmt.Sprintf("Revocation check failed: %v", err)
	}

	// Build success result
	result := "Certificate chain validation successful!\n\n"
	result += "Chain Details:\n"
	for i, c := range chain.Certs {
		result += fmt.Sprintf("%d: %s\n", i+1, c.Subject.CommonName)
		result += fmt.Sprintf("   Valid: %s to %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
		if chain.IsRootNode(c) {
			result += "   Type: Root CA\n"
		} else if chain.IsSelfSigned(c) {
			result += "   Type: Self-signed\n"
		} else {
			result += "   Type: Intermediate\n"
		}
	}
	result += fmt.Sprintf("\nTotal certificates: %d\n", len(chain.Certs))
	result += "Validation: PASSED ✓\n\n"
	result += revocationStatus

	return mcp.NewToolResultText(result), nil
}

func handleBatchResolveCertChain(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract arguments
	certInput, err := request.RequireString("certificates")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificates parameter required: %v", err)), nil
	}

	format := request.GetString("format", "pem")
	includeSystemRoot := request.GetBool("include_system_root", false)
	intermediateOnly := request.GetBool("intermediate_only", false)

	// Parse comma-separated certificate inputs
	certInputs := strings.Split(certInput, ",")
	for i, input := range certInputs {
		certInputs[i] = strings.TrimSpace(input)
	}

	// Process each certificate
	results := make([]string, 0, len(certInputs))

	for i, certInput := range certInputs {
		if certInput == "" {
			continue
		}

		result := fmt.Sprintf("Certificate %d:\n", i+1)

		// Read certificate data
		var certData []byte

		// Try to read as file first
		if fileData, err := os.ReadFile(certInput); err == nil {
			certData = fileData
		} else {
			// Try to decode as base64
			if decoded, err := base64.StdEncoding.DecodeString(certInput); err == nil {
				certData = decoded
			} else {
				result += "  Error: failed to read certificate: not a valid file path or base64 data\n"
				results = append(results, result)
				continue
			}
		}

		// Decode certificate
		certManager := x509certs.New()
		cert, err := certManager.Decode(certData)
		if err != nil {
			result += fmt.Sprintf("  Error: failed to decode certificate: %v\n", err)
			results = append(results, result)
			continue
		}

		// Fetch certificate chain
		chain := x509chain.New(cert, version.Version)
		if err := chain.FetchCertificate(ctx); err != nil {
			result += fmt.Sprintf("  Error: failed to fetch certificate chain: %v\n", err)
			results = append(results, result)
			continue
		}

		// Optionally add system root CA
		if includeSystemRoot {
			if err := chain.AddRootCA(); err != nil {
				result += fmt.Sprintf("  Warning: failed to add root CA: %v\n", err)
			}
		}

		// Filter certificates if needed
		certs := chain.Certs
		if intermediateOnly {
			certs = chain.FilterIntermediates()
		}

		// Format output
		switch format {
		case "der":
			derData := certManager.EncodeMultipleDER(certs)
			result += fmt.Sprintf("  Format: DER (%d bytes)\n", len(derData))
		case "json":
			result += "  Format: JSON\n" + formatJSON(certs, certManager)
		default: // pem
			pemData := certManager.EncodeMultiplePEM(certs)
			result += fmt.Sprintf("  Format: PEM\n%s", string(pemData))
		}

		result += fmt.Sprintf("  Chain: %d certificate(s)\n", len(certs))
		results = append(results, result)
	}

	// Combine all results
	finalResult := "Batch Certificate Chain Resolution Results:\n"
	finalResult += fmt.Sprintf("Processed %d certificate(s)\n\n", len(certInputs))
	finalResult += strings.Join(results, "\n")

	return mcp.NewToolResultText(finalResult), nil
}

func handleFetchRemoteCert(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	// Extract arguments
	hostname, err := request.RequireString("hostname")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("hostname parameter required: %v", err)), nil
	}

	port := request.GetInt("port", 443)

	format := request.GetString("format", config.Defaults.Format)
	includeSystemRoot := request.GetBool("include_system_root", config.Defaults.IncludeSystemRoot)
	intermediateOnly := request.GetBool("intermediate_only", config.Defaults.IntermediateOnly)

	chain, certs, err := x509chain.FetchRemoteChain(ctx, hostname, port, time.Duration(config.Defaults.Timeout)*time.Second, version.Version)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Fetch any additional certificates if needed
	if err := chain.FetchCertificate(ctx); err != nil {
		// This might fail if intermediates are already complete, which is ok
		// We'll proceed with what we have
	}

	// Optionally add system root CA
	if includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to add root CA: %v", err)), nil
		}
	}

	// Filter certificates if needed
	filteredCerts := chain.Certs
	if intermediateOnly {
		filteredCerts = chain.FilterIntermediates()
	}

	// Format output
	var output string
	certManager := x509certs.New()

	result := "Remote Certificate Fetch Results:\n"
	result += fmt.Sprintf("Host: %s:%d\n", hostname, port)
	result += fmt.Sprintf("Certificates received: %d\n", len(certs))
	result += fmt.Sprintf("Certificates after filtering: %d\n\n", len(filteredCerts))

	switch format {
	case "der":
		derData := certManager.EncodeMultipleDER(filteredCerts)
		output = base64.StdEncoding.EncodeToString(derData)
		result += "Format: DER (base64 encoded)\n\n" + output
	case "json":
		output = formatJSON(filteredCerts, certManager)
		result += "Format: JSON\n\n" + output
	default: // pem
		pemData := certManager.EncodeMultiplePEM(filteredCerts)
		output = string(pemData)
		result += "Format: PEM\n\n" + output
	}

	result += fmt.Sprintf("\nTotal certificates in chain: %d", len(filteredCerts))

	return mcp.NewToolResultText(result), nil
}

func handleCheckCertExpiry(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	// Extract arguments
	certInput, err := request.RequireString("certificate")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificate parameter required: %v", err)), nil
	}

	warnDaysStr := request.GetString("warn_days", strconv.Itoa(config.Defaults.WarnDays))
	warnDays, err := strconv.Atoi(warnDaysStr)
	if err != nil {
		warnDays = config.Defaults.WarnDays // fallback to config default
	}

	// Read certificate data
	var certData []byte

	// Try to read as file first
	if fileData, err := os.ReadFile(certInput); err == nil {
		certData = fileData
	} else {
		// Try to decode as base64
		if decoded, err := base64.StdEncoding.DecodeString(certInput); err == nil {
			certData = decoded
		} else {
			return mcp.NewToolResultError("failed to read certificate: not a valid file path or base64 data"), nil
		}
	}

	// Decode certificate(s) - could be a bundle
	certManager := x509certs.New()
	certs, err := certManager.DecodeMultiple(certData)
	if err != nil {
		// Try single cert
		cert, err := certManager.Decode(certData)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to decode certificate: %v", err)), nil
		}
		certs = []*x509.Certificate{cert}
	}

	// Check expiry for each certificate
	result := "Certificate Expiry Check Results:\n\n"
	now := time.Now()

	allValid := true
	expiringSoonCount := 0
	expiredCount := 0

	for i, cert := range certs {
		result += fmt.Sprintf("Certificate %d: %s\n", i+1, cert.Subject.CommonName)
		result += fmt.Sprintf("  Issued: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		result += fmt.Sprintf("  Expires: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

		if now.After(cert.NotAfter) {
			result += fmt.Sprintf("  Status: EXPIRED (%d days ago)\n", -daysUntilExpiry)
			expiredCount++
			allValid = false
		} else if daysUntilExpiry <= warnDays {
			result += fmt.Sprintf("  Status: EXPIRING SOON (%d days remaining)\n", daysUntilExpiry)
			expiringSoonCount++
			allValid = false
		} else {
			result += fmt.Sprintf("  Status: VALID (%d days remaining)\n", daysUntilExpiry)
		}
		result += "\n"
	}

	// Summary
	result += "Summary:\n"
	result += fmt.Sprintf("- Total certificates checked: %d\n", len(certs))
	result += fmt.Sprintf("- Expired: %d\n", expiredCount)
	result += fmt.Sprintf("- Expiring within %d days: %d\n", warnDays, expiringSoonCount)
	result += fmt.Sprintf("- Valid: %d\n", len(certs)-expiredCount-expiringSoonCount)

	if allValid {
		result += "\n✓ All certificates are valid and not expiring soon."
	} else {
		result += "\n⚠️  Some certificates require attention."
	}

	return mcp.NewToolResultText(result), nil
}

func formatJSON(certs []*x509.Certificate, certManager *x509certs.Certificate) string {
	type CertInfo struct {
		Subject            string `json:"subject"`
		Issuer             string `json:"issuer"`
		Serial             string `json:"serial"`
		SignatureAlgorithm string `json:"signatureAlgorithm"`
		PEM                string `json:"pem"`
	}

	certInfos := make([]CertInfo, len(certs))
	for i, cert := range certs {
		pemData := certManager.EncodePEM(cert)
		certInfos[i] = CertInfo{
			Subject:            cert.Subject.CommonName,
			Issuer:             cert.Issuer.CommonName,
			Serial:             cert.SerialNumber.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PEM:                string(pemData),
		}
	}

	output := map[string]any{
		"title":            "X.509 Certificate Chain",
		"totalChained":     len(certs),
		"listCertificates": certInfos,
	}

	jsonData, _ := json.MarshalIndent(output, "", "  ")
	return string(jsonData)
}

// createResources creates and returns all MCP resources without adding them to a server
// This allows for easier testing of resource creation logic
func createResources() []server.ServerResource {
	return []server.ServerResource{
		{
			Resource: mcp.NewResource(
				"config://template",
				"Server Configuration Template",
				mcp.WithResourceDescription("Example configuration file for the MCP server"),
				mcp.WithMIMEType("application/json"),
			),
			Handler: handleConfigResource,
		},
		{
			Resource: mcp.NewResource(
				"info://version",
				"Server Version Information",
				mcp.WithResourceDescription("Version and build information for the MCP server"),
				mcp.WithMIMEType("application/json"),
			),
			Handler: handleVersionResource,
		},
		{
			Resource: mcp.NewResource(
				"docs://certificate-formats",
				"Certificate Format Documentation",
				mcp.WithResourceDescription("Documentation on supported certificate formats and usage"),
				mcp.WithMIMEType("text/markdown"),
			),
			Handler: handleFormatsResource,
		},
		{
			Resource: mcp.NewResource(
				"status://server-status",
				"Server Status Information",
				mcp.WithResourceDescription("Current status and health information for the MCP server"),
				mcp.WithMIMEType("application/json"),
			),
			Handler: handleStatusResource,
		},
	}
}

// handleConfigResource handles requests for the configuration template resource
func handleConfigResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	exampleConfig := map[string]any{
		"defaults": map[string]any{
			"format":            "pem",
			"includeSystemRoot": false,
			"intermediateOnly":  false,
			"warnDays":          30,
			"timeoutSeconds":    10,
		},
	}

	jsonData, err := json.MarshalIndent(exampleConfig, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config template: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "config://template",
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// handleVersionResource handles requests for version information resource
func handleVersionResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	versionInfo := map[string]any{
		"name":    "X509 Certificate Chain Resolver",
		"version": version.Version,
		"type":    "MCP Server",
		"capabilities": map[string]any{
			"tools":     []string{"resolve_cert_chain", "validate_cert_chain", "check_cert_expiry", "batch_resolve_cert_chain", "fetch_remote_cert", "analyze_certificate_with_ai"},
			"resources": []string{"config://template", "info://version", "docs://certificate-formats", "status://server-status"},
			"prompts":   []string{"certificate-analysis", "expiry-monitoring", "security-audit", "troubleshooting"},
		},
		"supportedFormats": []string{"pem", "der", "json"},
	}

	jsonData, err := json.MarshalIndent(versionInfo, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal version info: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "info://version",
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// handleFormatsResource handles requests for certificate formats documentation resource
func handleFormatsResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	content, err := MagicEmbed.ReadFile("templates/certificate-formats.md")
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate formats template: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "docs://certificate-formats",
			MIMEType: "text/markdown",
			Text:     string(content),
		},
	}, nil
}

// handleStatusResource handles requests for server status information resource
func handleStatusResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	statusInfo := map[string]any{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"server":    "X509 Certificate Chain Resolver MCP Server",
		"version":   version.Version,
		"capabilities": map[string]any{
			"tools":     []string{"resolve_cert_chain", "validate_cert_chain", "check_cert_expiry", "batch_resolve_cert_chain", "fetch_remote_cert", "analyze_certificate_with_ai"},
			"resources": []string{"config://template", "info://version", "docs://certificate-formats", "status://server-status"},
			"prompts":   []string{"certificate-analysis", "expiry-monitoring", "security-audit", "troubleshooting"},
		},
		"supportedFormats": []string{"pem", "der", "json"},
	}

	jsonData, err := json.MarshalIndent(statusInfo, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal status info: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "status://server-status",
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// handleAnalyzeCertificateWithAI analyzes certificate data using AI collaboration through sampling
func handleAnalyzeCertificateWithAI(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	certInput, err := request.RequireString("certificate")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("certificate parameter required: %v", err)), nil
	}

	analysisType := request.GetString("analysis_type", "general")

	// Read certificate data
	var certData []byte
	if fileData, err := os.ReadFile(certInput); err == nil {
		certData = fileData
	} else {
		// Try to decode as base64
		if decoded, err := base64.StdEncoding.DecodeString(certInput); err == nil {
			certData = decoded
		} else {
			return mcp.NewToolResultError("failed to read certificate: not a valid file path or base64 data"), nil
		}
	}

	// Create certificate manager
	certManager := x509certs.New()

	// Decode certificate
	certs, err := certManager.DecodeMultiple(certData)
	if err != nil {
		// Try single cert
		cert, err := certManager.Decode(certData)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to decode certificate: %v", err)), nil
		}
		certs = []*x509.Certificate{cert}
	}

	// Create certificate chain and fetch complete chain for analysis
	chain := x509chain.New(certs[0], version.Version)
	if len(certs) > 1 {
		chain.Certs = certs
	}

	// Configure timeout from MCP server config
	chain.HTTPConfig.Timeout = time.Duration(config.Defaults.Timeout) * time.Second

	// Fetch additional certificates from AIA URLs if available
	fetchCtx, cancel := context.WithTimeout(ctx, time.Duration(config.Defaults.Timeout)*time.Second)
	defer cancel()
	if err := chain.FetchCertificate(fetchCtx); err != nil {
		// Log error but continue with available certificates
		// This is not a fatal error for AI analysis
	}

	// Perform revocation status checks
	revocationCtx, revocationCancel := context.WithTimeout(ctx, time.Duration(config.Defaults.Timeout)*time.Second)
	defer revocationCancel()
	revocationStatus, err := chain.CheckRevocationStatus(revocationCtx)
	if err != nil {
		// Revocation checking failure is not fatal
		revocationStatus = fmt.Sprintf("Revocation check failed: %v", err)
	}

	// Build comprehensive certificate context for AI analysis including revocation status
	certificateContext := buildCertificateContextWithRevocation(chain.Certs, revocationStatus, analysisType)

	// Use context engineering as the primary prompt for AI analysis
	analysisPrompt := certificateContext + "\n\n" + getAnalysisInstruction(analysisType)

	// Try to get AI analysis if API key is configured
	if config.AI.APIKey != "" {
		// Read system prompt from embedded template
		systemPromptBytes, err := MagicEmbed.ReadFile("templates/certificate-analysis-system-prompt.md")
		systemPrompt := ""
		if err == nil {
			systemPrompt = string(systemPromptBytes)
		} else {
			// Fallback system prompt if file cannot be read
			systemPrompt = "You are a certificate security analyzer. Follow these exact instructions for analyzing X.509 certificates."
		}

		// Create sampling handler for this request
		samplingHandler := &DefaultSamplingHandler{
			apiKey:   config.AI.APIKey,
			endpoint: config.AI.Endpoint,
			model:    config.AI.Model,
			timeout:  time.Duration(config.AI.Timeout) * time.Second,
			client:   &http.Client{Timeout: time.Duration(config.AI.Timeout) * time.Second},
		}

		// Prepare sampling request with system prompt
		samplingRequest := mcp.CreateMessageRequest{
			CreateMessageParams: mcp.CreateMessageParams{
				Messages: []mcp.SamplingMessage{
					{
						Role:    mcp.RoleUser,
						Content: mcp.TextContent{Text: analysisPrompt},
					},
				},
				SystemPrompt: systemPrompt,
				MaxTokens:    4096, // Increased for comprehensive analysis
				Temperature:  0.3,  // Lower temperature for more consistent analysis
			},
		}

		// Call the AI API
		samplingResult, err := samplingHandler.CreateMessage(ctx, samplingRequest)
		if err != nil {
			// If sampling fails, fall back to showing the context
			result := fmt.Sprintf("AI Analysis Request Failed: %v\n\n", err)
			result += fmt.Sprintf("Analysis Type: %s\n\n", analysisType)
			result += "Certificate Context Prepared:\n"
			result += certificateContext
			result += fmt.Sprintf("\n\nPrompt that would be sent:\n%s", analysisPrompt)
			return mcp.NewToolResultText(result), nil
		}

		// Return the AI's analysis
		result := fmt.Sprintf("🤖 AI-Powered Certificate Analysis (%s)\n\n", analysisType)
		result += "Analysis provided by AI assistant:\n\n"
		if textContent, ok := samplingResult.SamplingMessage.Content.(mcp.TextContent); ok {
			result += textContent.Text
		} else {
			result += "AI provided analysis (content format not supported for display)"
		}
		result += fmt.Sprintf("\n\n---\n*AI Model: %s*", samplingResult.Model)

		return mcp.NewToolResultText(result), nil
	}

	// Fallback: Show what would be sent to AI (no API key configured)
	result := fmt.Sprintf("AI Collaborative Analysis (%s)\n\n", analysisType)
	result += "⚠️  No AI API key configured. To enable real AI analysis:\n"
	result += "   1. Set X509_AI_APIKEY environment variable, or\n"
	result += "   2. Configure 'ai.apiKey' in your config.json file\n\n"
	result += "📋 Certificate Context Prepared for AI Analysis:\n"
	result += certificateContext
	result += fmt.Sprintf("\n\n💭 Analysis Prompt Ready:\n%s", analysisPrompt)
	result += "\n\n🔄 With API key configured, this would send the context to AI for intelligent analysis."

	return mcp.NewToolResultText(result), nil
}

// buildCertificateContext creates comprehensive context information about certificates for AI analysis
//
// Deprecated: This function is deprecated and replaced by buildCertificateContextWithRevocation.
// The replacement includes revocation status checks for comprehensive certificate analysis.
func buildCertificateContext(certs []*x509.Certificate, analysisType string) string {
	var context strings.Builder

	// Chain overview
	context.WriteString(fmt.Sprintf("Chain Length: %d certificates\n", len(certs)))
	context.WriteString(fmt.Sprintf("Analysis Type: %s\n", analysisType))
	context.WriteString(fmt.Sprintf("Current Time: %s UTC\n\n", time.Now().UTC().Format("2006-01-02 15:04:05")))

	// Detailed certificate information
	for i, cert := range certs {
		context.WriteString(fmt.Sprintf("=== CERTIFICATE %d ===\n", i+1))
		context.WriteString(fmt.Sprintf("Role: %s\n", getCertificateRole(i, len(certs))))

		// Subject information
		context.WriteString("SUBJECT:\n")
		context.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Subject.CommonName))
		context.WriteString(fmt.Sprintf("  Organization: %s\n", strings.Join(cert.Subject.Organization, ", ")))
		context.WriteString(fmt.Sprintf("  Organizational Unit: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", ")))
		context.WriteString(fmt.Sprintf("  Country: %s\n", strings.Join(cert.Subject.Country, ", ")))
		context.WriteString(fmt.Sprintf("  State/Province: %s\n", strings.Join(cert.Subject.Province, ", ")))
		context.WriteString(fmt.Sprintf("  Locality: %s\n", strings.Join(cert.Subject.Locality, ", ")))

		// Issuer information
		context.WriteString("ISSUER:\n")
		context.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Issuer.CommonName))
		context.WriteString(fmt.Sprintf("  Organization: %s\n", strings.Join(cert.Issuer.Organization, ", ")))

		// Validity period
		context.WriteString("VALIDITY:\n")
		context.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST")))
		context.WriteString(fmt.Sprintf("  Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST")))

		now := time.Now()
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		context.WriteString(fmt.Sprintf("  Days until expiry: %d\n", daysUntilExpiry))
		if daysUntilExpiry < 0 {
			context.WriteString("  Status: EXPIRED\n")
		} else if daysUntilExpiry < 30 {
			context.WriteString("  Status: EXPIRING SOON\n")
		} else {
			context.WriteString("  Status: VALID\n")
		}

		// Cryptographic information
		context.WriteString("CRYPTOGRAPHY:\n")
		context.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String()))
		context.WriteString(fmt.Sprintf("  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String()))
		context.WriteString(fmt.Sprintf("  Key Size: %d bits\n", getKeySize(cert)))

		// Certificate properties
		context.WriteString("PROPERTIES:\n")
		context.WriteString(fmt.Sprintf("  Version: %d\n", cert.Version))
		context.WriteString(fmt.Sprintf("  Serial Number: %s\n", cert.SerialNumber.String()))
		context.WriteString(fmt.Sprintf("  Is CA: %t\n", cert.IsCA))

		// Key usage and extended key usage
		if cert.KeyUsage != 0 {
			context.WriteString(fmt.Sprintf("  Key Usage: %s\n", formatKeyUsage(cert.KeyUsage)))
		}
		if len(cert.ExtKeyUsage) > 0 {
			context.WriteString(fmt.Sprintf("  Extended Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage)))
		}

		// Subject Alternative Names
		if len(cert.DNSNames) > 0 {
			context.WriteString(fmt.Sprintf("  DNS Names: %s\n", strings.Join(cert.DNSNames, ", ")))
		}
		if len(cert.EmailAddresses) > 0 {
			context.WriteString(fmt.Sprintf("  Email Addresses: %s\n", strings.Join(cert.EmailAddresses, ", ")))
		}
		if len(cert.IPAddresses) > 0 {
			ips := make([]string, len(cert.IPAddresses))
			for j, ip := range cert.IPAddresses {
				ips[j] = ip.String()
			}
			context.WriteString(fmt.Sprintf("  IP Addresses: %s\n", strings.Join(ips, ", ")))
		}

		// Certificate Authority Information
		if cert.IssuingCertificateURL != nil {
			context.WriteString(fmt.Sprintf("  Issuer URLs: %s\n", strings.Join(cert.IssuingCertificateURL, ", ")))
		}
		if cert.CRLDistributionPoints != nil {
			context.WriteString(fmt.Sprintf("  CRL Distribution Points: %s\n", strings.Join(cert.CRLDistributionPoints, ", ")))
		}
		if cert.OCSPServer != nil {
			context.WriteString(fmt.Sprintf("  OCSP Servers: %s\n", strings.Join(cert.OCSPServer, ", ")))
		}

		context.WriteString("\n")
	}

	// Chain validation context
	context.WriteString("=== CHAIN VALIDATION CONTEXT ===\n")
	if len(certs) > 1 {
		for i := 0; i < len(certs)-1; i++ {
			subject := certs[i].Subject.CommonName
			issuer := certs[i].Issuer.CommonName
			nextSubject := certs[i+1].Subject.CommonName

			if issuer == nextSubject {
				context.WriteString(fmt.Sprintf("✓ Certificate %d (%s) is properly signed by Certificate %d (%s)\n",
					i+1, subject, i+2, nextSubject))
			} else {
				context.WriteString(fmt.Sprintf("⚠ Certificate %d (%s) issuer (%s) doesn't match Certificate %d subject (%s)\n",
					i+1, subject, issuer, i+2, nextSubject))
			}
		}
	}

	// Security context
	context.WriteString("\n=== SECURITY CONTEXT ===\n")
	context.WriteString("Current TLS/SSL Best Practices:\n")
	context.WriteString("- ~RSA keys should be 2048 bits or larger~ (Quantum Vulnerable 💀)\n")
	context.WriteString("- ~ECDSA keys should use P-256 or stronger curves~ (Quantum Vulnerable 💀)\n")
	context.WriteString("- Certificates should not be valid for more than 398 days (CA/Browser Forum)\n")
	context.WriteString("- Modern clients require SAN (Subject Alternative Name) extension\n")
	context.WriteString("- Quantum-resistant algorithms: Consider ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+) for post-quantum cryptography\n")
	context.WriteString("- Hybrid certificates combining classical and quantum-resistant algorithms provide transitional security\n")
	context.WriteString("- Deprecated: MD5, SHA-1 signatures\n")
	context.WriteString("- Deprecated: SSLv3, TLS 1.0, TLS 1.1\n")

	return context.String()
}

// buildCertificateContextWithRevocation creates comprehensive context information about certificates for AI analysis including revocation status
func buildCertificateContextWithRevocation(certs []*x509.Certificate, revocationStatus string, analysisType string) string {
	var context strings.Builder

	// Chain overview
	context.WriteString(fmt.Sprintf("Chain Length: %d certificates\n", len(certs)))
	context.WriteString(fmt.Sprintf("Analysis Type: %s\n", analysisType))
	context.WriteString(fmt.Sprintf("Current Time: %s UTC\n\n", time.Now().UTC().Format("2006-01-02 15:04:05")))

	// Include revocation status summary with methodology explanation
	context.WriteString("REVOCATION STATUS SUMMARY:\n")
	context.WriteString("Methodology: OCSP takes priority over CRL. If OCSP is unavailable, CRL is checked.\n")
	context.WriteString("Redundancy: Multiple OCSP servers and CRL distribution points are tried for reliability.\n")
	context.WriteString("Security: Only properly signed CRLs are accepted; unverified CRLs are rejected.\n\n")
	context.WriteString(revocationStatus)
	context.WriteString("\n")

	// Detailed certificate information
	for i, cert := range certs {
		context.WriteString(fmt.Sprintf("=== CERTIFICATE %d ===\n", i+1))
		context.WriteString(fmt.Sprintf("Role: %s\n", getCertificateRole(i, len(certs))))

		// Subject information
		context.WriteString("SUBJECT:\n")
		context.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Subject.CommonName))
		context.WriteString(fmt.Sprintf("  Organization: %s\n", strings.Join(cert.Subject.Organization, ", ")))
		context.WriteString(fmt.Sprintf("  Organizational Unit: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", ")))
		context.WriteString(fmt.Sprintf("  Country: %s\n", strings.Join(cert.Subject.Country, ", ")))
		context.WriteString(fmt.Sprintf("  State/Province: %s\n", strings.Join(cert.Subject.Province, ", ")))
		context.WriteString(fmt.Sprintf("  Locality: %s\n", strings.Join(cert.Subject.Locality, ", ")))

		// Issuer information
		context.WriteString("ISSUER:\n")
		context.WriteString(fmt.Sprintf("  Common Name: %s\n", cert.Issuer.CommonName))
		context.WriteString(fmt.Sprintf("  Organization: %s\n", strings.Join(cert.Issuer.Organization, ", ")))

		// Validity period
		context.WriteString("VALIDITY:\n")
		context.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST")))
		context.WriteString(fmt.Sprintf("  Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST")))

		now := time.Now()
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		context.WriteString(fmt.Sprintf("  Days until expiry: %d\n", daysUntilExpiry))
		if daysUntilExpiry < 0 {
			context.WriteString("  Status: EXPIRED\n")
		} else if daysUntilExpiry < 30 {
			context.WriteString("  Status: EXPIRING SOON\n")
		} else {
			context.WriteString("  Status: VALID\n")
		}

		// Cryptographic information
		context.WriteString("CRYPTOGRAPHY:\n")
		context.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String()))
		context.WriteString(fmt.Sprintf("  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String()))
		context.WriteString(fmt.Sprintf("  Key Size: %d bits\n", getKeySize(cert)))

		// Certificate properties
		context.WriteString("PROPERTIES:\n")
		context.WriteString(fmt.Sprintf("  Version: %d\n", cert.Version))
		context.WriteString(fmt.Sprintf("  Serial Number: %s\n", cert.SerialNumber.String()))
		context.WriteString(fmt.Sprintf("  Is CA: %t\n", cert.IsCA))

		// Key usage and extended key usage
		if cert.KeyUsage != 0 {
			context.WriteString(fmt.Sprintf("  Key Usage: %s\n", formatKeyUsage(cert.KeyUsage)))
		}
		if len(cert.ExtKeyUsage) > 0 {
			context.WriteString(fmt.Sprintf("  Extended Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage)))
		}

		// Subject Alternative Names
		if len(cert.DNSNames) > 0 {
			context.WriteString(fmt.Sprintf("  DNS Names: %s\n", strings.Join(cert.DNSNames, ", ")))
		}
		if len(cert.EmailAddresses) > 0 {
			context.WriteString(fmt.Sprintf("  Email Addresses: %s\n", strings.Join(cert.EmailAddresses, ", ")))
		}
		if len(cert.IPAddresses) > 0 {
			ips := make([]string, len(cert.IPAddresses))
			for j, ip := range cert.IPAddresses {
				ips[j] = ip.String()
			}
			context.WriteString(fmt.Sprintf("  IP Addresses: %s\n", strings.Join(ips, ", ")))
		}

		// Certificate Authority Information
		if cert.IssuingCertificateURL != nil {
			context.WriteString(fmt.Sprintf("  Issuer URLs: %s\n", strings.Join(cert.IssuingCertificateURL, ", ")))
		}
		if cert.CRLDistributionPoints != nil {
			context.WriteString(fmt.Sprintf("  CRL Distribution Points: %s\n", strings.Join(cert.CRLDistributionPoints, ", ")))
		}
		if cert.OCSPServer != nil {
			context.WriteString(fmt.Sprintf("  OCSP Servers: %s\n", strings.Join(cert.OCSPServer, ", ")))
		}

		// Serial Number for revocation tracking (duplicate but explicit for AI context)
		context.WriteString(fmt.Sprintf("  Serial Number: %s\n", cert.SerialNumber.String()))

		context.WriteString("\n")
	}

	// Chain validation context
	context.WriteString("=== CHAIN VALIDATION CONTEXT ===\n")
	if len(certs) > 1 {
		for i := 0; i < len(certs)-1; i++ {
			subject := certs[i].Subject.CommonName
			issuer := certs[i].Issuer.CommonName
			nextSubject := certs[i+1].Subject.CommonName

			if issuer == nextSubject {
				context.WriteString(fmt.Sprintf("✓ Certificate %d (%s) is properly signed by Certificate %d (%s)\n",
					i+1, subject, i+2, nextSubject))
			} else {
				context.WriteString(fmt.Sprintf("⚠ Certificate %d (%s) issuer (%s) doesn't match Certificate %d subject (%s)\n",
					i+1, subject, issuer, i+2, nextSubject))
			}
		}
	}

	// Security context
	context.WriteString("\n=== SECURITY CONTEXT ===\n")
	context.WriteString("Current TLS/SSL Best Practices:\n")
	context.WriteString("- ~RSA keys should be 2048 bits or larger~ (Quantum Vulnerable 💀)\n")
	context.WriteString("- ~ECDSA keys should use P-256 or stronger curves~ (Quantum Vulnerable 💀)\n")
	context.WriteString("- Certificates should not be valid for more than 398 days (CA/Browser Forum)\n")
	context.WriteString("- Modern clients require SAN (Subject Alternative Name) extension\n")
	context.WriteString("- Quantum-resistant algorithms: Consider ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+) for post-quantum cryptography\n")
	context.WriteString("- Hybrid certificates combining classical and quantum-resistant algorithms provide transitional security\n")
	context.WriteString("- Deprecated: MD5, SHA-1 signatures\n")
	context.WriteString("- Deprecated: SSLv3, TLS 1.0, TLS 1.1\n")

	return context.String()
}

// getCertificateRole determines the role of a certificate in the chain
func getCertificateRole(index int, total int) string {
	if total == 1 {
		return "Self-Signed Certificate"
	}
	if index == 0 {
		return "End-Entity (Server/Leaf) Certificate"
	}
	if index == total-1 {
		return "Root CA Certificate"
	}
	return "Intermediate CA Certificate"
}

// getKeySize extracts the key size from a certificate
func getKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.Size() * 8 // Convert bytes to bits
	case rsa.PublicKey:
		return pub.Size() * 8 // Convert bytes to bits
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}

// formatKeyUsage converts KeyUsage flags to readable string
func formatKeyUsage(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Signing")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Signing")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return strings.Join(usages, ", ")
}

// formatExtKeyUsage converts ExtKeyUsage to readable string
func formatExtKeyUsage(usage []x509.ExtKeyUsage) string {
	var usages []string
	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usages = append(usages, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usages = append(usages, "Microsoft Kernel Code Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown (%d)", u))
		}
	}
	return strings.Join(usages, ", ")
}

// getAnalysisInstruction returns specific analysis instructions based on the type
func getAnalysisInstruction(analysisType string) string {
	switch analysisType {
	case "security":
		return `
SECURITY ANALYSIS REQUEST:
Based on the certificate data above, provide a comprehensive security assessment focusing on:
1. Cryptographic strength and algorithm security
2. Certificate validity and trust chain integrity
3. Potential security vulnerabilities or misconfigurations
4. Compliance with current security best practices
5. Recommendations for security improvements
6. Risk assessment (Critical/High/Medium/Low) with specific findings

Be specific about any security concerns found in the certificate properties, validity periods, or cryptographic settings.`

	case "compliance":
		return `
COMPLIANCE ANALYSIS REQUEST:
Based on the certificate data above, assess compliance with industry standards:
1. CA/Browser Forum Baseline Requirements compliance
2. NIST cryptographic standards adherence
3. Industry-specific regulatory requirements
4. Certificate lifecycle management compliance
5. Audit and reporting requirements
6. Remediation steps for any compliance gaps

Identify any violations of current standards and provide specific compliance recommendations.`

	default: // general
		return `
GENERAL CERTIFICATE ANALYSIS REQUEST:
Based on the certificate data above, provide a comprehensive analysis covering:
1. Certificate chain structure and validation status
2. Cryptographic properties and security posture
3. Validity periods and renewal considerations
4. Identity verification and certificate usage
5. Operational health and maintenance recommendations
6. Any notable characteristics or potential concerns

Provide actionable insights for certificate management and security.`
	}
}
