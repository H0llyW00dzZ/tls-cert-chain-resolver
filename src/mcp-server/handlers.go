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
	"text/template"
	"time"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// MagicEmbed provides access to embedded template files for certificate analysis and documentation.
//
//go:embed templates
var MagicEmbed embed.FS

// handleResolveCertChain resolves a certificate chain from a file path or base64-encoded certificate data.
// It fetches the complete certificate chain, optionally adds system root CA, and formats the output.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing certificate input and format options
//
// Returns:
//   - The tool execution result containing the resolved certificate chain
//   - An error if certificate resolution or processing fails
//
// The function supports multiple input formats (file path or base64) and output formats (PEM, DER, JSON).
// It uses the x509chain package to fetch additional certificates from AIA URLs.
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

// handleValidateCertChain validates a certificate chain for correctness and trust.
// It resolves the complete chain, verifies signatures, checks revocation status, and reports validation results.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing certificate input and validation options
//
// Returns:
//   - The tool execution result containing validation status and certificate details
//   - An error if certificate processing or validation fails
//
// The function performs comprehensive validation including chain integrity, trust verification,
// and revocation status checking using OCSP/CRL. It provides detailed feedback on certificate roles
// and validation outcomes.
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

// handleBatchResolveCertChain processes multiple certificate chains in batch from comma-separated inputs.
// It resolves each certificate chain independently and formats the results for comparison.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing comma-separated certificate inputs and format options
//
// Returns:
//   - The tool execution result containing batch processing results for all certificates
//   - An error if any certificate processing fails critically
//
// The function handles multiple certificates efficiently, processing each one independently
// and collecting results. Individual certificate failures are reported per-certificate rather
// than failing the entire batch.
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

// handleFetchRemoteCert fetches a certificate chain from a remote hostname and port.
// It establishes a TLS connection to retrieve server certificates and formats the results.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing hostname, port, and format options
//   - config: Server configuration containing timeout and format defaults
//
// Returns:
//   - The tool execution result containing the fetched certificate chain
//   - An error if connection or certificate retrieval fails
//
// The function uses the x509chain.FetchRemoteChain function to establish a TLS connection
// and retrieve certificates presented by the remote server. It supports optional system root
// CA addition and certificate filtering.
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

// handleCheckCertExpiry checks certificate expiry dates and warns about upcoming expirations.
// It analyzes certificate validity periods and provides renewal recommendations based on configurable warning thresholds.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing certificate input and warning threshold
//   - config: Server configuration containing default warning days and other settings
//
// Returns:
//   - The tool execution result containing expiry analysis and renewal recommendations
//   - An error if certificate processing fails
//
// The function supports both single certificates and certificate bundles, calculating days until expiry
// and categorizing certificates as expired, expiring soon, or valid. It provides a summary of the
// certificate expiry status across all processed certificates.
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

// formatJSON formats a slice of certificates into a structured JSON representation.
// It creates a comprehensive JSON object containing certificate metadata and PEM-encoded data.
//
// Parameters:
//   - certs: Slice of X.509 certificates to format
//   - certManager: Certificate manager instance for PEM encoding operations
//
// Returns:
//   - A JSON string containing structured certificate information with title, total count, and certificate list
//
// The JSON output includes subject, issuer, serial number, signature algorithm, and PEM-encoded certificate data
// for each certificate in the chain. This format is suitable for programmatic processing and analysis.
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

// createResources creates and returns all MCP resources without adding them to a server.
// This allows for easier testing of resource creation logic and resource definition validation.
//
// Returns:
//   - A slice of server.ServerResource containing all static and dynamic resources
//
// The function defines resources for configuration templates, version information,
// certificate format documentation, and server status. These resources provide
// static content and metadata to MCP clients. Each resource includes URI, name,
// description, MIME type, and handler function.
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
			Handler: handleCertificateFormatsResource,
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

// handleConfigResource handles requests for the configuration template resource.
// It provides a JSON template showing the expected configuration structure for the MCP server.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for the config template
//
// Returns:
//   - A slice containing the configuration template as JSON content
//   - An error if JSON marshaling fails
//
// The resource provides default values for format, includeSystemRoot, intermediateOnly, warnDays, and timeoutSeconds.
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

// handleVersionResource handles requests for version information resource.
// It provides server metadata including version, capabilities, and supported features.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for version information
//
// Returns:
//   - A slice containing version and capability information as JSON content
//   - An error if JSON marshaling fails
//
// The resource includes server name, version, supported tools, resources, prompts, and certificate formats.
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

// handleCertificateFormatsResource handles requests for certificate formats documentation resource.
// It serves embedded documentation about supported certificate formats (PEM, DER, etc.).
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for certificate format documentation
//
// Returns:
//   - A slice containing the certificate formats documentation as markdown content
//   - An error if the embedded file cannot be read
//
// The documentation is stored in templates/certificate-formats.md and provides
// detailed information about certificate encoding formats and usage.
func handleCertificateFormatsResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
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

// handleStatusResource handles requests for server status information resource.
// It provides current server health, version, and operational status.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for server status
//
// Returns:
//   - A slice containing server status information as JSON content
//   - An error if JSON marshaling fails
//
// The status includes server health, timestamp, version, and available capabilities
// (tools, resources, prompts, supported formats).
func handleStatusResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	statusInfo := map[string]any{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"server":    "X509 Certificate Chain Resolver MCP Server",
		"version":   version.Version,
		"capabilities": map[string]any{
			"tools":     []string{"resolve_cert_chain", "validate_cert_chain", "check_cert_expiry", "batch_resolve_cert_chain", "fetch_remote_cert", "analyze_certificate_with_ai", "get_resource_usage"},
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

// handleAnalyzeCertificateWithAI analyzes certificate data using AI collaboration through sampling.
// It performs comprehensive security analysis including revocation status, cryptographic strength,
// and compliance assessment using bidirectional AI communication.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing certificate input and analysis type
//   - config: Server configuration containing AI API settings and defaults
//
// Returns:
//   - The tool execution result containing AI-powered certificate analysis
//   - An error if certificate processing or AI analysis fails
//
// The function supports general, security, and compliance analysis types. If no AI API key
// is configured, it returns a helpful message with the prepared analysis context.
// When AI is available, it uses embedded system prompts and streaming responses for
// comprehensive certificate security assessment.
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
			// If sampling fails, return only the error
			result := fmt.Sprintf("AI Analysis Request Failed: %v", err)
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

// buildCertificateContext creates comprehensive context information about certificates for AI analysis.
//
// Deprecated: This function is deprecated and replaced by buildCertificateContextWithRevocation.
// The replacement includes revocation status checks for comprehensive certificate analysis.
//
// Parameters:
//   - certs: Slice of X.509 certificates to analyze
//   - analysisType: Type of analysis (general, security, compliance)
//
// Returns:
//   - A formatted string containing certificate context for AI analysis
//
// This function provides basic certificate information without revocation status.
// Use buildCertificateContextWithRevocation for complete analysis including OCSP/CRL status.
func buildCertificateContext(certs []*x509.Certificate, analysisType string) string {
	var context strings.Builder

	// Chain overview
	fmt.Fprintf(&context, "Chain Length: %d certificates\n", len(certs))
	fmt.Fprintf(&context, "Analysis Type: %s\n", analysisType)
	fmt.Fprintf(&context, "Current Time: %s UTC\n\n", time.Now().UTC().Format("2006-01-02 15:04:05"))

	// Detailed certificate information
	for i, cert := range certs {
		fmt.Fprintf(&context, "=== CERTIFICATE %d ===\n", i+1)
		fmt.Fprintf(&context, "Role: %s\n", getCertificateRole(i, len(certs)))

		// Subject information
		context.WriteString("SUBJECT:\n")
		fmt.Fprintf(&context, "  Common Name: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(&context, "  Organization: %s\n", strings.Join(cert.Subject.Organization, ", "))
		fmt.Fprintf(&context, "  Organizational Unit: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", "))
		fmt.Fprintf(&context, "  Country: %s\n", strings.Join(cert.Subject.Country, ", "))
		fmt.Fprintf(&context, "  State/Province: %s\n", strings.Join(cert.Subject.Province, ", "))
		fmt.Fprintf(&context, "  Locality: %s\n", strings.Join(cert.Subject.Locality, ", "))

		// Issuer information
		context.WriteString("ISSUER:\n")
		fmt.Fprintf(&context, "  Common Name: %s\n", cert.Issuer.CommonName)
		fmt.Fprintf(&context, "  Organization: %s\n", strings.Join(cert.Issuer.Organization, ", "))

		// Validity period
		context.WriteString("VALIDITY:\n")
		fmt.Fprintf(&context, "  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&context, "  Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

		now := time.Now()
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		fmt.Fprintf(&context, "  Days until expiry: %d\n", daysUntilExpiry)
		if daysUntilExpiry < 0 {
			context.WriteString("  Status: EXPIRED\n")
		} else if daysUntilExpiry < 30 {
			context.WriteString("  Status: EXPIRING SOON\n")
		} else {
			context.WriteString("  Status: VALID\n")
		}

		// Cryptographic information
		context.WriteString("CRYPTOGRAPHY:\n")
		fmt.Fprintf(&context, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())
		fmt.Fprintf(&context, "  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())
		fmt.Fprintf(&context, "  Key Size: %d bits\n", getKeySize(cert))

		// Certificate properties
		context.WriteString("PROPERTIES:\n")
		fmt.Fprintf(&context, "  Version: %d\n", cert.Version)
		fmt.Fprintf(&context, "  Serial Number: %s\n", cert.SerialNumber.String())
		fmt.Fprintf(&context, "  Is CA: %t\n", cert.IsCA)

		// Key usage and extended key usage
		if cert.KeyUsage != 0 {
			fmt.Fprintf(&context, "  Key Usage: %s\n", formatKeyUsage(cert.KeyUsage))
		}
		if len(cert.ExtKeyUsage) > 0 {
			fmt.Fprintf(&context, "  Extended Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
		}

		// Subject Alternative Names
		if len(cert.DNSNames) > 0 {
			fmt.Fprintf(&context, "  DNS Names: %s\n", strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.EmailAddresses) > 0 {
			fmt.Fprintf(&context, "  Email Addresses: %s\n", strings.Join(cert.EmailAddresses, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			ips := make([]string, len(cert.IPAddresses))
			for j, ip := range cert.IPAddresses {
				ips[j] = ip.String()
			}
			fmt.Fprintf(&context, "  IP Addresses: %s\n", strings.Join(ips, ", "))
		}

		// Certificate Authority Information
		if cert.IssuingCertificateURL != nil {
			fmt.Fprintf(&context, "  Issuer URLs: %s\n", strings.Join(cert.IssuingCertificateURL, ", "))
		}
		if cert.CRLDistributionPoints != nil {
			fmt.Fprintf(&context, "  CRL Distribution Points: %s\n", strings.Join(cert.CRLDistributionPoints, ", "))
		}
		if cert.OCSPServer != nil {
			fmt.Fprintf(&context, "  OCSP Servers: %s\n", strings.Join(cert.OCSPServer, ", "))
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
				fmt.Fprintf(&context, "✓ Certificate %d (%s) is properly signed by Certificate %d (%s)\n",
					i+1, subject, i+2, nextSubject)
			} else {
				fmt.Fprintf(&context, "⚠ Certificate %d (%s) issuer (%s) doesn't match Certificate %d subject (%s)\n",
					i+1, subject, issuer, i+2, nextSubject)
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

// buildCertificateContextWithRevocation creates comprehensive context information about certificates for AI analysis including revocation status.
// It builds detailed certificate context with OCSP/CRL revocation information for enhanced security analysis.
//
// Parameters:
//   - certs: Slice of X.509 certificates to analyze
//   - revocationStatus: String containing revocation check results (OCSP/CRL status)
//   - analysisType: Type of analysis (general, security, compliance)
//
// Returns:
//   - A formatted string containing comprehensive certificate context including revocation status
//
// This function provides complete certificate analysis context including cryptographic details,
// validity periods, extensions, and revocation status for AI-powered security assessment.
// It uses helper functions to organize information into logical sections.
func buildCertificateContextWithRevocation(certs []*x509.Certificate, revocationStatus string, analysisType string) string {
	var context strings.Builder

	// Chain overview
	fmt.Fprintf(&context, "Chain Length: %d certificates\n", len(certs))
	fmt.Fprintf(&context, "Analysis Type: %s\n", analysisType)
	fmt.Fprintf(&context, "Current Time: %s UTC\n\n", time.Now().UTC().Format("2006-01-02 15:04:05"))

	// Include revocation status summary with methodology explanation
	context.WriteString("REVOCATION STATUS SUMMARY:\n")
	context.WriteString("Methodology: OCSP takes priority over CRL. If OCSP is unavailable, CRL is checked.\n")
	context.WriteString("Redundancy: Multiple OCSP servers and CRL distribution points are tried for reliability.\n")
	context.WriteString("Security: Only properly signed CRLs are accepted; unverified CRLs are rejected.\n\n")
	context.WriteString(revocationStatus)
	context.WriteString("\n")

	// Detailed certificate information
	for i, cert := range certs {
		fmt.Fprintf(&context, "=== CERTIFICATE %d ===\n", i+1)
		fmt.Fprintf(&context, "Role: %s\n", getCertificateRole(i, len(certs)))

		appendSubjectInfo(&context, cert)
		appendIssuerInfo(&context, cert)
		appendValidityInfo(&context, cert)
		appendCryptoInfo(&context, cert)
		appendCertProperties(&context, cert)
		appendCertExtensions(&context, cert)
		appendCAInfo(&context, cert)

		context.WriteString("\n")
	}

	appendChainValidationContext(&context, certs)
	appendSecurityContext(&context)

	return context.String()
}

// appendSubjectInfo adds subject information to the context builder for AI analysis.
// It formats and appends certificate subject details including common name, organization, and location.
//
// Parameters:
//   - context: String builder to append subject information to
//   - cert: X.509 certificate to extract subject information from
//
// The function appends subject fields in a structured format suitable for AI analysis,
// including common name, organization hierarchy, and geographic information.
func appendSubjectInfo(context *strings.Builder, cert *x509.Certificate) {
	context.WriteString("SUBJECT:\n")
	fmt.Fprintf(context, "  Common Name: %s\n", cert.Subject.CommonName)
	fmt.Fprintf(context, "  Organization: %s\n", strings.Join(cert.Subject.Organization, ", "))
	fmt.Fprintf(context, "  Organizational Unit: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", "))
	fmt.Fprintf(context, "  Country: %s\n", strings.Join(cert.Subject.Country, ", "))
	fmt.Fprintf(context, "  State/Province: %s\n", strings.Join(cert.Subject.Province, ", "))
	fmt.Fprintf(context, "  Locality: %s\n", strings.Join(cert.Subject.Locality, ", "))
}

// appendIssuerInfo adds issuer information to the context builder for AI analysis.
// It formats and appends certificate issuer details including common name and organization.
//
// Parameters:
//   - context: String builder to append issuer information to
//   - cert: X.509 certificate to extract issuer information from
//
// The function appends issuer fields in a structured format suitable for AI analysis,
// focusing on the certificate authority that issued the certificate.
func appendIssuerInfo(context *strings.Builder, cert *x509.Certificate) {
	context.WriteString("ISSUER:\n")
	fmt.Fprintf(context, "  Common Name: %s\n", cert.Issuer.CommonName)
	fmt.Fprintf(context, "  Organization: %s\n", strings.Join(cert.Issuer.Organization, ", "))
}

// appendValidityInfo adds validity period and status to the context builder for AI analysis.
// It formats and appends certificate validity information including dates and expiry status.
//
// Parameters:
//   - context: String builder to append validity information to
//   - cert: X.509 certificate to extract validity information from
//
// The function calculates days until expiry and categorizes the certificate as
// expired, expiring soon, or valid based on the current time and certificate dates.
func appendValidityInfo(context *strings.Builder, cert *x509.Certificate) {
	context.WriteString("VALIDITY:\n")
	fmt.Fprintf(context, "  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(context, "  Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	fmt.Fprintf(context, "  Days until expiry: %d\n", daysUntilExpiry)

	if daysUntilExpiry < 0 {
		context.WriteString("  Status: EXPIRED\n")
	} else if daysUntilExpiry < 30 {
		context.WriteString("  Status: EXPIRING SOON\n")
	} else {
		context.WriteString("  Status: VALID\n")
	}
}

// appendCryptoInfo adds cryptographic information to the context builder for AI analysis.
// It formats and appends certificate cryptographic details including algorithms and key sizes.
//
// Parameters:
//   - context: String builder to append cryptographic information to
//   - cert: X.509 certificate to extract cryptographic information from
//
// The function extracts signature algorithm, public key algorithm, and key size
// information for security analysis and compliance assessment.
func appendCryptoInfo(context *strings.Builder, cert *x509.Certificate) {
	context.WriteString("CRYPTOGRAPHY:\n")
	fmt.Fprintf(context, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())
	fmt.Fprintf(context, "  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())
	fmt.Fprintf(context, "  Key Size: %d bits\n", getKeySize(cert))
}

// appendCertProperties adds basic certificate properties to the context builder for AI analysis.
// It formats and appends fundamental certificate attributes like version, serial number, and CA status.
//
// Parameters:
//   - context: String builder to append certificate properties to
//   - cert: X.509 certificate to extract properties from
//
// The function includes version information, serial number, and whether the certificate
// is a Certificate Authority, providing essential certificate metadata for analysis.
func appendCertProperties(context *strings.Builder, cert *x509.Certificate) {
	context.WriteString("PROPERTIES:\n")
	fmt.Fprintf(context, "  Version: %d\n", cert.Version)
	fmt.Fprintf(context, "  Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Fprintf(context, "  Is CA: %t\n", cert.IsCA)
}

// appendCertExtensions adds certificate extensions to the context builder for AI analysis.
// It formats and appends key usage, extended key usage, and subject alternative names.
//
// Parameters:
//   - context: String builder to append certificate extensions to
//   - cert: X.509 certificate to extract extension information from
//
// The function includes key usage flags, extended key usage purposes, DNS names,
// email addresses, and IP addresses for comprehensive certificate capability analysis.
func appendCertExtensions(context *strings.Builder, cert *x509.Certificate) {
	// Key usage and extended key usage
	if cert.KeyUsage != 0 {
		fmt.Fprintf(context, "  Key Usage: %s\n", formatKeyUsage(cert.KeyUsage))
	}
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Fprintf(context, "  Extended Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	// Subject Alternative Names
	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(context, "  DNS Names: %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Fprintf(context, "  Email Addresses: %s\n", strings.Join(cert.EmailAddresses, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for j, ip := range cert.IPAddresses {
			ips[j] = ip.String()
		}
		fmt.Fprintf(context, "  IP Addresses: %s\n", strings.Join(ips, ", "))
	}
}

// appendCAInfo adds Certificate Authority information to the context builder for AI analysis.
// It formats and appends CA-specific details including issuer URLs, CRL distribution points, and OCSP servers.
//
// Parameters:
//   - context: String builder to append CA information to
//   - cert: X.509 certificate to extract CA-related information from
//
// The function includes authority information access URLs and revocation endpoints
// essential for certificate validation and revocation status checking.
func appendCAInfo(context *strings.Builder, cert *x509.Certificate) {
	// Certificate Authority Information
	if cert.IssuingCertificateURL != nil {
		fmt.Fprintf(context, "  Issuer URLs: %s\n", strings.Join(cert.IssuingCertificateURL, ", "))
	}
	if cert.CRLDistributionPoints != nil {
		fmt.Fprintf(context, "  CRL Distribution Points: %s\n", strings.Join(cert.CRLDistributionPoints, ", "))
	}
	if cert.OCSPServer != nil {
		fmt.Fprintf(context, "  OCSP Servers: %s\n", strings.Join(cert.OCSPServer, ", "))
	}

	// Serial Number for revocation tracking (duplicate but explicit for AI context)
	fmt.Fprintf(context, "  Serial Number: %s\n", cert.SerialNumber.String())
}

// appendChainValidationContext adds chain validation information to the context builder.
// It analyzes certificate chain relationships and identifies validation issues.
//
// Parameters:
//   - context: String builder to append chain validation information to
//   - certs: Slice of X.509 certificates representing the certificate chain
//
// The function checks issuer-subject relationships between certificates in the chain
// and reports any validation issues or proper signing relationships for AI analysis.
func appendChainValidationContext(context *strings.Builder, certs []*x509.Certificate) {
	context.WriteString("=== CHAIN VALIDATION CONTEXT ===\n")
	if len(certs) > 1 {
		for i := 0; i < len(certs)-1; i++ {
			subject := certs[i].Subject.CommonName
			issuer := certs[i].Issuer.CommonName
			nextSubject := certs[i+1].Subject.CommonName

			if issuer == nextSubject {
				fmt.Fprintf(context, "✓ Certificate %d (%s) is properly signed by Certificate %d (%s)\n",
					i+1, subject, i+2, nextSubject)
			} else {
				fmt.Fprintf(context, "⚠ Certificate %d (%s) issuer (%s) doesn't match Certificate %d subject (%s)\n",
					i+1, subject, issuer, i+2, nextSubject)
			}
		}
	}
}

// appendSecurityContext adds current TLS/SSL security best practices and recommendations to the context builder.
// It includes information about cryptographic algorithms, certificate validity periods, and deprecated protocols.
//
// Parameters:
//   - context: String builder to append security context information to
//
// The function provides guidance on quantum-resistant algorithms, certificate lifetime limits,
// required extensions, and deprecated cryptographic primitives for comprehensive security assessment.
func appendSecurityContext(context *strings.Builder) {
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
}

// getCertificateRole determines the role of a certificate in the chain based on its position.
// It categorizes certificates as end-entity, intermediate CA, root CA, or self-signed.
//
// Parameters:
//   - index: Zero-based position of the certificate in the chain (0 = leaf/end-entity)
//   - total: Total number of certificates in the chain
//
// Returns:
//   - A descriptive string indicating the certificate's role in the chain
//
// The function uses positional logic: first certificate is end-entity, last is root CA,
// middle certificates are intermediates, and single certificates are self-signed.
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

// getKeySize extracts the key size in bits from a certificate's public key.
// It handles both RSA and ECDSA keys, returning the appropriate bit length.
//
// Parameters:
//   - cert: X.509 certificate containing the public key to analyze
//
// Returns:
//   - The key size in bits (e.g., 2048 for RSA, 256 for P-256 ECDSA)
//   - 0 if the key type is unsupported or unrecognized
//
// The function supports both pointer and value types for RSA and ECDSA public keys
// to handle different certificate parsing scenarios.
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

// formatKeyUsage converts x509.KeyUsage bit flags to a human-readable comma-separated string.
// It maintains consistent ordering of usage descriptions for predictable output.
//
// Parameters:
//   - usage: Bit field containing one or more x509.KeyUsage flags
//
// Returns:
//   - A comma-separated string of key usage descriptions (e.g., "Digital Signature, Key Encipherment")
//   - Empty string if no usage flags are set
//
// The function uses an ordered slice of key usage flags to ensure consistent output
// regardless of the order in which flags are set in the bit field.
func formatKeyUsage(usage x509.KeyUsage) string {
	// Ordered slice of KeyUsage flags to maintain consistent output order
	keyUsageFlags := []struct {
		flag x509.KeyUsage
		desc string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Signing"},
		{x509.KeyUsageCRLSign, "CRL Signing"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}

	var usages []string
	for _, item := range keyUsageFlags {
		if usage&item.flag != 0 {
			usages = append(usages, item.desc)
		}
	}
	return strings.Join(usages, ", ")
}

// formatExtKeyUsage converts a slice of x509.ExtKeyUsage values to a human-readable comma-separated string.
// It maps each extended key usage value to its descriptive name.
//
// Parameters:
//   - usage: Slice of extended key usage values from the certificate
//
// Returns:
//   - A comma-separated string of extended key usage descriptions
//   - "Unknown (value)" for unrecognized usage values
//
// The function uses a comprehensive map of all standard extended key usage values
// including server/client auth, code signing, email protection, and various Microsoft/Netscape extensions.
func formatExtKeyUsage(usage []x509.ExtKeyUsage) string {
	// Map of ExtKeyUsage values to human-readable strings
	extKeyUsageMap := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "Server Authentication",
		x509.ExtKeyUsageClientAuth:                     "Client Authentication",
		x509.ExtKeyUsageCodeSigning:                    "Code Signing",
		x509.ExtKeyUsageEmailProtection:                "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSEC End System",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSEC Tunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSEC User",
		x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
	}

	var usages []string
	for _, u := range usage {
		if desc, exists := extKeyUsageMap[u]; exists {
			usages = append(usages, desc)
		} else {
			usages = append(usages, fmt.Sprintf("Unknown (%d)", u))
		}
	}
	return strings.Join(usages, ", ")
}

// getAnalysisInstruction returns tailored analysis instructions for AI certificate assessment based on the requested analysis type.
// It provides specific prompts for general, security, and compliance analysis types.
//
// Parameters:
//   - analysisType: The type of analysis requested ("general", "security", or "compliance")
//
// Returns:
//   - A formatted string containing detailed analysis instructions for the AI
//
// The function uses structured prompts that guide the AI to focus on relevant aspects
// of certificate analysis, including cryptographic strength, compliance requirements,
// and security assessments with specific risk levels and recommendations.
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

// handleGetResourceUsage handles requests for current resource usage statistics including memory, GC, and CRL cache metrics.
// It collects comprehensive system and application resource data and formats it according to the requested output format.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing format and detail level parameters
//
// Returns:
//   - The tool execution result containing formatted resource usage data
//   - An error if resource collection or formatting fails
//
// The function supports both JSON and Markdown output formats, with optional detailed metrics
// including CRL cache statistics, memory breakdown, and system information.
func handleGetResourceUsage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	detailed := request.GetBool("detailed", false)
	format := request.GetString("format", "json")

	// Collect resource usage data
	data := CollectResourceUsage(detailed)

	// Format output based on format parameter
	switch format {
	case "markdown":
		markdown := FormatResourceUsageAsMarkdown(data)
		return mcp.NewToolResultText(markdown), nil
	case "json":
		fallthrough
	default:
		jsonData, err := FormatResourceUsageAsJSON(data)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to format resource usage: %v", err)), nil
		}

		// Parse the JSON string back to a map for structured content
		var structuredData map[string]any
		if err := json.Unmarshal([]byte(jsonData), &structuredData); err != nil {
			// Fallback to text if parsing fails
			return mcp.NewToolResultText(jsonData), nil
		}

		// Return structured JSON content for programmatic access
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.NewTextContent(jsonData),
			},
			StructuredContent: structuredData,
			IsError:           false,
		}, nil
	}
}

// instructionData holds the data used to populate the MCP server instructions template.
type instructionData struct {
	Tools []toolInfo
}

// toolInfo represents information about an MCP tool for template rendering.
type toolInfo struct {
	Name        string
	Description string
}

// loadInstructions loads the server instructions from the embedded MCP server instructions template.
// It parses the template with dynamic data from the provided tools and returns the rendered instructions as a string for MCP client initialization.
//
// Parameters:
//   - tools: Slice of tool definitions without config requirements
//   - toolsWithConfig: Slice of tool definitions that require configuration access
//
// Returns:
//   - string: The rendered instruction text describing server capabilities and tool usage
//   - error: If the embedded file cannot be read or template parsing fails
//
// The instructions provide MCP clients with comprehensive guidance on using
// all available certificate analysis tools and workflows.
func loadInstructions(tools []ToolDefinition, toolsWithConfig []ToolDefinitionWithConfig) (string, error) {
	// Read the template file
	templateBytes, err := MagicEmbed.ReadFile("templates/X509_instructions.md")
	if err != nil {
		return "", fmt.Errorf("failed to load MCP server instructions template: %w", err)
	}

	// Extract tool info for template
	var toolInfos []toolInfo
	for _, tool := range tools {
		toolInfos = append(toolInfos, toolInfo{
			Name:        string(tool.Tool.Name),
			Description: tool.Tool.Description,
		})
	}
	for _, tool := range toolsWithConfig {
		toolInfos = append(toolInfos, toolInfo{
			Name:        string(tool.Tool.Name),
			Description: tool.Tool.Description,
		})
	}

	// Prepare data for template
	data := instructionData{
		Tools: toolInfos,
	}

	// Parse the template
	tmpl, err := template.New("instructions").Parse(string(templateBytes))
	if err != nil {
		return "", fmt.Errorf("failed to parse instructions template: %w", err)
	}

	// Execute the template
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute instructions template: %w", err)
	}

	return buf.String(), nil
}
