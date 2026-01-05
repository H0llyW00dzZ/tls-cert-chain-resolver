// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/mcp"
)

// readCertificateData reads certificate data from either a file path or base64-encoded string.
// It first attempts to read as a file, then falls back to base64 decoding.
//
// Parameters:
//   - input: Certificate data as either a file path or base64-encoded string
//
// Returns:
//   - []byte: The certificate data bytes
//   - error: Error if both file reading and base64 decoding fail
//
// The function provides flexible input handling for certificate data in multiple formats.
// It prioritizes file reading for security and falls back to base64 for programmatic use.
func readCertificateData(input string) ([]byte, error) {
	// Try to read as file first
	if fileData, err := os.ReadFile(input); err == nil {
		return fileData, nil
	}

	// Try to decode as base64
	if decoded, err := base64.StdEncoding.DecodeString(input); err == nil {
		return decoded, nil
	}

	return nil, fmt.Errorf("certificate input '%s' is not a valid file path or base64-encoded data", input)
}

// resolveChainOptions contains configuration options for certificate chain resolution.
// It groups related parameters to reduce function complexity and improve maintainability.
//
// Fields:
//   - format: Output format ("pem", "der", or "json")
//   - includeSystemRoot: Whether to include system root CA in the chain
//   - intermediateOnly: Whether to return only intermediate certificates
type resolveChainOptions struct {
	// format: Output format ("pem", "der", or "json")
	format string
	// includeSystemRoot: Whether to include system root CA in the chain
	includeSystemRoot bool
	// intermediateOnly: Whether to return only intermediate certificates
	intermediateOnly bool
}

// validateResolveParams validates and extracts parameters for certificate chain resolution.
// It ensures required parameters are present and returns structured resolution options.
//
// Parameters:
//   - request: MCP tool call request containing certificate input and format options
//
// Returns:
//   - certInput: Certificate input as file path or base64 data
//   - opts: Structured resolution options
//   - error: Parameter validation error
func validateResolveParams(request mcp.CallToolRequest) (certInput string, opts resolveChainOptions, err error) {
	certInput, err = request.RequireString("certificate")
	if err != nil {
		return "", resolveChainOptions{}, fmt.Errorf("certificate parameter required: %w", err)
	}

	opts = resolveChainOptions{
		format:            request.GetString("format", "pem"),
		includeSystemRoot: request.GetBool("include_system_root", false),
		intermediateOnly:  request.GetBool("intermediate_only", false),
	}

	return certInput, opts, nil
}

// resolveCertChain performs the core certificate chain resolution logic.
// It reads, decodes, and fetches the complete certificate chain with optional root CA addition.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - certInput: Certificate input as file path or base64 data
//   - opts: Resolution options controlling processing behavior
//
// Returns:
//   - certs: Resolved certificate chain
//   - error: Chain resolution error
func resolveCertChain(ctx context.Context, certInput string, opts resolveChainOptions) ([]*x509.Certificate, error) {
	// Read certificate data
	certData, err := readCertificateData(certInput)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Decode certificate
	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	// Fetch certificate chain
	chain := x509chain.New(cert, version.Version)
	if err := chain.FetchCertificate(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch certificate chain: %w", err)
	}

	// Optionally add system root CA
	if opts.includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			return nil, fmt.Errorf("failed to add root CA: %w", err)
		}
	}

	// Filter certificates if needed
	certs := chain.Certs
	if opts.intermediateOnly {
		certs = chain.FilterIntermediates()
	}

	return certs, nil
}

// formatChainOutput formats the resolved certificate chain according to the specified format.
// It handles PEM, DER, and JSON output formats with appropriate encoding.
//
// Parameters:
//   - certs: Certificate chain to format
//   - format: Output format ("pem", "der", or "json")
//   - certManager: Certificate manager for encoding operations
//
// Returns:
//   - output: Formatted certificate data as string
func formatChainOutput(certs []*x509.Certificate, format string, certManager *x509certs.Certificate) string {
	switch format {
	case "der":
		derData := certManager.EncodeMultipleDER(certs)
		return base64.StdEncoding.EncodeToString(derData)
	case "json":
		return formatJSON(certs, certManager)
	default: // pem
		pemData := certManager.EncodeMultiplePEM(certs)
		return string(pemData)
	}
}

// buildResolveResult creates the final formatted result for certificate chain resolution.
// It includes chain information and the formatted certificate data.
//
// Parameters:
//   - certs: Resolved certificate chain
//   - output: Formatted certificate data
//
// Returns:
//   - result: Complete formatted result string
func buildResolveResult(certs []*x509.Certificate, output string) string {
	var chainInfo strings.Builder
	chainInfo.WriteString("Certificate chain resolved successfully:\n")
	for i, c := range certs {
		chainInfo.WriteString(fmt.Sprintf("%d: %s\n", i+1, c.Subject.CommonName))
	}
	chainInfo.WriteString(fmt.Sprintf("\nTotal: %d certificate(s)\n\n", len(certs)))
	chainInfo.WriteString(output)

	return chainInfo.String()
}

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
	// Validate and extract parameters
	certInput, opts, err := validateResolveParams(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Resolve certificate chain
	certs, err := resolveCertChain(ctx, certInput, opts)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Format output
	certManager := x509certs.New()
	output := formatChainOutput(certs, opts.format, certManager)

	// Build and return result
	result := buildResolveResult(certs, output)
	return mcp.NewToolResultText(result), nil
}

// validateValidateParams validates and extracts parameters for certificate chain validation.
// It ensures required parameters are present and returns structured validation options.
//
// Parameters:
//   - request: MCP tool call request containing certificate input and validation options
//
// Returns:
//   - certInput: Certificate input as file path or base64 data
//   - includeSystemRoot: Whether to include system root CA for validation
//   - error: Parameter validation error
func validateValidateParams(request mcp.CallToolRequest) (certInput string, includeSystemRoot bool, err error) {
	certInput, err = request.RequireString("certificate")
	if err != nil {
		return "", false, fmt.Errorf("certificate parameter required: %w", err)
	}

	includeSystemRoot = request.GetBool("include_system_root", true)
	return certInput, includeSystemRoot, nil
}

// validateCertChain performs comprehensive certificate chain validation.
// It resolves the complete chain, verifies signatures, checks revocation status, and returns validation results.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - certInput: Certificate input as file path or base64 data
//   - includeSystemRoot: Whether to include system root CA for validation
//
// Returns:
//   - chain: Validated certificate chain
//   - revocationStatus: Revocation check results
//   - error: Validation error
func validateCertChain(ctx context.Context, certInput string, includeSystemRoot bool) (*x509chain.Chain, string, error) {
	// Read certificate data
	certData, err := readCertificateData(certInput)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read certificate: %w", err)
	}

	// Decode certificate
	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode certificate: %w", err)
	}

	// Create chain and fetch certificates
	chain := x509chain.New(cert, version.Version)
	if err := chain.FetchCertificate(ctx); err != nil {
		return nil, "", fmt.Errorf("failed to fetch certificate chain: %w", err)
	}

	// Add system root if requested
	if includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			return nil, "", fmt.Errorf("failed to add root CA: %w", err)
		}
	}

	// Validate the chain
	if err := chain.VerifyChain(); err != nil {
		return nil, "", fmt.Errorf("certificate chain validation failed: %w", err)
	}

	// Check revocation status
	revocationStatus, err := chain.CheckRevocationStatus(ctx)
	if err != nil {
		// Log error but don't fail - revocation checking is optional
		revocationStatus = fmt.Sprintf("Revocation check failed: %v", err)
	}

	return chain, revocationStatus, nil
}

// buildValidationResult creates the formatted result for certificate chain validation.
// It includes chain details, certificate information, and validation status.
//
// Parameters:
//   - chain: Validated certificate chain
//   - revocationStatus: Revocation check results
//
// Returns:
//   - result: Formatted validation result string
func buildValidationResult(chain *x509chain.Chain, revocationStatus string) string {
	var result strings.Builder
	result.WriteString("Certificate chain validation successful!\n\n")
	result.WriteString("Chain Details:\n")
	for i, c := range chain.Certs {
		result.WriteString(fmt.Sprintf("%d: %s\n", i+1, c.Subject.CommonName))
		result.WriteString(fmt.Sprintf("   Valid: %s to %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02")))
		if chain.IsRootNode(c) {
			result.WriteString("   Type: Root CA\n")
		} else if chain.IsSelfSigned(c) {
			result.WriteString("   Type: Self-signed\n")
		} else {
			result.WriteString("   Type: Intermediate\n")
		}
	}
	result.WriteString(fmt.Sprintf("\nTotal certificates: %d\n", len(chain.Certs)))
	result.WriteString("Validation: PASSED ✓\n\n")
	result.WriteString(revocationStatus)

	return result.String()
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
	// Validate and extract parameters
	certInput, includeSystemRoot, err := validateValidateParams(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Validate certificate chain
	chain, revocationStatus, err := validateCertChain(ctx, certInput, includeSystemRoot)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Build and return result
	result := buildValidationResult(chain, revocationStatus)
	return mcp.NewToolResultText(result), nil
}

// batchResolveOptions contains configuration options for batch certificate resolution operations.
// It groups related parameters to reduce function complexity and improve maintainability.
//
// Fields:
//   - format: Output format ("pem", "der", or "json")
//   - includeSystemRoot: Whether to include system root CA in the chain
//   - intermediateOnly: Whether to return only intermediate certificates
type batchResolveOptions struct {
	// format: Output format ("pem", "der", or "json")
	format string
	// includeSystemRoot: Whether to include system root CA in the chain
	includeSystemRoot bool
	// intermediateOnly: Whether to return only intermediate certificates
	intermediateOnly bool
}

// processSingleCertificate processes a single certificate input and returns formatted result.
// It handles the complete certificate processing workflow including reading, decoding, chain resolution,
// and formatting for a single certificate in a batch operation.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling during certificate fetching
//   - certInput: Certificate input as file path or base64-encoded data
//   - index: Certificate index in the batch (0-based) for display purposes
//   - opts: Batch resolution options controlling output format and processing behavior
//
// Returns:
//   - A formatted string containing the certificate processing result or error message
//
// The function performs all certificate operations (read, decode, fetch chain, format) for a single
// certificate and returns a consistent result format suitable for batch processing.
func processSingleCertificate(ctx context.Context, certInput string, index int, opts batchResolveOptions) string {
	result := fmt.Sprintf("Certificate %d:\n", index+1)

	// Read certificate data
	certData, err := readCertificateData(certInput)
	if err != nil {
		result += fmt.Sprintf("  Error: failed to read certificate: %v\n", err)
		return result
	}

	// Decode certificate
	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		result += fmt.Sprintf("  Error: failed to decode certificate: %v\n", err)
		return result
	}

	// Fetch certificate chain
	chain := x509chain.New(cert, version.Version)
	if err := chain.FetchCertificate(ctx); err != nil {
		result += fmt.Sprintf("  Error: failed to fetch certificate chain: %v\n", err)
		return result
	}

	// Optionally add system root CA
	if opts.includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			result += fmt.Sprintf("  Warning: failed to add root CA: %v\n", err)
		}
	}

	// Filter certificates if needed
	certs := chain.Certs
	if opts.intermediateOnly {
		certs = chain.FilterIntermediates()
	}

	// Format output
	switch opts.format {
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
	return result
}

// formatBatchResults combines individual certificate results into final batch output.
// It creates a structured summary showing the total number of certificates processed
// and concatenates all individual results with proper formatting.
//
// Parameters:
//   - results: Slice of individual certificate processing results (one per certificate)
//   - totalProcessed: Total number of certificates that were processed (including failures)
//
// Returns:
//   - A formatted string containing the complete batch results summary
//
// The function provides consistent batch output formatting that matches the expected
// user interface for batch certificate operations.
func formatBatchResults(results []string, totalProcessed int) string {
	finalResult := "Batch Certificate Chain Resolution Results:\n"
	finalResult += fmt.Sprintf("Processed %d certificate(s)\n\n", totalProcessed)
	finalResult += strings.Join(results, "\n")
	return finalResult
}

// validateBatchParams validates and extracts parameters for batch certificate resolution.
// It ensures required parameters are present and returns structured batch options.
//
// Parameters:
//   - request: MCP tool call request containing certificate inputs and format options
//
// Returns:
//   - certInput: Raw certificate input string (comma-separated)
//   - opts: Structured batch resolution options
//   - error: Parameter validation error
func validateBatchParams(request mcp.CallToolRequest) (certInput string, opts batchResolveOptions, err error) {
	certInput, err = request.RequireString("certificates")
	if err != nil {
		return "", batchResolveOptions{}, fmt.Errorf("certificates parameter required: %w", err)
	}

	opts = batchResolveOptions{
		format:            request.GetString("format", "pem"),
		includeSystemRoot: request.GetBool("include_system_root", false),
		intermediateOnly:  request.GetBool("intermediate_only", false),
	}

	return certInput, opts, nil
}

// parseCertInputs parses comma-separated certificate inputs and trims whitespace.
// It filters out empty inputs to ensure clean processing.
//
// Parameters:
//   - certInput: Raw certificate input string (comma-separated)
//
// Returns:
//   - certInputs: Cleaned list of certificate inputs
func parseCertInputs(certInput string) []string {
	inputs := strings.Split(certInput, ",")
	var cleanedInputs []string
	for _, input := range inputs {
		trimmed := strings.TrimSpace(input)
		if trimmed != "" {
			cleanedInputs = append(cleanedInputs, trimmed)
		}
	}
	return cleanedInputs
}

// processBatchCertificates processes multiple certificates in batch.
// It processes each certificate independently and collects results.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - certInputs: List of certificate inputs to process
//   - opts: Batch resolution options
//
// Returns:
//   - results: List of processing results for each certificate
func processBatchCertificates(ctx context.Context, certInputs []string, opts batchResolveOptions) []string {
	results := make([]string, 0, len(certInputs))

	for i, certInput := range certInputs {
		result := processSingleCertificate(ctx, certInput, i, opts)
		results = append(results, result)
	}

	return results
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
	// Validate and extract parameters
	certInput, opts, err := validateBatchParams(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Parse certificate inputs
	certInputs := parseCertInputs(certInput)

	// Process certificates in batch
	results := processBatchCertificates(ctx, certInputs, opts)

	// Combine and return results
	finalResult := formatBatchResults(results, len(certInputs))
	return mcp.NewToolResultText(finalResult), nil
}

// validateRemoteParams validates and extracts parameters for remote certificate fetching.
// It ensures required parameters are present and returns structured remote options.
//
// Parameters:
//   - request: MCP tool call request containing hostname, port, and format options
//   - config: Server configuration containing defaults
//
// Returns:
//   - hostname: Target hostname to connect to
//   - port: Port number for connection
//   - format: Output format for certificates
//   - includeSystemRoot: Whether to include system root CA
//   - intermediateOnly: Whether to return only intermediate certificates
//   - error: Parameter validation error
func validateRemoteParams(request mcp.CallToolRequest, config *Config) (hostname string, port int, format string, includeSystemRoot, intermediateOnly bool, err error) {
	hostname, err = request.RequireString("hostname")
	if err != nil {
		return "", 0, "", false, false, fmt.Errorf("hostname parameter required: %w", err)
	}

	port = request.GetInt("port", 443)
	format = request.GetString("format", "pem")
	includeSystemRoot = request.GetBool("include_system_root", false)
	intermediateOnly = request.GetBool("intermediate_only", false)

	return hostname, port, format, includeSystemRoot, intermediateOnly, nil
}

// fetchRemoteCertificates fetches certificate chain from a remote hostname and port.
// It establishes a TLS connection and retrieves server certificates with optional post-processing.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - hostname: Target hostname to connect to
//   - port: Port number for connection
//   - includeSystemRoot: Whether to include system root CA
//   - intermediateOnly: Whether to return only intermediate certificates
//   - config: Server configuration containing timeout settings
//
// Returns:
//   - chain: Certificate chain object
//   - filteredCerts: Filtered certificate list based on options
//   - certCount: Number of certificates initially received
//   - error: Fetching or processing error
func fetchRemoteCertificates(ctx context.Context, hostname string, port int, includeSystemRoot, intermediateOnly bool, config *Config) (*x509chain.Chain, []*x509.Certificate, int, error) {
	chain, certs, err := x509chain.FetchRemoteChain(ctx, hostname, port, time.Duration(config.Defaults.Timeout)*time.Second, version.Version)
	if err != nil {
		return nil, nil, 0, err
	}

	// Fetch any additional certificates if needed
	if err := chain.FetchCertificate(ctx); err != nil {
		// This might fail if intermediates are already complete, which is ok
		// We'll proceed with what we have
	}

	// Optionally add system root CA
	if includeSystemRoot {
		if err := chain.AddRootCA(); err != nil {
			return nil, nil, 0, fmt.Errorf("failed to add root CA: %w", err)
		}
	}

	// Filter certificates if needed
	filteredCerts := chain.Certs
	if intermediateOnly {
		filteredCerts = chain.FilterIntermediates()
	}

	return chain, filteredCerts, len(certs), nil
}

// buildRemoteResult creates the formatted result for remote certificate fetching.
// It includes connection details, certificate counts, and formatted certificate data.
//
// Parameters:
//   - hostname: Target hostname that was connected to
//   - port: Port number that was used
//   - certCount: Number of certificates initially received
//   - filteredCerts: Final list of certificates after filtering
//   - format: Output format for certificates
//
// Returns:
//   - result: Formatted remote certificate fetch result string
func buildRemoteResult(hostname string, port int, certCount int, filteredCerts []*x509.Certificate, format string) (string, error) {
	certManager := x509certs.New()

	result := "Remote Certificate Fetch Results:\n"
	result += fmt.Sprintf("Host: %s:%d\n", hostname, port)
	result += fmt.Sprintf("Certificates received: %d\n", certCount)
	result += fmt.Sprintf("Certificates after filtering: %d\n\n", len(filteredCerts))

	var output string
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
	return result, nil
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
	// Validate and extract parameters
	hostname, port, format, includeSystemRoot, intermediateOnly, err := validateRemoteParams(request, config)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Fetch remote certificates
	_, filteredCerts, certCount, err := fetchRemoteCertificates(ctx, hostname, port, includeSystemRoot, intermediateOnly, config)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Build and return result
	result, err := buildRemoteResult(hostname, port, certCount, filteredCerts, format)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(result), nil
}

// validateExpiryParams validates and extracts parameters for certificate expiry checking.
// It ensures required parameters are present and uses the configured warning days.
//
// Parameters:
//   - request: MCP tool call request containing certificate input
//   - config: Server configuration containing default warning days
//
// Returns:
//   - certInput: Certificate input as file path or base64 data
//   - warnDays: Number of days before expiry to show warnings (from config)
//   - error: Parameter validation error
func validateExpiryParams(request mcp.CallToolRequest, config *Config) (certInput string, warnDays int, err error) {
	certInput, err = request.RequireString("certificate")
	if err != nil {
		return "", 0, fmt.Errorf("certificate parameter required: %w", err)
	}

	warnDays = config.Defaults.WarnDays
	return certInput, warnDays, nil
}

// checkCertificateExpiry performs expiry analysis on certificates.
// It calculates days until expiry and categorizes certificates by status.
//
// Parameters:
//   - certInput: Certificate input as file path or base64 data
//   - warnDays: Number of days before expiry to show warnings
//
// Returns:
//   - certs: Decoded certificates
//   - expiryResults: List of expiry status for each certificate
//   - summary: Summary statistics
//   - error: Processing error
func checkCertificateExpiry(certInput string, warnDays int) ([]*x509.Certificate, []string, map[string]int, error) {
	// Read certificate data
	certData, err := readCertificateData(certInput)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Decode certificate(s) - could be a bundle
	certManager := x509certs.New()
	certs, err := certManager.DecodeMultiple(certData)
	if err != nil {
		// Try single cert
		cert, err := certManager.Decode(certData)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode certificate: %w", err)
		}
		certs = []*x509.Certificate{cert}
	}

	// Check expiry for each certificate
	now := time.Now()
	var expiryResults []string
	expiredCount := 0
	expiringSoonCount := 0

	for i, cert := range certs {
		result := fmt.Sprintf("Certificate %d: %s\n", i+1, cert.Subject.CommonName)
		result += fmt.Sprintf("  Issued: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		result += fmt.Sprintf("  Expires: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

		if now.After(cert.NotAfter) {
			result += fmt.Sprintf("  Status: EXPIRED (%d days ago)\n", -daysUntilExpiry)
			expiredCount++
		} else if daysUntilExpiry <= warnDays {
			result += fmt.Sprintf("  Status: EXPIRING SOON (%d days remaining)\n", daysUntilExpiry)
			expiringSoonCount++
		} else {
			result += fmt.Sprintf("  Status: VALID (%d days remaining)\n", daysUntilExpiry)
		}
		result += "\n"

		expiryResults = append(expiryResults, result)
	}

	summary := map[string]int{
		"total":        len(certs),
		"expired":      expiredCount,
		"expiringSoon": expiringSoonCount,
		"valid":        len(certs) - expiredCount - expiringSoonCount,
	}

	return certs, expiryResults, summary, nil
}

// buildExpiryResult creates the formatted result for certificate expiry checking.
// It includes individual certificate status and summary statistics.
//
// Parameters:
//   - expiryResults: Individual certificate expiry status strings
//   - summary: Summary statistics map
//   - warnDays: Warning threshold used for analysis
//
// Returns:
//   - result: Formatted expiry check result string
func buildExpiryResult(expiryResults []string, summary map[string]int, warnDays int) string {
	var result strings.Builder
	result.WriteString("Certificate Expiry Check Results:\n\n")

	// Individual certificate results
	for _, certResult := range expiryResults {
		result.WriteString(certResult)
	}

	// Summary
	result.WriteString("Summary:\n")
	result.WriteString(fmt.Sprintf("- Total certificates checked: %d\n", summary["total"]))
	result.WriteString(fmt.Sprintf("- Expired: %d\n", summary["expired"]))
	result.WriteString(fmt.Sprintf("- Expiring within %d days: %d\n", warnDays, summary["expiringSoon"]))
	result.WriteString(fmt.Sprintf("- Valid: %d\n", summary["valid"]))

	allValid := summary["expired"] == 0 && summary["expiringSoon"] == 0
	if allValid {
		result.WriteString("\n✓ All certificates are valid and not expiring soon.")
	} else {
		result.WriteString("\n⚠️  Some certificates require attention.")
	}

	return result.String()
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
	// Validate and extract parameters
	certInput, warnDays, err := validateExpiryParams(request, config)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Check certificate expiry
	_, expiryResults, summary, err := checkCertificateExpiry(certInput, warnDays)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Build and return result
	result := buildExpiryResult(expiryResults, summary, warnDays)
	return mcp.NewToolResultText(result), nil
}

// validateAIAnalysisParams validates and extracts parameters for AI certificate analysis.
// It ensures required parameters are present and returns structured analysis options.
//
// Parameters:
//   - request: MCP tool call request containing certificate input and analysis type
//
// Returns:
//   - certInput: Certificate input as file path or base64 data
//   - analysisType: Type of analysis (general, security, compliance)
//   - error: Parameter validation error
func validateAIAnalysisParams(request mcp.CallToolRequest) (certInput string, analysisType string, err error) {
	certInput, err = request.RequireString("certificate")
	if err != nil {
		return "", "", fmt.Errorf("certificate parameter required: %w", err)
	}

	analysisType = request.GetString("analysis_type", "general")
	return certInput, analysisType, nil
}

// prepareCertificateForAnalysis reads and decodes certificate data, then prepares the certificate chain.
// It handles both single certificates and certificate bundles, fetching additional certificates as needed.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - certInput: Certificate input as file path or base64 data
//   - config: Server configuration containing timeout settings
//
// Returns:
//   - chain: Prepared certificate chain ready for analysis
//   - error: Certificate processing error
func prepareCertificateForAnalysis(ctx context.Context, certInput string, config *Config) (*x509chain.Chain, error) {
	// Read certificate data
	certData, err := readCertificateData(certInput)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Create certificate manager
	certManager := x509certs.New()

	// Decode certificate(s)
	certs, err := certManager.DecodeMultiple(certData)
	if err != nil {
		// Try single cert
		cert, err := certManager.Decode(certData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: %w", err)
		}
		certs = []*x509.Certificate{cert}
	}

	// Create certificate chain
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

	return chain, nil
}

// performRevocationCheck performs revocation status checks for the certificate chain.
// It uses OCSP/CRL checking with proper timeout handling and returns formatted status.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - chain: Certificate chain to check revocation status for
//   - config: Server configuration containing timeout settings
//
// Returns:
//   - revocationStatus: Formatted revocation status string
func performRevocationCheck(ctx context.Context, chain *x509chain.Chain, config *Config) string {
	revocationCtx, revocationCancel := context.WithTimeout(ctx, time.Duration(config.Defaults.Timeout)*time.Second)
	defer revocationCancel()

	revocationStatus, err := chain.CheckRevocationStatus(revocationCtx)
	if err != nil {
		// Revocation checking failure is not fatal
		revocationStatus = fmt.Sprintf("Revocation check failed: %v", err)
	}

	return revocationStatus
}

// buildAIAnalysisPrompt constructs the complete analysis prompt for AI processing.
// It combines certificate context with analysis-specific instructions.
//
// Parameters:
//   - chain: Certificate chain with revocation status
//   - revocationStatus: Revocation check results
//   - analysisType: Type of analysis requested
//
// Returns:
//   - prompt: Complete analysis prompt for AI processing
func buildAIAnalysisPrompt(chain *x509chain.Chain, revocationStatus, analysisType string) string {
	certificateContext := buildCertificateContextWithRevocation(chain, revocationStatus, analysisType)
	return certificateContext + "\n\n" + getAnalysisInstruction(analysisType)
}

// executeAIAnalysis performs the actual AI analysis using the configured sampling handler.
// It handles system prompt loading, sampling request creation, and response processing.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - analysisPrompt: Complete analysis prompt for AI
//   - analysisType: Type of analysis for result formatting
//   - config: Server configuration containing AI settings
//
// Returns:
//   - result: Formatted AI analysis result
//   - error: AI processing error
func executeAIAnalysis(ctx context.Context, analysisPrompt, analysisType string, config *Config) (string, error) {
	// Read system prompt from embedded template
	systemPromptBytes, err := templates.MagicEmbed.ReadFile("certificate-analysis-system-prompt.md")
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
		return fmt.Sprintf("AI Analysis Request Failed: %v", err), nil
	}

	// Format the AI's analysis
	result := fmt.Sprintf("🤖 AI-Powered Certificate Analysis (%s)\n\n", analysisType)
	result += "Analysis provided by AI assistant:\n\n"
	if textContent, ok := samplingResult.SamplingMessage.Content.(mcp.TextContent); ok {
		result += textContent.Text
	} else {
		result += "AI provided analysis (content format not supported for display)"
	}
	result += fmt.Sprintf("\n\n---\n*AI Model: %s*", samplingResult.Model)

	return result, nil
}

// formatFallbackResult creates a fallback result when AI API key is not configured.
// It shows what would be sent to AI for analysis.
//
// Parameters:
//   - analysisType: Type of analysis requested
//   - certificateContext: Certificate context that would be sent to AI
//   - analysisPrompt: Complete analysis prompt that would be sent
//
// Returns:
//   - result: Formatted fallback result with configuration instructions
func formatFallbackResult(analysisType, certificateContext, analysisPrompt string) string {
	result := fmt.Sprintf("AI Collaborative Analysis (%s)\n\n", analysisType)
	result += "⚠️  No AI API key configured. To enable real AI analysis:\n"
	result += "   1. Set X509_AI_APIKEY environment variable, or\n"
	result += "   2. Configure 'ai.apiKey' in your config.json or config.yaml file\n\n"
	result += "📋 Certificate Context Prepared for AI Analysis:\n"
	result += certificateContext
	result += fmt.Sprintf("\n\n💭 Analysis Prompt Ready:\n%s", analysisPrompt)
	result += "\n\n🔄 With API key configured, this would send the context to AI for intelligent analysis."

	return result
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
	// Validate and extract parameters
	certInput, analysisType, err := validateAIAnalysisParams(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Prepare certificate chain for analysis
	chain, err := prepareCertificateForAnalysis(ctx, certInput, config)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Perform revocation status checks
	revocationStatus := performRevocationCheck(ctx, chain, config)

	// Build analysis prompt for AI
	analysisPrompt := buildAIAnalysisPrompt(chain, revocationStatus, analysisType)

	// Try to get AI analysis if API key is configured
	if config.AI.APIKey != "" {
		result, err := executeAIAnalysis(ctx, analysisPrompt, analysisType, config)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(result), nil
	}

	// Fallback: Show what would be sent to AI (no API key configured)
	certificateContext := buildCertificateContextWithRevocation(chain, revocationStatus, analysisType)
	result := formatFallbackResult(analysisType, certificateContext, analysisPrompt)
	return mcp.NewToolResultText(result), nil
}

// validateResourceParams validates and extracts parameters for resource usage monitoring.
// It ensures parameters are properly handled with defaults.
//
// Parameters:
//   - request: MCP tool call request containing format and detail level parameters
//
// Returns:
//   - detailed: Whether to include detailed metrics
//   - format: Output format ("json" or "markdown")
func validateResourceParams(request mcp.CallToolRequest) (detailed bool, format string) {
	detailed = request.GetBool("detailed", false)
	format = request.GetString("format", "json")
	return detailed, format
}

// formatResourceResult formats resource usage data according to the specified format.
// It handles both JSON and Markdown output formats with appropriate structured content.
//
// Parameters:
//   - data: Resource usage data to format
//   - format: Output format ("json" or "markdown")
//
// Returns:
//   - result: Formatted MCP tool result
//   - error: Formatting error
func formatResourceResult(data *ResourceUsageData, format string) (*mcp.CallToolResult, error) {
	switch format {
	case "markdown":
		markdown := FormatResourceUsageAsMarkdown(data)
		return mcp.NewToolResultText(markdown), nil
	case "json":
		fallthrough
	default:
		jsonData, err := FormatResourceUsageAsJSON(data)
		if err != nil {
			return nil, fmt.Errorf("failed to format resource usage: %w", err)
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
	// Validate and extract parameters
	detailed, format := validateResourceParams(request)

	// Collect resource usage data
	data := CollectResourceUsage(detailed)

	// Format and return result
	result, err := formatResourceResult(data, format)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return result, nil
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

// buildCertificateContextWithRevocation creates comprehensive context information about certificates for AI analysis including revocation status.
// It builds detailed certificate context with OCSP/CRL revocation information for enhanced security analysis.
//
// Parameters:
//   - chain: Certificate chain to analyze
//   - revocationStatus: String containing revocation check results (OCSP/CRL status)
//   - analysisType: Type of analysis (general, security, compliance)
//
// Returns:
//   - A formatted string containing comprehensive certificate context including revocation status
//
// This function provides complete certificate analysis context including cryptographic details,
// validity periods, extensions, and revocation status for AI-powered security assessment.
// It uses helper functions to organize information into logical sections.
func buildCertificateContextWithRevocation(chain *x509chain.Chain, revocationStatus string, analysisType string) string {
	var context strings.Builder

	// Handle nil chain gracefully
	var certs []*x509.Certificate
	if chain != nil {
		certs = chain.Certs
	}

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
		fmt.Fprintf(&context, "Role: %s\n", chain.GetCertificateRole(i))

		appendSubjectInfo(&context, cert)
		appendIssuerInfo(&context, cert)
		appendValidityInfo(&context, cert)
		appendCryptoInfo(&context, chain, cert)
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
//   - chain: Certificate chain instance for key size calculation
//   - cert: X.509 certificate to extract cryptographic information from
//
// The function extracts signature algorithm, public key algorithm, and key size
// information for security analysis and compliance assessment.
func appendCryptoInfo(context *strings.Builder, chain *x509chain.Chain, cert *x509.Certificate) {
	context.WriteString("CRYPTOGRAPHY:\n")
	fmt.Fprintf(context, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())
	fmt.Fprintf(context, "  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())

	keySize := 0
	if chain != nil {
		keySize = chain.KeySize(cert)
	}
	fmt.Fprintf(context, "  Key Size: %d bits\n", keySize)
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

// validateVisualizeParams validates and extracts parameters for certificate chain visualization.
// It ensures required parameters are present and validates the format option.
//
// Parameters:
//   - request: MCP tool call request containing certificate input and format options
//
// Returns:
//   - certInput: Certificate input as file path or base64 data
//   - format: Visualization format ("ascii", "table", or "json")
//   - error: Parameter validation error
func validateVisualizeParams(request mcp.CallToolRequest) (certInput, format string, err error) {
	certInput, err = request.RequireString("certificate")
	if err != nil {
		return "", "", fmt.Errorf("certificate parameter required: %w", err)
	}

	format = request.GetString("format", "ascii")
	validFormats := map[string]bool{
		"ascii": true,
		"table": true,
		"json":  true,
	}
	if !validFormats[format] {
		return "", "", fmt.Errorf("unsupported format '%s', supported formats: ascii, table, json", format)
	}

	return certInput, format, nil
}

// resolveCertChainForVisualization resolves a certificate chain for visualization purposes.
// It reads, decodes, and fetches the complete certificate chain.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - certInput: Certificate input as file path or base64 data
//
// Returns:
//   - chain: Resolved certificate chain ready for visualization
//   - error: Chain resolution error
func resolveCertChainForVisualization(ctx context.Context, certInput string) (*x509chain.Chain, error) {
	// Read certificate data
	certData, err := readCertificateData(certInput)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Decode certificate
	certManager := x509certs.New()
	cert, err := certManager.Decode(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	// Resolve certificate chain
	chain := x509chain.New(cert, version.Version)
	if err := chain.FetchCertificate(ctx); err != nil {
		return nil, fmt.Errorf("failed to resolve certificate chain: %w", err)
	}

	return chain, nil
}

// formatVisualizationResult generates the visualization output in the specified format.
// It uses the chain's built-in visualization methods for ASCII tree, table, and JSON formats.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - chain: Resolved certificate chain to visualize
//   - format: Visualization format ("ascii", "table", or "json")
//
// Returns:
//   - result: Formatted visualization output
//   - error: Visualization generation error
func formatVisualizationResult(ctx context.Context, chain *x509chain.Chain, format string) (string, error) {
	// Note: Revocation status is now checked internally by the visualization methods
	switch format {
	case "ascii":
		return chain.RenderASCIITree(ctx), nil
	case "table":
		return chain.RenderTable(ctx), nil
	case "json":
		jsonData, err := chain.ToVisualizationJSON(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to generate JSON visualization: %w", err)
		}
		return string(jsonData), nil
	default:
		return "", fmt.Errorf("unsupported format '%s'", format)
	}
}

// handleVisualizeCertChain visualizes a certificate chain in multiple formats (ASCII tree, table, JSON).
// It resolves the certificate chain and provides rich visualization for better analysis and debugging.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP tool call request containing certificate input and format options
//
// Returns:
//   - The tool execution result containing the certificate chain visualization
//   - An error if certificate resolution or visualization fails
//
// The function supports multiple output formats:
//   - "ascii": ASCII tree diagram showing certificate hierarchy
//   - "table": Markdown table with certificate details
//   - "json": Structured JSON export for external tools
//
// This provides enhanced certificate chain analysis capabilities for debugging and documentation.
func handleVisualizeCertChain(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Validate and extract parameters
	certInput, format, err := validateVisualizeParams(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Resolve certificate chain
	chain, err := resolveCertChainForVisualization(ctx, certInput)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Generate visualization
	result, err := formatVisualizationResult(ctx, chain, format)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(result), nil
}
