// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/mcp"
)

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
	result += "Validation: PASSED ✓"

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

	portStr := request.GetString("port", strconv.Itoa(config.Defaults.Port))
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		port = config.Defaults.Port // fallback to config default
	}

	// Establish TLS connection to get certificate chain
	dialer := &net.Dialer{
		Timeout: time.Duration(config.Defaults.Timeout) * time.Second,
	}

	format := request.GetString("format", config.Defaults.Format)
	includeSystemRoot := request.GetBool("include_system_root", config.Defaults.IncludeSystemRoot)
	intermediateOnly := request.GetBool("intermediate_only", config.Defaults.IntermediateOnly)

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", hostname, port), &tls.Config{
		InsecureSkipVerify: true, // We just want the cert chain, not to verify
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to connect to %s:%d: %v", hostname, port, err)), nil
	}
	defer conn.Close()

	// Get the certificate chain from the connection
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return mcp.NewToolResultError("no certificates received from server"), nil
	}

	// Use the leaf certificate to create a chain
	leafCert := certs[0]
	chain := x509chain.New(leafCert, version.Version)

	// Add the intermediates from the connection
	for _, cert := range certs[1:] {
		chain.Certs = append(chain.Certs, cert)
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
	result += fmt.Sprintf("Certificates received: %d\n\n", len(certs))

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

func handleCheckCertExpiry(request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
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
		"title":            "TLS Certificate Chain",
		"totalChained":     len(certs),
		"listCertificates": certInfos,
	}

	jsonData, _ := json.MarshalIndent(output, "", "  ")
	return string(jsonData)
}
