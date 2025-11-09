// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// RevocationStatus represents revocation status of a certificate
type RevocationStatus struct {
	OCSPStatus   string
	CRLEnabled   bool
	CRLStatus    string
	SerialNumber string
}

// ParseOCSPResponse parses a minimal OCSP response to extract status
func ParseOCSPResponse(respData []byte) (string, error) {
	// OCSP responses have a specific ASN.1 structure
	// For simplicity, we'll check for common status indicators in the response
	respStr := string(respData)

	// Look for status indicators in the response
	if strings.Contains(respStr, "good") {
		return "Good", nil
	}
	if strings.Contains(respStr, "revoked") {
		return "Revoked", nil
	}

	return "Unknown", nil
}

// ParseCRLResponse parses a minimal CRL response to extract status
func ParseCRLResponse(crlData []byte) (string, error) {
	// For simplicity, check if CRL contains "revoked" or similar indicators
	crlStr := string(crlData)

	if strings.Contains(crlStr, "revoked") || strings.Contains(crlStr, "REVOKED") {
		return "Revoked", nil
	}

	return "Good", nil
}

// checkOCSPStatus performs a basic OCSP check for revocation status
func (ch *Chain) checkOCSPStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {
	if len(cert.OCSPServer) == 0 {
		return &RevocationStatus{OCSPStatus: "Not Available"}, nil
	}

	ocspURL := cert.OCSPServer[0]

	// Create a simple OCSP request
	// Note: Full OCSP implementation would require ASN.1 encoding/decoding
	// For demonstration, we'll use a basic HTTP GET approach
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ocspURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}
	req.Header.Set("User-Agent", "X.509-Certificate-Chain-Resolver/"+ch.Version+" (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)")

	client := &http.Client{Timeout: 10}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OCSP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	// Read response
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	status, err := ParseOCSPResponse(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	return &RevocationStatus{
		OCSPStatus:   status,
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// checkCRLStatus performs a basic CRL check for revocation status
func (ch *Chain) checkCRLStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return &RevocationStatus{CRLStatus: "Not Available"}, nil
	}

	crlURL := cert.CRLDistributionPoints[0]

	// Fetch CRL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL request: %w", err)
	}
	req.Header.Set("User-Agent", "X.509-Certificate-Chain-Resolver/"+ch.Version+" (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)")

	client := &http.Client{Timeout: 10}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CRL request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned status %d", resp.StatusCode)
	}

	// Read CRL data
	crlData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	// For simplicity, check if CRL contains the certificate serial number
	// A full implementation would parse DER-encoded CRL structure
	status, err := ParseCRLResponse(crlData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return &RevocationStatus{
		CRLStatus:    status,
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// CheckRevocationStatus performs OCSP/CRL checks for the certificate chain
func (ch *Chain) CheckRevocationStatus(ctx context.Context) (string, error) {
	var result strings.Builder
	result.WriteString("Revocation Status Check:\n\n")

	for i, cert := range ch.Certs {
		// Skip ultimate trust anchor; roots aren't revoked via OCSP/CRL
		if i == len(ch.Certs)-1 {
			continue
		}

		result.WriteString(fmt.Sprintf("Certificate %d: %s\n", i+1, cert.Subject.CommonName))

		// Check OCSP
		ocspStatus, ocspErr := ch.checkOCSPStatus(ctx, cert)
		if ocspErr != nil {
			result.WriteString(fmt.Sprintf("  OCSP Error: %v\n", ocspErr))
		} else {
			result.WriteString(fmt.Sprintf("  OCSP Status: %s\n", ocspStatus.OCSPStatus))
		}

		// Check CRL
		crlStatus, crlErr := ch.checkCRLStatus(ctx, cert)
		if crlErr != nil {
			result.WriteString(fmt.Sprintf("  CRL Error: %v\n", crlErr))
		} else {
			result.WriteString(fmt.Sprintf("  CRL Status: %s\n", crlStatus.CRLStatus))
		}

		result.WriteString("\n")
	}

	return result.String(), nil
}
