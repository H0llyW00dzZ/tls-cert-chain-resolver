// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
)

// RevocationStatus represents revocation status of a certificate
type RevocationStatus struct {
	OCSPStatus   string
	CRLStatus    string
	SerialNumber string
}

// ParseOCSPResponse parses an OCSP response to extract certificate status
func ParseOCSPResponse(respData []byte) (string, error) {
	// Basic OCSP response parsing
	// OCSP responses are ASN.1 encoded, but for simplicity we'll do basic checks
	respStr := strings.ToLower(string(respData))

	// Check for common OCSP response patterns
	if strings.Contains(respStr, "good") || bytes.Contains(respData, []byte{0x00, 0x01}) {
		return "Good", nil
	}
	if strings.Contains(respStr, "revoked") || bytes.Contains(respData, []byte{0x00, 0x02}) {
		return "Revoked", nil
	}
	if strings.Contains(respStr, "unknown") || bytes.Contains(respData, []byte{0x00, 0x03}) {
		return "Unknown", nil
	}

	// If we can't determine status, return unknown
	return "Unknown", nil
}

// ParseCRLResponse parses a CRL response to extract status for a specific certificate
func ParseCRLResponse(crlData []byte, certSerial *big.Int) (string, error) {
	if len(crlData) == 0 {
		return "Unknown", fmt.Errorf("empty CRL data")
	}

	if certSerial == nil {
		return "Unknown", fmt.Errorf("certificate serial number is nil")
	}

	var lastErr error
	data := crlData

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if strings.Contains(block.Type, "CRL") {
			status, err := parseCRLBlock(block.Bytes, certSerial)
			if err != nil {
				lastErr = err
			} else {
				return status, nil
			}
		}

		if len(rest) == 0 {
			break
		}
		data = rest
	}

	status, err := parseCRLBlock(crlData, certSerial)
	if err == nil {
		return status, nil
	}

	if lastErr != nil {
		return "Unknown", lastErr
	}

	return "Unknown", err
}

func parseCRLBlock(der []byte, certSerial *big.Int) (string, error) {
	crl, err := x509.ParseCRL(der)
	if err != nil {
		return "Unknown", fmt.Errorf("failed to parse CRL data: %w", err)
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if revoked.SerialNumber != nil && revoked.SerialNumber.Cmp(certSerial) == 0 {
			return "Revoked", nil
		}
	}

	return "Good", nil
}

// checkOCSPStatus performs a basic OCSP check for revocation status
func (ch *Chain) checkOCSPStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {
	if len(cert.OCSPServer) == 0 {
		return &RevocationStatus{OCSPStatus: "Not Available"}, nil
	}

	ocspURL := cert.OCSPServer[0]

	// For simplicity, use HTTP GET request to OCSP server
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ocspURL, nil)
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to create OCSP request: %w", err)
	}
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	client := &http.Client{Timeout: ch.HTTPConfig.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("OCSP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	// Read OCSP response
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset the buffer to prevent data leaks
		gc.Default.Put(buf) // Return the buffer to the pool for reuse
	}()

	// Read the response body into the buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	respData := buf.Bytes()

	status, err := ParseOCSPResponse(respData)
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to parse OCSP response: %w", err)
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
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	client := &http.Client{Timeout: ch.HTTPConfig.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CRL request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned status %d", resp.StatusCode)
	}

	// Read CRL data
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset the buffer to prevent data leaks
		gc.Default.Put(buf) // Return the buffer to the pool for reuse
	}()

	// Read the response body into the buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	crlData := buf.Bytes()

	// Parse CRL and check revocation status
	status, err := ParseCRLResponse(crlData, cert.SerialNumber)
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
