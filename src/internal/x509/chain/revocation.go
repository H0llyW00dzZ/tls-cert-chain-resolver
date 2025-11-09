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
	"golang.org/x/crypto/ocsp"
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
func ParseCRLResponse(crlData []byte, certSerial *big.Int, issuer *x509.Certificate) (string, error) {
	if len(crlData) == 0 {
		return "Unknown", fmt.Errorf("empty CRL data")
	}

	if certSerial == nil {
		return "Unknown", fmt.Errorf("certificate serial number is nil")
	}

	if issuer == nil {
		return "Unknown", fmt.Errorf("issuer certificate is nil")
	}

	var lastErr error
	data := crlData

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if strings.Contains(block.Type, "CRL") {
			status, err := parseCRLBlock(block.Bytes, certSerial, issuer)
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

	status, err := parseCRLBlock(crlData, certSerial, issuer)
	if err == nil {
		return status, nil
	}

	if lastErr != nil {
		return "Unknown", lastErr
	}

	return "Unknown", err
}

func parseCRLBlock(der []byte, certSerial *big.Int, issuer *x509.Certificate) (string, error) {
	crl, err := x509.ParseCRL(der)
	if err != nil {
		return "Unknown", fmt.Errorf("failed to parse CRL data: %w", err)
	}

	if err := issuer.CheckCRLSignature(crl); err != nil {
		return "Unknown", fmt.Errorf("invalid CRL signature: %w", err)
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if revoked.SerialNumber != nil && revoked.SerialNumber.Cmp(certSerial) == 0 {
			return "Revoked", nil
		}
	}

	return "Good", nil
}

// checkOCSPStatus performs OCSP check for revocation status
func (ch *Chain) checkOCSPStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {
	if len(cert.OCSPServer) == 0 {
		return &RevocationStatus{OCSPStatus: "Not Available"}, nil
	}

	ocspURL := cert.OCSPServer[0]

	// Find the issuer certificate
	issuer := ch.findIssuerForCertificate(cert)
	if issuer == nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("could not find issuer certificate for OCSP request")
	}

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Create HTTP POST request with OCSP data
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to create OCSP HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	resp, err := ch.HTTPConfig.Client().Do(req)
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

	ocspRespData := buf.Bytes()

	// Parse OCSP response
	ocspResp, err := ocsp.ParseResponseForCert(ocspRespData, cert, issuer)
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	// Convert OCSP status to our format
	var status string
	switch ocspResp.Status {
	case ocsp.Good:
		status = "Good"
	case ocsp.Revoked:
		status = "Revoked"
	case ocsp.Unknown:
		status = "Unknown"
	default:
		status = "Unknown"
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
		return &RevocationStatus{CRLStatus: "Unknown"}, fmt.Errorf("failed to create CRL request: %w", err)
	}
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	resp, err := ch.HTTPConfig.Client().Do(req)
	if err != nil {
		return &RevocationStatus{CRLStatus: "Unknown"}, fmt.Errorf("CRL request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &RevocationStatus{CRLStatus: "Unknown"}, fmt.Errorf("CRL server returned status %d", resp.StatusCode)
	}

	// Read CRL data
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset the buffer to prevent data leaks
		gc.Default.Put(buf) // Return the buffer to the pool for reuse
	}()

	// Read the response body into the buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return &RevocationStatus{CRLStatus: "Unknown"}, fmt.Errorf("failed to read CRL: %w", err)
	}

	crlData := buf.Bytes()

	// Parse CRL and check revocation status
	issuer := ch.findIssuerForCertificate(cert)
	if issuer == nil {
		// For CRL verification, try all certificates in chain as potential signers
		var lastErr error
		for _, potentialIssuer := range ch.Certs {
			if potentialIssuer == cert {
				continue
			}
			status, err := ParseCRLResponse(crlData, cert.SerialNumber, potentialIssuer)
			if err == nil {
				return &RevocationStatus{
					CRLStatus:    status,
					SerialNumber: cert.SerialNumber.String(),
				}, nil
			}
			lastErr = err
		}
		// If all failed, try parsing without signature verification as fallback
		// This is less secure but better than completely failing
		crl, err := x509.ParseCRL(crlData)
		if err == nil {
			for _, revoked := range crl.TBSCertList.RevokedCertificates {
				if revoked.SerialNumber != nil && revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return &RevocationStatus{
						CRLStatus:    "Revoked (unverified)",
						SerialNumber: cert.SerialNumber.String(),
					}, nil
				}
			}
			return &RevocationStatus{
				CRLStatus:    "Good (unverified)",
				SerialNumber: cert.SerialNumber.String(),
			}, nil
		}
		return &RevocationStatus{CRLStatus: "Unknown"}, fmt.Errorf("could not verify CRL signature or parse CRL: %w", lastErr)
	}

	status, err := ParseCRLResponse(crlData, cert.SerialNumber, issuer)
	if err != nil {
		return &RevocationStatus{CRLStatus: "Unknown"}, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return &RevocationStatus{
		CRLStatus:    status,
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// findIssuerForCertificate finds the certificate that issued the given cert in the chain
func (ch *Chain) findIssuerForCertificate(cert *x509.Certificate) *x509.Certificate {
	// For each certificate in the chain (starting from intermediates up)
	for i := len(ch.Certs) - 1; i >= 0; i-- {
		potentialIssuer := ch.Certs[i]
		// Skip self
		if potentialIssuer == cert {
			continue
		}
		// Check if this cert could have issued our cert
		if err := cert.CheckSignatureFrom(potentialIssuer); err == nil {
			return potentialIssuer
		}
	}
	return nil
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
