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

// RevocationStatus represents the revocation status of a certificate.
//
// It contains the results from both OCSP and CRL revocation checking,
// providing a consolidated view of the certificate's revocation state.
//
// Fields:
//   - OCSPStatus: Status from OCSP check ("Good", "Revoked", "Unknown")
//   - CRLStatus: Status from CRL check ("Good", "Revoked", "Unknown")
//   - SerialNumber: Certificate serial number as a string
type RevocationStatus struct {
	// OCSPStatus: Status from OCSP check with certificate serial for identification
	OCSPStatus string
	// CRLStatus: Status from CRL check with certificate serial for identification
	CRLStatus string
	// SerialNumber: Certificate serial number as a string for correlation
	SerialNumber string
}

// ParseCRLResponse parses a CRL response to extract status for a specific certificate.
//
// It iterates through the PEM blocks in the provided data, finding the first valid
// CRL block that is correctly signed by the issuer. It then checks if the target
// certificate's serial number is listed in the revoked entries.
//
// Parameters:
//   - crlData: Raw CRL data (PEM or DER)
//   - certSerial: Serial number of certificate to check
//   - issuer: Issuer certificate for signature verification
//
// Returns:
//   - string: Status ("Good", "Revoked", or "Unknown")
//   - error: Error if parsing or verification fails
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

// parseCRLBlock parses a single DER-encoded CRL block and checks revocation status.
//
// Parameters:
//   - der: DER encoded CRL
//   - certSerial: Target certificate serial number
//   - issuer: Issuer certificate
//
// Returns:
//   - string: Status ("Good" or "Revoked")
//   - error: Error if parsing or signature verification fails
func parseCRLBlock(der []byte, certSerial *big.Int, issuer *x509.Certificate) (string, error) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return "Unknown", fmt.Errorf("failed to parse CRL data: %w", err)
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return "Unknown", fmt.Errorf("invalid CRL signature: %w", err)
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber != nil && revoked.SerialNumber.Cmp(certSerial) == 0 {
			return "Revoked", nil
		}
	}

	return "Good", nil
}

// checkOCSPStatus performs OCSP check for revocation status, trying all available OCSP servers.
//
// It iterates through the OCSP servers listed in the certificate's AIA extension.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - cert: Certificate to check
//
// Returns:
//   - *RevocationStatus: Result of the check
//   - error: Error if all servers fail or issuer not found
func (ch *Chain) checkOCSPStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {
	if len(cert.OCSPServer) == 0 {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Not Available (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, nil
	}

	// Find the issuer certificate
	issuer := ch.findIssuerForCertificate(cert)
	if issuer == nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("could not find issuer certificate for OCSP request")
	}

	// Try all OCSP servers until one succeeds
	var lastErr error
	var failedServers []string
	for _, ocspURL := range cert.OCSPServer {
		status, err := ch.tryOCSPServer(ctx, cert, issuer, ocspURL)
		if err == nil {
			return status, nil
		}
		failedServers = append(failedServers, ocspURL)
		lastErr = err
	}

	// All OCSP servers failed
	return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("all OCSP servers failed for certificate serial %s (failed servers: %s): %w", cert.SerialNumber.String(), strings.Join(failedServers, ", "), lastErr)
}

// tryOCSPServer attempts OCSP check against a specific OCSP server.
//
// It sends an OCSP request and parses the response.
//
// Parameters:
//   - ctx: Context for request
//   - cert: Certificate to check
//   - issuer: Issuer certificate
//   - ocspURL: URL of OCSP responder
//
// Returns:
//   - *RevocationStatus: Result of the check
//   - error: Error if request fails or response is invalid
func (ch *Chain) tryOCSPServer(ctx context.Context, cert, issuer *x509.Certificate, ocspURL string) (*RevocationStatus, error) {
	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Create HTTP POST request with OCSP data
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to create OCSP HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	resp, err := ch.HTTPConfig.Client().Do(req)
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("OCSP request to %s failed: %w", ocspURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("OCSP server %s returned HTTP %d", ocspURL, resp.StatusCode)
	}

	// Read OCSP response
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset the buffer to prevent data leaks
		gc.Default.Put(buf) // Return the buffer to the pool for reuse
	}()

	// Read the response body into the buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspRespData := buf.Bytes()

	// Parse OCSP response
	ocspResp, err := ocsp.ParseResponseForCert(ocspRespData, cert, issuer)
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to parse OCSP response from %s: %w", ocspURL, err)
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
		OCSPStatus:   fmt.Sprintf("%s (Serial: %s)", status, cert.SerialNumber.String()),
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// checkCRLStatus performs a CRL check for revocation status, trying all available distribution points.
//
// It iterates through the CRL Distribution Points extension URLs.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - cert: Certificate to check
//
// Returns:
//   - *RevocationStatus: Result of the check
//   - error: Error if all points fail
func (ch *Chain) checkCRLStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {

	if len(cert.CRLDistributionPoints) == 0 {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Not Available (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, nil
	}

	// Try all CRL distribution points until one succeeds
	var lastErr error
	var failedPoints []string
	for _, crlURL := range cert.CRLDistributionPoints {
		status, err := ch.tryCRLDistributionPoint(ctx, cert, crlURL)
		if err == nil {
			return status, nil
		}
		failedPoints = append(failedPoints, crlURL)
		lastErr = err
	}

	// All CRL distribution points failed
	return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("all CRL distribution points failed for certificate serial %s (failed points: %s): %w", cert.SerialNumber.String(), strings.Join(failedPoints, ", "), lastErr)
}

// tryCRLDistributionPoint attempts CRL check against a specific distribution point with caching.
//
// It first checks the internal CRL cache. If missing or expired, it fetches the
// CRL from the network and caches it if valid.
//
// Parameters:
//   - ctx: Context for request
//   - cert: Certificate to check
//   - crlURL: URL of CRL distribution point
//
// Returns:
//   - *RevocationStatus: Result of the check
//   - error: Error if fetch fails or CRL cannot be verified
func (ch *Chain) tryCRLDistributionPoint(ctx context.Context, cert *x509.Certificate, crlURL string) (*RevocationStatus, error) {
	// Check cache first
	if cachedData, found := GetCachedCRL(crlURL); found {
		// Use cached CRL data
		return ch.processCRLData(cachedData, cert)
	}

	// Fetch CRL from network
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to create CRL request: %w", err)
	}
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	resp, err := ch.HTTPConfig.Client().Do(req)
	if err != nil {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("CRL request to %s failed: %w", crlURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("CRL server %s returned HTTP %d", crlURL, resp.StatusCode)
	}

	// Read CRL data
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset the buffer to prevent data leaks
		gc.Default.Put(buf) // Return the buffer to the pool for reuse
	}()

	// Read the response body into the buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to read CRL: %w", err)
	}

	crlData := buf.Bytes()

	// Parse CRL to extract NextUpdate for caching
	crl, parseErr := x509.ParseRevocationList(crlData)
	if parseErr == nil && !crl.NextUpdate.IsZero() {
		// Cache the CRL with its next update time
		if err := SetCachedCRL(crlURL, crlData, crl.NextUpdate); err != nil {
			// Log error but don't fail the operation
			// The CRL is still valid for this request
		}
	}

	// Process the CRL data
	return ch.processCRLData(crlData, cert)
}

// processCRLData processes CRL data and checks revocation status.
//
// It attempts to verify the CRL signature using the likely issuer (found in chain)
// or by trying all certificates in the chain as potential signers.
//
// Parameters:
//   - crlData: Raw CRL data
//   - cert: Certificate to check
//
// Returns:
//   - *RevocationStatus: Result of the check
//   - error: Error if signature verification fails
func (ch *Chain) processCRLData(crlData []byte, cert *x509.Certificate) (*RevocationStatus, error) {
	// Try to find issuer certificate for CRL signature verification
	issuer := ch.findIssuerForCertificate(cert)
	if issuer != nil {
		// Try verified CRL parsing first
		status, err := ParseCRLResponse(crlData, cert.SerialNumber, issuer)
		if err == nil {
			return &RevocationStatus{
				CRLStatus:    fmt.Sprintf("%s (Serial: %s)", status, cert.SerialNumber.String()),
				SerialNumber: cert.SerialNumber.String(),
			}, nil
		}
		// If verified parsing fails, continue to try other potential issuers
	}

	// Try all certificates in chain as potential CRL signers
	for _, potentialIssuer := range ch.Certs {
		if potentialIssuer == cert {
			continue // Skip self
		}
		status, err := ParseCRLResponse(crlData, cert.SerialNumber, potentialIssuer)
		if err == nil {
			return &RevocationStatus{
				CRLStatus:    fmt.Sprintf("%s (Serial: %s)", status, cert.SerialNumber.String()),
				SerialNumber: cert.SerialNumber.String(),
			}, nil
		}
	}

	// If all signature verification attempts fail, we cannot trust this CRL
	return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("CRL signature verification failed for certificate serial %s (tried all certificates in chain as potential issuers)", cert.SerialNumber.String())
}

// CheckRevocationStatus performs OCSP/CRL checks for the certificate chain with priority logic.
//
// It iterates through the certificate chain (excluding root) and checks revocation
// status for each certificate.
//
// Priority Logic:
//  1. Check OCSP first (real-time status)
//  2. If OCSP unavailable/unknown, check CRL (with caching)
//
// Returns:
//   - string: Formatted report of revocation status
//   - error: Always nil (errors are included in the report)
func (ch *Chain) CheckRevocationStatus(ctx context.Context) (string, error) {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	var result strings.Builder
	result.WriteString("Revocation Status Check:\n\n")

	for i, cert := range ch.Certs {
		// Skip ultimate trust anchor; roots aren't revoked via OCSP/CRL
		if i == len(ch.Certs)-1 {
			continue
		}

		result.WriteString(fmt.Sprintf("Certificate %d: %s\n", i+1, cert.Subject.CommonName))

		// Check OCSP first (higher priority)
		ocspStatus, ocspErr := ch.checkOCSPStatus(ctx, cert)
		if ocspErr != nil {
			result.WriteString(fmt.Sprintf("  OCSP Error: %v\n", ocspErr))
		} else {
			result.WriteString(fmt.Sprintf("  OCSP Status: %s\n", ocspStatus.OCSPStatus))

			// If OCSP says revoked, certificate is revoked - no need to check CRL
			if strings.Contains(ocspStatus.OCSPStatus, "Revoked") {
				result.WriteString("  Final Status: REVOKED (via OCSP)\n\n")
				continue
			}

			// If OCSP says good, certificate is good - CRL check not needed
			if strings.Contains(ocspStatus.OCSPStatus, "Good") {
				result.WriteString("  Final Status: Good (via OCSP)\n\n")
				continue
			}
		}

		// OCSP is unavailable or unknown, check CRL
		crlStatus, crlErr := ch.checkCRLStatus(ctx, cert)
		if crlErr != nil {
			result.WriteString(fmt.Sprintf("  CRL Error: %v\n", crlErr))
			result.WriteString("  Final Status: Unknown (both OCSP and CRL unavailable)\n")
		} else {
			result.WriteString(fmt.Sprintf("  CRL Status: %s\n", crlStatus.CRLStatus))
			if strings.Contains(crlStatus.CRLStatus, "Revoked") {
				result.WriteString("  Final Status: Revoked (via CRL)\n")
			} else if strings.Contains(crlStatus.CRLStatus, "Good") {
				result.WriteString("  Final Status: Good (via CRL)\n")
			} else {
				result.WriteString("  Final Status: Unknown\n")
			}
		}

		result.WriteString("\n")
	}

	return result.String(), nil
}
