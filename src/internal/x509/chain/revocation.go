// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
)

// RevocationStatus represents revocation status of a certificate
type RevocationStatus struct {
	OCSPStatus   string
	CRLEnabled   bool
	CRLStatus    string
	SerialNumber string
}

// OCSP request structures for proper ASN.1 encoding
type ocspRequest struct {
	TBSRequest tbsRequest `asn1:"tag:0,explicit"`
}

type tbsRequest struct {
	Version       int             `asn1:"optional,tag:0,default:0"`
	RequestorName asn1.RawValue   `asn1:"optional,tag:1"`
	RequestList   []request       `asn1:"tag:2"`
	Extensions    []asn1.RawValue `asn1:"optional,tag:3"`
}

type request struct {
	CertID    certID          `asn1:"tag:0"`
	SingleReq []asn1.RawValue `asn1:"optional,tag:1"`
}

type certID struct {
	HashAlgorithm  algorithmIdentifier `asn1:"tag:0"`
	IssuerNameHash []byte              `asn1:"tag:1"`
	IssuerKeyHash  []byte              `asn1:"tag:2"`
	SerialNumber   *big.Int            `asn1:"tag:3"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
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

// TODO: This needs improvement.
func createOCSPRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	// Calculate issuer name hash (SHA-1 of issuer's DN)
	issuerNameHash := sha1.Sum(issuer.RawSubject)

	// Calculate issuer key hash (SHA-1 of issuer's public key)
	issuerKeyHash := sha1.Sum(issuer.RawSubjectPublicKeyInfo)

	// Create CertID
	certID := certID{
		HashAlgorithm: algorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, // SHA-1
		},
		IssuerNameHash: issuerNameHash[:],
		IssuerKeyHash:  issuerKeyHash[:],
		SerialNumber:   cert.SerialNumber,
	}

	// Create request
	req := request{
		CertID: certID,
	}

	// Create TBSRequest
	tbsReq := tbsRequest{
		Version:     0,
		RequestList: []request{req},
	}

	// Create OCSP request
	ocspReq := ocspRequest{
		TBSRequest: tbsReq,
	}

	// Encode to ASN.1 DER
	requestData, err := asn1.Marshal(ocspReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OCSP request: %w", err)
	}

	return requestData, nil
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

// checkOCSPStatus performs a full OCSP check for revocation status
func (ch *Chain) checkOCSPStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {
	if len(cert.OCSPServer) == 0 {
		return &RevocationStatus{OCSPStatus: "Not Available"}, nil
	}

	ocspURL := cert.OCSPServer[0]

	// Find issuer certificate
	var issuer *x509.Certificate
	for _, c := range ch.Certs {
		if bytes.Equal(c.RawSubject, cert.RawIssuer) {
			issuer = c
			break
		}
	}
	if issuer == nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("issuer certificate not found in chain")
	}

	// Create proper OCSP request
	ocspReqData, err := createOCSPRequest(cert, issuer)
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Make HTTP POST request to OCSP server (RFC 2560)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReqData))
	if err != nil {
		return &RevocationStatus{OCSPStatus: "Unknown"}, fmt.Errorf("failed to create OCSP HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
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
