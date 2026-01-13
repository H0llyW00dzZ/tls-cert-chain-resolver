// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleAnalyzeCertificateWithAI_Resilience(t *testing.T) {
	// Generate a self-signed certificate with unreachable AIA and CRL URLs
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate private key")

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Resilience Cert",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IssuingCertificateURL: []string{"http://192.0.2.1/unreachable-ca.crt"}, // Test-Net-1 (reserved, unreachable)
		CRLDistributionPoints: []string{"http://192.0.2.1/unreachable.crl"},    // Test-Net-1
		OCSPServer:            []string{"http://192.0.2.1/ocsp"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err, "failed to create certificate")

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Create request
	// Base64 encode the PEM data to simulate passing certificate content directly
	certBase64 := base64.StdEncoding.EncodeToString(certPEM)
	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "analyze_certificate_with_ai",
			Arguments: map[string]any{
				"certificate": certBase64,
			},
		},
	}

	// Config with very short timeout to fail fast
	config := &Config{}
	config.Defaults.Timeout = 1
	config.AI.APIKey = ""

	ctx := context.Background()

	// Execute
	result, err := handleAnalyzeCertificateWithAI(ctx, req, config)
	require.NoError(t, err, "handleAnalyzeCertificateWithAI should not return error")

	// Verify result
	require.Len(t, result.Content, 1, "should have one content item")
	content, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected text content result")

	// Check if it processed successfully despite errors
	assert.Contains(t, content.Text, "Test Resilience Cert", "result should contain certificate subject")

	// Check if revocation failure was noted in the context OR if revocation section is present
	// The context is included in the result when no API key is present
	assert.Contains(t, content.Text, "Revocation Status Check", "expected revocation status section in context")

	// Check if AI fallback message is present
	assert.Contains(t, content.Text, "No AI API key", "expected no API key warning")
}

func TestHandleAnalyzeCertificateWithAI_Sampling(t *testing.T) {
	// This test focuses on the SamplingHandler logic coverage by mocking the flow
	// But since we can't easily mock the AI API endpoint without starting a server,
	// we'll trust the existing tests for sampling handler structure.
	// However, we can test the "sampling fails" path if we provide an invalid endpoint?
	// Or if we provide a valid config but the call fails.

	// Let's verify if we can hit lines 715-718 (sampling failed).

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate private key")

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err, "failed to create certificate")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certBase64 := base64.StdEncoding.EncodeToString(certPEM)

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "analyze_certificate_with_ai",
			Arguments: map[string]any{
				"certificate": certBase64,
			},
		},
	}

	// Config with unreachable endpoint
	config := &Config{}
	config.Defaults.Timeout = 10
	config.AI.APIKey = "test-key"
	config.AI.Endpoint = "http://192.0.2.1:12345" // Unreachable
	config.AI.Timeout = 1

	ctx := context.Background()
	result, err := handleAnalyzeCertificateWithAI(ctx, req, config)

	// It should NOT return error, but return a ToolResult with the error message
	require.NoError(t, err, "handleAnalyzeCertificateWithAI should not return error on API failure")

	require.Len(t, result.Content, 1, "should have one content item")
	content, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected text content")

	assert.Contains(t, content.Text, "AI Analysis Request Failed", "expected failure message")
}
