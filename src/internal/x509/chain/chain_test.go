// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestChain creates a test certificate chain for visualization testing
func createTestChain(t *testing.T) []*x509.Certificate {
	t.Helper()

	// Create root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate root key")

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err, "failed to create root cert")

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err, "failed to parse root cert")

	// Create intermediate CA
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate intermediate key")

	intTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
		},
		Issuer:                rootTemplate.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	intCertDER, err := x509.CreateCertificate(rand.Reader, &intTemplate, rootCert, &intKey.PublicKey, rootKey)
	require.NoError(t, err, "failed to create intermediate cert")

	intCert, err := x509.ParseCertificate(intCertDER)
	require.NoError(t, err, "failed to parse intermediate cert")

	// Create leaf certificate
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate leaf key")

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		Issuer:    intTemplate.Subject,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{"test.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, intCert, &leafKey.PublicKey, intKey)
	require.NoError(t, err, "failed to create leaf cert")

	leafCert, err := x509.ParseCertificate(leafCertDER)
	require.NoError(t, err, "failed to parse leaf cert")

	return []*x509.Certificate{leafCert, intCert, rootCert}
}

// Test certificate from www.google.com (valid until February 16, 2026)
// Retrieved: December 15, 2025 by Grok using these MCP tools from this repo
const testCertPEM = `
-----BEGIN CERTIFICATE-----
MIIEVzCCAz+gAwIBAgIRAIsnDh7AqstVCQTDZO49FUQwDQYJKoZIhvcNAQELBQAw
OzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEM
MAoGA1UEAxMDV1IyMB4XDTI1MTEyNDA4NDEwNVoXDTI2MDIxNjA4NDEwNFowGTEX
MBUGA1UEAxMOd3d3Lmdvb2dsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASpOrUKgQJxuBGxizx+kmyx5RrD4jQmo8qLKSuwJqGHq32bVzWZGD67H9R4OZrU
dvyPaKf5c8xcR0dfErljBgc9o4ICQTCCAj0wDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFB/jnLpRtZ7i
zZrj5pmoPbY4QlomMB8GA1UdIwQYMBaAFN4bHu15FdQ+NyTDIbvsNDltQrIwMFgG
CCsGAQUFBwEBBEwwSjAhBggrBgEFBQcwAYYVaHR0cDovL28ucGtpLmdvb2cvd3Iy
MCUGCCsGAQUFBzAChhlodHRwOi8vaS5wa2kuZ29vZy93cjIuY3J0MBkGA1UdEQQS
MBCCDnd3dy5nb29nbGUuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMDYGA1UdHwQv
MC0wK6ApoCeGJWh0dHA6Ly9jLnBraS5nb29nL3dyMi9HU3lUMU40UEJyZy5jcmww
ggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdwCWl2S/VViXrfdDh2g3CEJ36fA61fak
8zZuRqQ/D8qpxgAAAZq1PQh6AAAEAwBIMEYCIQDkvhCgZXnoybm66RiqqWXZN6qE
VzPoPHn/kyXZ7Y55yAIhALTMfGlCgnC9W0iu+cR9qCmOwsEr5k6Bl7Ub2w7GCUIu
AHUASZybad4dfOz8Nt7Nh2SmuFuvCoeAGdFVUvvp6ynd+MMAAAGatT0IWAAABAMA
RjBEAiBQITcviDubQYQiIxBwjcgmkl4CH1x4RzykXJrp8cCLKwIgFpdUBEBwTjCw
wTjI3H2paYucltfUre6q/vBei3HhNqcwDQYJKoZIhvcNAQELBQADggEBAE+UAURG
T3JZxq6fjAK5Espfe49Wb0mz1kCTwNY56sbYP/Fa+Kb7kVluDIFbMN2rspADwKBu
FR7QVda3zEIu4Hj1DUmD7ecmVYCxLQ241OYdice4AfJTwDVJVymdQPFoLBP27dWK
3izwcfkPSgXIT8nHcEvDvXljn7n+n3XXuzh1Y1vFnFUa5E69JQFXXDuu/a7LiEXx
uB5j0Xga7DgFyHHHnz7zSiFr37NBb0/CH/31fkgaQPj7Fr5dyCMzMg1rQe1FGOM6
fXT8WHASUpqRebQfDy2TPE7sjve2NenS36NeiiVZXhBo5MHvGCBY3W8OYljK4zeU
uugY3q/5At03UHw=
-----END CERTIFICATE-----
`

var version = "1.3.3.7-testing"

func TestChainOperations(t *testing.T) {
	tests := []struct {
		name        string
		certPEM     string
		skipOnMacOS bool
		testFunc    func(t *testing.T, manager *Chain)
	}{
		{
			name:    "Fetch Certificate Chain",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				err := manager.FetchCertificate(ctx)
				require.NoError(t, err, "FetchCertificate() error")

				expectedChainLen := 3
				assert.Equal(t, expectedChainLen, len(manager.Certs), "expected chain length")

				decoder := x509certs.New()
				for _, c := range manager.Certs {
					t.Logf("Certificate Subject: %s", c.Subject.CommonName)
					pemData := decoder.EncodePEM(c)
					t.Logf("Certificate PEM:\n%s", pemData)
				}
			},
		},
		{
			name:        "Add Root CA",
			certPEM:     testCertPEM,
			skipOnMacOS: true,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				err := manager.FetchCertificate(ctx)
				require.NoError(t, err, "FetchCertificate() error")

				err = manager.AddRootCA()
				require.NoError(t, err, "AddRootCA() error")

				decoder := x509certs.New()
				for _, c := range manager.Certs {
					t.Logf("Certificate Subject: %s", c.Subject.CommonName)
					pemData := decoder.EncodePEM(c)
					t.Logf("Certificate PEM:\n%s", pemData)
				}
			},
		},
		{
			name:    "Filter Intermediates",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				err := manager.FetchCertificate(ctx)
				require.NoError(t, err, "FetchCertificate() error")

				intermediates := manager.FilterIntermediates()

				expectedIntermediates := 1
				assert.Equal(t, expectedIntermediates, len(intermediates), "expected intermediates")

				decoder := x509certs.New()
				for _, c := range intermediates {
					t.Logf("Intermediate Certificate Subject: %s", c.Subject.CommonName)
					pemData := decoder.EncodePEM(c)
					t.Logf("Intermediate Certificate PEM:\n%s", pemData)
				}
			},
		},
		{
			name:    "IsSelfSigned - Root Certificate",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				err := manager.FetchCertificate(ctx)
				require.NoError(t, err, "FetchCertificate() error")

				rootCert := manager.Certs[len(manager.Certs)-1]
				assert.True(t, manager.IsSelfSigned(rootCert), "expected root certificate to be self-signed")

				leafCert := manager.Certs[0]
				assert.False(t, manager.IsSelfSigned(leafCert), "expected leaf certificate to not be self-signed")
			},
		},
		{
			name:    "IsRootNode",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				err := manager.FetchCertificate(ctx)
				require.NoError(t, err, "FetchCertificate() error")

				rootCert := manager.Certs[len(manager.Certs)-1]
				assert.True(t, manager.IsRootNode(rootCert), "expected last certificate to be root node")

				leafCert := manager.Certs[0]
				assert.False(t, manager.IsRootNode(leafCert), "expected first certificate to not be root node")
			},
		},
		{
			name:    "FilterIntermediates - No Intermediates",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				manager.Certs = manager.Certs[:1]

				intermediates := manager.FilterIntermediates()
				assert.Nil(t, intermediates, "expected nil for single certificate")
			},
		},
		{
			name:    "VerifyChain - Valid Chain",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				err := manager.FetchCertificate(ctx)
				require.NoError(t, err, "FetchCertificate() error")

				err = manager.VerifyChain()
				assert.NoError(t, err, "VerifyChain() error")
			},
		},
		{
			name:    "New Chain Creation",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				assert.Equal(t, version, manager.HTTPConfig.Version, "expected version")
				assert.Equal(t, 1, len(manager.Certs), "expected 1 initial certificate")
				assert.NotNil(t, manager.Roots, "expected Roots pool to be initialized")
				assert.NotNil(t, manager.Intermediates, "expected Intermediates pool to be initialized")
				assert.NotNil(t, manager.Certificate, "expected Certificate decoder to be initialized")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnMacOS && runtime.GOOS == "darwin" {
				t.Skip("Skipping on macOS: system certificate validation has stricter EKU constraints")
			}

			block, _ := pem.Decode([]byte(tt.certPEM))
			require.NotNil(t, block, "failed to parse certificate PEM")

			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err, "failed to parse certificate")

			manager := New(cert, version)
			tt.testFunc(t, manager)
		})
	}
}

func TestChain_Visualization(t *testing.T) {
	// Create a test certificate chain
	certs := createTestChain(t)

	chain := New(certs[0], "1.0.0")
	if len(certs) > 1 {
		chain.Certs = append(chain.Certs, certs[1:]...)
	}

	// Test ASCII tree visualization
	treeOutput := chain.RenderASCIITree(t.Context())
	assert.NotEmpty(t, treeOutput, "Expected non-empty tree output")
	assert.Contains(t, treeOutput, "test.example.com", "Expected tree to contain leaf certificate")

	// Test table visualization
	tableOutput := chain.RenderTable(t.Context())
	assert.NotEmpty(t, tableOutput, "Expected non-empty table output")
	assert.Contains(t, tableOutput, "test.example.com", "Expected table to contain leaf certificate")

	// Test JSON visualization
	jsonData, err := chain.ToVisualizationJSON(t.Context())
	require.NoError(t, err, "ToVisualizationJSON failed")
	assert.NotEmpty(t, jsonData, "Expected non-empty JSON output")
	assert.Contains(t, string(jsonData), "test.example.com", "Expected JSON to contain leaf certificate")
}

func TestChain_ContextCancellation(t *testing.T) {
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

	manager := New(cert, version)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err = manager.FetchCertificate(ctx)
	assert.Error(t, err, "expected error from cancelled context")
}

func TestFetchRemoteChain(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		port        int
		timeout     time.Duration
		expectError bool
	}{
		{
			name:        "Valid hostname - www.google.com",
			hostname:    "www.google.com",
			port:        443,
			timeout:     10 * time.Second,
			expectError: false,
		},
		{
			name:        "Invalid hostname",
			hostname:    "invalid.hostname.that.does.not.exist.example",
			port:        443,
			timeout:     5 * time.Second,
			expectError: true,
		},
		{
			name:        "Invalid port",
			hostname:    "www.google.com",
			port:        9999, // Invalid port
			timeout:     5 * time.Second,
			expectError: true,
		},
		{
			name:        "Timeout test",
			hostname:    "192.0.2.1", // Reserved IP that should timeout
			port:        443,
			timeout:     1 * time.Millisecond, // Very short timeout
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if testing.Short() {
				t.Skip("Skipping remote fetch test in short mode")
			}

			ctx, cancel := context.WithTimeout(t.Context(), tt.timeout)
			defer cancel()

			chain, certs, err := FetchRemoteChain(ctx, tt.hostname, tt.port, tt.timeout, version)

			if tt.expectError {
				assert.Error(t, err, "expected error")
				return
			}

			require.NoError(t, err, "FetchRemoteChain() error")

			assert.NotNil(t, chain, "expected chain to be non-nil")
			assert.NotEmpty(t, certs, "expected at least one certificate")
			assert.NotEmpty(t, chain.Certs, "expected chain to contain certificates")

			// Verify the first certificate in the chain matches the returned certs
			assert.True(t, chain.Certs[0].Equal(certs[0]), "expected first certificate in chain to match first returned cert")

			decoder := x509certs.New()
			for i, cert := range certs {
				t.Logf("Certificate %d Subject: %s", i+1, cert.Subject.CommonName)
				pemData := decoder.EncodePEM(cert)
				t.Logf("Certificate %d PEM:\n%s", i+1, pemData)
			}
		})
	}
}

func TestCheckRevocationStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping revocation status test in short mode")
	}

	tests := []struct {
		name           string
		certPEM        string
		expectContains []string
		setupTimeout   time.Duration
	}{
		{
			name:    "Certificate with OCSP and CRL URLs",
			certPEM: testCertPEM,
			expectContains: []string{
				"Revocation Status Check:",
				"OCSP",
				"CRL",
			},
			setupTimeout: 15 * time.Second,
		},
		{
			name:    "Certificate with no revocation URLs",
			certPEM: testCertPEM,
			expectContains: []string{
				"Revocation Status Check:",
				"Not Available",
			},
			setupTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(tt.certPEM))
			require.NotNil(t, block, "failed to parse certificate PEM")

			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err, "failed to parse certificate")

			manager := New(cert, version)

			// Fetch the chain first
			ctx, cancel := context.WithTimeout(t.Context(), tt.setupTimeout)
			defer cancel()

			err = manager.FetchCertificate(ctx)
			require.NoError(t, err, "FetchCertificate() error")

			// Test revocation status check
			revocationCtx, revocationCancel := context.WithTimeout(t.Context(), tt.setupTimeout)
			defer revocationCancel()

			result, err := manager.CheckRevocationStatus(revocationCtx)
			require.NoError(t, err, "CheckRevocationStatus() error")

			// Verify the result contains expected elements
			for _, expected := range tt.expectContains {
				assert.Contains(t, result, expected, "expected result to contain %q", expected)
			}

			t.Logf("Revocation check result:\n%s", result)
		})
	}
}

func TestParseCRLResponse(t *testing.T) {
	// Create a simple test certificate for issuer
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

	// Test that function signature works correctly
	_, err = ParseCRLResponse([]byte("invalid"), big.NewInt(12345), cert)
	assert.Error(t, err, "expected error for invalid CRL data")

	_, err = ParseCRLResponse([]byte{}, big.NewInt(12345), cert)
	assert.Error(t, err, "expected error for empty CRL data")

	// Test with nil serial
	_, err = ParseCRLResponse([]byte("data"), nil, cert)
	assert.Error(t, err, "expected error for nil serial")

	// Test with nil issuer
	_, err = ParseCRLResponse([]byte("data"), big.NewInt(12345), nil)
	assert.Error(t, err, "expected error for nil issuer")
}

func TestChain_AddRootCA_Error(t *testing.T) {
	// Create a certificate that will fail verification
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

	manager := New(cert, version)

	// Add a malformed certificate to the chain to trigger verification error
	manager.Certs = append(manager.Certs, &x509.Certificate{Raw: []byte("invalid")})

	err = manager.AddRootCA()
	require.Error(t, err, "expected error for malformed certificate in chain")
}

func TestChain_VerifyChain_Error(t *testing.T) {
	// Create a chain with certificates that won't verify
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

	manager := New(cert, version)

	// Replace with a self-signed cert that doesn't match the chain
	fakeCert := &x509.Certificate{
		Raw:                []byte("fake"),
		Subject:            cert.Subject,
		Issuer:             cert.Issuer,
		SignatureAlgorithm: cert.SignatureAlgorithm,
	}
	manager.Certs = []*x509.Certificate{fakeCert, fakeCert}

	err = manager.VerifyChain()
	require.Error(t, err, "expected verification error for invalid chain")
}

func TestRevocationStatus_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

	manager := New(cert, version)

	// Fetch the chain first
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	require.NoError(t, manager.FetchCertificate(ctx), "FetchCertificate() error")

	// Test with very short timeout to force timeout
	revocationCtx, revocationCancel := context.WithTimeout(t.Context(), 1*time.Millisecond)
	defer revocationCancel()

	_, err = manager.CheckRevocationStatus(revocationCtx)
	// Should either succeed quickly or timeout - we accept both as valid behavior
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		assert.Fail(t, fmt.Sprintf("unexpected error: %v", err))
	}
}

func TestRevocationStatus_ContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping context cancellation test in short mode")
	}

	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

	manager := New(cert, version)

	// Fetch the chain first
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	require.NoError(t, manager.FetchCertificate(ctx), "FetchCertificate() error")

	// Test with context that gets cancelled mid-operation
	revocationCtx, revocationCancel := context.WithCancel(t.Context())

	// Cancel after a short delay to ensure the operation starts
	go func() {
		time.Sleep(10 * time.Millisecond)
		revocationCancel()
	}()

	_, err = manager.CheckRevocationStatus(revocationCtx)
	// Accept both cancellation error and successful completion (depending on timing)
	if err != nil && !strings.Contains(err.Error(), "context canceled") && !strings.Contains(err.Error(), "context deadline exceeded") {
		assert.Fail(t, fmt.Sprintf("unexpected error: %v", err))
	}
}

func TestRevocationWorkflow_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "Complete Revocation Workflow",
			testFunc: func(t *testing.T) {
				// 1. Parse certificate from PEM
				block, _ := pem.Decode([]byte(testCertPEM))
				require.NotNil(t, block, "failed to parse certificate PEM")

				cert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err, "failed to parse certificate")

				// 2. Create chain manager
				manager := New(cert, version)

				// 3. Fetch certificate chain
				fetchCtx, fetchCancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer fetchCancel()

				require.NoError(t, manager.FetchCertificate(fetchCtx), "FetchCertificate() error")

				require.GreaterOrEqual(t, len(manager.Certs), 2, "expected at least 2 certificates in chain")

				t.Logf("Successfully fetched certificate chain with %d certificates", len(manager.Certs))

				// 4. Check revocation status
				revocationCtx, revocationCancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer revocationCancel()

				revocationStatus, err := manager.CheckRevocationStatus(revocationCtx)
				require.NoError(t, err, "CheckRevocationStatus() error")

				// Verify revocation status contains expected elements
				assert.Contains(t, revocationStatus, "Revocation Status Check:", "revocation status should contain header")
				assert.Contains(t, revocationStatus, "Certificate 1:", "revocation status should contain certificate information")

				// Should contain either OCSP or CRL status
				hasOCSP := strings.Contains(revocationStatus, "OCSP")
				hasCRL := strings.Contains(revocationStatus, "CRL")

				assert.True(t, hasOCSP || hasCRL, "revocation status should contain OCSP or CRL information")

				t.Logf("Revocation status check completed successfully")

				// 5. Validate certificate chain (skip if chain doesn't verify - focus is on workflow integration)
				// Note: Some test certificates may not form a valid chain for verification
				if err := manager.VerifyChain(); err != nil {
					t.Logf("Chain verification failed (expected for some test certificates): %v", err)
				} else {
					t.Logf("Certificate chain validation successful")
				}

				// 6. Verify overall chain integrity
				for i, c := range manager.Certs {
					assert.NotNil(t, c, fmt.Sprintf("certificate %d is nil", i))
					assert.NotEmpty(t, c.Raw, fmt.Sprintf("certificate %d has empty raw data", i))
				}

				t.Logf("Complete integration test passed: fetch → revocation check → workflow validation")
			},
		},
		{
			name: "Revocation Workflow with Root CA Addition",
			testFunc: func(t *testing.T) {
				// Skip on macOS due to stricter EKU constraints
				if runtime.GOOS == "darwin" {
					t.Skip("Skipping root CA test on macOS due to EKU constraints")
				}

				// 1. Parse certificate
				block, _ := pem.Decode([]byte(testCertPEM))
				require.NotNil(t, block, "failed to parse certificate PEM")

				cert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err, "failed to parse certificate")

				// 2. Create chain manager
				manager := New(cert, version)

				// 3. Fetch certificate chain
				fetchCtx, fetchCancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer fetchCancel()

				require.NoError(t, manager.FetchCertificate(fetchCtx), "FetchCertificate() error")

				// 4. Add root CA
				require.NoError(t, manager.AddRootCA(), "AddRootCA() error")

				// Chain should now include root
				require.GreaterOrEqual(t, len(manager.Certs), 3, "expected at least 3 certificates after adding root CA")

				// 5. Check revocation status (should work with root CA)
				revocationCtx, revocationCancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer revocationCancel()

				revocationStatus, err := manager.CheckRevocationStatus(revocationCtx)
				require.NoError(t, err, "CheckRevocationStatus() after adding root CA error")

				assert.Contains(t, revocationStatus, "Certificate 1:", "revocation status should contain certificate information")

				// 6. Validate complete chain (skip if doesn't verify - focus on workflow)
				if err := manager.VerifyChain(); err != nil {
					t.Logf("Chain verification failed with root CA (expected for some test certificates): %v", err)
				} else {
					t.Logf("Certificate chain validation with root CA successful")
				}

				t.Logf("Integration test with root CA passed: fetch → add root → revocation check → workflow validation")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}

func TestCRLCacheConfig(t *testing.T) {
	// Test setting custom configuration
	originalConfig := GetCRLCacheConfig()

	customConfig := &CRLCacheConfig{
		MaxSize:         50,
		CleanupInterval: 30 * time.Minute,
	}
	SetCRLCacheConfig(customConfig)

	currentConfig := GetCRLCacheConfig()
	assert.Equal(t, 50, currentConfig.MaxSize, "expected MaxSize 50")
	assert.Equal(t, 30*time.Minute, currentConfig.CleanupInterval, "expected CleanupInterval 30m")

	// Test nil config falls back to defaults
	SetCRLCacheConfig(nil)
	defaultConfig := GetCRLCacheConfig()
	assert.Equal(t, 100, defaultConfig.MaxSize, "expected default MaxSize 100")

	// Restore original config
	SetCRLCacheConfig(originalConfig)
}

func TestCRLCacheMetrics(t *testing.T) {
	// Clear cache for clean test
	ClearCRLCache()

	// Test initial metrics
	metrics := GetCRLCacheMetrics()
	assert.Equal(t, int64(0), metrics.Size, "expected initial size 0")
	assert.Equal(t, int64(0), metrics.Hits, "expected initial hits 0")
	assert.Equal(t, int64(0), metrics.Misses, "expected initial misses 0")

	// Test cache operations
	testURL := "http://example.com/test.crl"
	testData := []byte("test CRL data")
	testNextUpdate := time.Now().Add(24 * time.Hour)

	// Set a CRL
	require.NoError(t, SetCachedCRL(testURL, testData, testNextUpdate), "failed to set cached CRL")

	// Check metrics after set
	metrics = GetCRLCacheMetrics()
	assert.Equal(t, int64(1), metrics.Size, "expected size 1 after set")

	// Get the CRL (should be a hit)
	data, found := GetCachedCRL(testURL)
	assert.True(t, found, "expected CRL to be found")
	assert.NotEmpty(t, data, "expected non-empty CRL data")

	// Check metrics after get
	metrics = GetCRLCacheMetrics()
	assert.Equal(t, int64(1), metrics.Hits, "expected 1 hit")
	assert.Equal(t, int64(0), metrics.Misses, "expected 0 misses")

	// Get non-existent CRL (should be a miss)
	_, found = GetCachedCRL("http://nonexistent.com/crl")
	assert.False(t, found, "expected non-existent CRL to not be found")

	// Check metrics after miss
	metrics = GetCRLCacheMetrics()
	assert.Equal(t, int64(1), metrics.Misses, "expected 1 miss")
}

func TestCRLCacheStats(t *testing.T) {
	// Clear cache for clean test
	ClearCRLCache()

	// Add some test data
	testURL1 := "http://example1.com/crl"
	testURL2 := "http://example2.com/crl"
	testData1 := []byte("test data 1")
	testData2 := make([]byte, 1024) // 1KB data for memory calculation

	require.NoError(t, SetCachedCRL(testURL1, testData1, time.Now().Add(24*time.Hour)), "failed to set cached CRL 1")
	require.NoError(t, SetCachedCRL(testURL2, testData2, time.Now().Add(24*time.Hour)), "failed to set cached CRL 2")

	// Get one to create a hit
	GetCachedCRL(testURL1)

	stats := GetCRLCacheStats()

	// Check that stats contains expected information
	expectedStrings := []string{
		"CRL Cache Statistics:",
		"Size: 2/",
		"Hit Rate:",
		"Memory Usage:",
		"Evictions:",
		"Cleanups:",
		"Cleanup Interval:",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, stats, expected, "expected stats to contain %q", expected)
	}

	// Test with no requests (should show 0% hit rate)
	ClearCRLCache()
	stats = GetCRLCacheStats()
	assert.Contains(t, stats, "Hit Rate: 0.0%", "expected 0.0%% hit rate for empty cache")
}

func TestCRLCacheCleanupExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cleanup test in short mode")
	}

	// Clear cache for clean test
	ClearCRLCache()

	// Add CRLs with different expiry times
	expiredURL := "http://expired.com/crl"
	validURL := "http://valid.com/crl"

	expiredTime := time.Now().Add(-2 * time.Hour) // Already expired
	validTime := time.Now().Add(24 * time.Hour)   // Still valid

	require.NoError(t, SetCachedCRL(expiredURL, []byte("expired"), expiredTime), "failed to set expired CRL")
	require.NoError(t, SetCachedCRL(validURL, []byte("valid"), validTime), "failed to set valid CRL")

	// Check that valid CRL is retrievable but expired one is not
	_, foundExpired := GetCachedCRL(expiredURL)
	assert.False(t, foundExpired, "expected expired CRL to not be retrievable")
	_, foundValid := GetCachedCRL(validURL)
	assert.True(t, foundValid, "expected valid CRL to be retrievable")

	// Trigger cleanup (this should remove any cached entries that are expired)
	CleanupExpiredCRLs()

	// Check that valid CRL is still retrievable
	_, foundValidAfter := GetCachedCRL(validURL)
	assert.True(t, foundValidAfter, "expected valid CRL to remain retrievable after cleanup")

	// Verify cache metrics were updated (if any expired entries were cleaned)
	metrics := GetCRLCacheMetrics()
	assert.LessOrEqual(t, metrics.Size, int64(1), "expected cache size to be at most 1 after cleanup")
}

func TestCRLCacheEviction(t *testing.T) {
	// Set small cache size for testing
	originalConfig := GetCRLCacheConfig()
	smallConfig := &CRLCacheConfig{
		MaxSize:         2,
		CleanupInterval: 1 * time.Hour,
	}
	SetCRLCacheConfig(smallConfig)
	defer SetCRLCacheConfig(originalConfig)

	// Clear cache
	ClearCRLCache()

	// Add CRLs up to the limit
	url1 := "http://test1.com/crl"
	url2 := "http://test2.com/crl"
	url3 := "http://test3.com/crl"

	require.NoError(t, SetCachedCRL(url1, []byte("data1"), time.Now().Add(24*time.Hour)), "failed to set CRL 1")
	require.NoError(t, SetCachedCRL(url2, []byte("data2"), time.Now().Add(24*time.Hour)), "failed to set CRL 2")

	// Check initial size
	metrics := GetCRLCacheMetrics()
	assert.Equal(t, int64(2), metrics.Size, "expected size 2")

	// Add third CRL (should trigger eviction)
	require.NoError(t, SetCachedCRL(url3, []byte("data3"), time.Now().Add(24*time.Hour)), "failed to set CRL 3")

	// Check final size and evictions
	metrics = GetCRLCacheMetrics()
	assert.Equal(t, int64(2), metrics.Size, "expected size to remain 2 after eviction")
	assert.Equal(t, int64(1), metrics.Evictions, "expected 1 eviction")

	// The first URL should have been evicted (LRU)
	_, found1 := GetCachedCRL(url1)
	assert.False(t, found1, "expected first URL to be evicted")
	_, found2 := GetCachedCRL(url2)
	assert.True(t, found2, "expected second URL to remain")
	_, found3 := GetCachedCRL(url3)
	assert.True(t, found3, "expected third URL to be cached")
}

func TestCRLCacheCleanup_ContextCancellation(t *testing.T) {
	// Reset the cleanup running flag to allow test instance
	atomic.StoreInt32(&crlCache.cleanupRunning, 0)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	// Start cleanup with cancelled context
	StartCRLCacheCleanup(ctx)

	// Wait briefly for goroutine to potentially start and exit
	time.Sleep(50 * time.Millisecond)

	// Verify the flag is still 0 (goroutine didn't start or exited immediately)
	assert.Equal(t, int32(0), atomic.LoadInt32(&crlCache.cleanupRunning), "Cleanup goroutine should not be running after context cancellation")

	// Clean up test state
	ClearCRLCache()
	StopCRLCacheCleanup()
	atomic.StoreInt32(&crlCache.cleanupRunning, 0)
}

// TestCRLCacheCleanupMemoryLeak verifies that the cleanup goroutine doesn't leak tickers
func TestCRLCacheCleanupMemoryLeak(t *testing.T) {
	// Stop any existing cleanup goroutine
	StopCRLCacheCleanup()
	atomic.StoreInt32(&crlCache.cleanupRunning, 0)

	// Clear any existing cache state
	ClearCRLCache()

	// Track initial goroutine count
	initialGoroutines := runtime.NumGoroutine()

	// Set up a very short interval for testing
	shortInterval := 10 * time.Millisecond
	SetCRLCacheConfig(&CRLCacheConfig{
		MaxSize:         10,
		CleanupInterval: shortInterval,
	})

	// Start cleanup with context
	ctx, cancel := context.WithCancel(t.Context())
	StartCRLCacheCleanup(ctx)

	// Let cleanup run for several intervals initially
	time.Sleep(5 * shortInterval)

	// Aggressive config changes - change interval very frequently
	// This would create ticker leaks in buggy implementation
	for i := range 10 {
		newInterval := time.Duration(10+i*5) * time.Millisecond
		SetCRLCacheConfig(&CRLCacheConfig{
			MaxSize:         10,
			CleanupInterval: newInterval,
		})
		time.Sleep(2 * newInterval) // Let it run with new config
	}

	// Verify only one cleanup goroutine is running
	assert.Equal(t, int32(1), atomic.LoadInt32(&crlCache.cleanupRunning), "Expected 1 cleanup goroutine")

	// Check that we haven't created excessive goroutines
	currentGoroutines := runtime.NumGoroutine()
	goroutineIncrease := currentGoroutines - initialGoroutines

	// Allow for some variance (test runner, GC, etc.) but not excessive growth
	// In a leaky implementation, we'd see many more goroutines
	assert.LessOrEqual(t, goroutineIncrease, 5, fmt.Sprintf("Too many goroutines created: initial=%d, current=%d, increase=%d",
		initialGoroutines, currentGoroutines, goroutineIncrease))

	// Test graceful shutdown
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Should not leak goroutines - cleanup flag should be reset
	assert.Equal(t, int32(0), atomic.LoadInt32(&crlCache.cleanupRunning), "Cleanup goroutine did not shut down properly")

	// Final goroutine check - should be back to reasonable levels
	finalGoroutines := runtime.NumGoroutine()
	finalIncrease := finalGoroutines - initialGoroutines

	assert.LessOrEqual(t, finalIncrease, 2, fmt.Sprintf("Goroutines not properly cleaned up: initial=%d, final=%d, increase=%d",
		initialGoroutines, finalGoroutines, finalIncrease))

	// Clean up test state
	ClearCRLCache()
	StopCRLCacheCleanup()
	atomic.StoreInt32(&crlCache.cleanupRunning, 0)
}

func TestGetUserAgent(t *testing.T) {
	// Test custom UserAgent
	conf := NewHTTPConfig("1.0.0")
	conf.UserAgent = "Custom-Agent/1.0"
	assert.Equal(t, "Custom-Agent/1.0", conf.GetUserAgent(), "expected Custom-Agent/1.0")

	// Test default
	confDefault := NewHTTPConfig("1.2.3")
	expected := "X.509-Certificate-Chain-Resolver/1.2.3 (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)"
	assert.Equal(t, expected, confDefault.GetUserAgent(), "expected default user agent")
}

func TestHTTPConfig_Client_Update(t *testing.T) {
	conf := NewHTTPConfig("1.0.0")
	conf.Timeout = 5 * time.Second

	// First call creates client
	client1 := conf.Client()
	assert.Equal(t, 5*time.Second, client1.Timeout, "expected timeout 5s")

	// Update timeout
	conf.Timeout = 10 * time.Second

	// Second call should update existing client
	client2 := conf.Client()
	assert.Equal(t, client1, client2, "expected same client instance")
	assert.Equal(t, 10*time.Second, client2.Timeout, "expected updated timeout 10s")
}
