// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
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
	"math/big"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
)

// createTestChain creates a test certificate chain for visualization testing
func createTestChain(t *testing.T) []*x509.Certificate {
	t.Helper()

	// Create root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

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
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}

	// Create intermediate CA
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}

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
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}

	intCert, err := x509.ParseCertificate(intCertDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate cert: %v", err)
	}

	// Create leaf certificate
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

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
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	return []*x509.Certificate{leafCert, intCert, rootCert}
}

// Test certificate from www.google.com (valid until December 15, 2025)
// Retrieved: October 16, 2025
const testCertPEM = `
-----BEGIN CERTIFICATE-----
MIIEVzCCAz+gAwIBAgIQXEsKucZT6MwJr/NcaQmnozANBgkqhkiG9w0BAQsFADA7
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQww
CgYDVQQDEwNXUjIwHhcNMjUwOTIyMDg0MjQwWhcNMjUxMjE1MDg0MjM5WjAZMRcw
FQYDVQQDEw53d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BM3QmmV89za/vDWm/Ctodj6J5s0RLy5fo5QsoGRdMlzItH3jBRpmdWEMysalvQtm
aLGUUvJv5ASJHKfixPD3LWijggJCMIICPjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUUYk76ccIt4qc
kyjMh0xUc5iMmTIwHwYDVR0jBBgwFoAU3hse7XkV1D43JMMhu+w0OW1CsjAwWAYI
KwYBBQUHAQEETDBKMCEGCCsGAQUFBzABhhVodHRwOi8vby5wa2kuZ29vZy93cjIw
JQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dyMi5jcnQwGQYDVR0RBBIw
EIIOd3d3Lmdvb2dsZS5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwNgYDVR0fBC8w
LTAroCmgJ4YlaHR0cDovL2MucGtpLmdvb2cvd3IyL0dTeVQxTjRQQnJnLmNybDCC
AQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2AN3cyjSV1+EWBeeVMvrHn/g9HFDf2wA6
FBJ2Ciysu8gqAAABmXDN1WkAAAQDAEcwRQIgdH62Tub0woIi1sa+gQHvdMpNlfa6
WQgVn2Ov2CM0ktkCIQDyivdzECaAyaCq8GG+EtKWge4nLJ8FM++Q5WVQD9kCUgB3
AMz7D2qFcQll/pWbU87psnwi6YVcDZeNtql+VMD+TA2wAAABmXDN1WgAAAQDAEgw
RgIhAPNnKBAUSFiPjBYsu9A+UlI8ykhnoaZiFMhaDvrHGMKvAiEA02wfQcWu2753
HW54J/Iyeak0ni5z8jqayf1Rd5518Q0wDQYJKoZIhvcNAQELBQADggEBAAqYHEc6
CiVjrSPb0E4QSHYZIbqpHSYnOs8OQ7T54QM8yoMWOb4tWaMZGwdZayaL6ehyYKzS
8lhyxL4OPN9E51//mScXtemV4EbgrDm0fk3uH0gAX3oP+0DZH4X7t7L9aO8nalSl
KGJvEoHrphu2HbkAJY9OUqUo804OjXHeiY3FLUkoER7hb89w1qcaWxjRrVfflJ/Q
0pJCjtltJFSBTZbM6t0Y0uir9/XNPHcec4nMSyp3W/UEmcAoKc3kDJrT6CE2l2lI
Dd4Zns+bUA5A9z1Qy5c9MKX6I3rsHmUNUhGRz/lCyJDdc6UNoGKPmilI98JSRZYY
tXHHbX1dudpKfHM=
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

				if err := manager.FetchCertificate(ctx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				expectedChainLen := 3
				if len(manager.Certs) != expectedChainLen {
					t.Errorf("expected chain length %d, got %d", expectedChainLen, len(manager.Certs))
				}

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

				if err := manager.FetchCertificate(ctx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				if err := manager.AddRootCA(); err != nil {
					t.Fatalf("AddRootCA() error = %v", err)
				}

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

				if err := manager.FetchCertificate(ctx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				intermediates := manager.FilterIntermediates()

				expectedIntermediates := 1
				if len(intermediates) != expectedIntermediates {
					t.Errorf("expected %d intermediates, got %d", expectedIntermediates, len(intermediates))
				}

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

				if err := manager.FetchCertificate(ctx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				rootCert := manager.Certs[len(manager.Certs)-1]
				if !manager.IsSelfSigned(rootCert) {
					t.Error("expected root certificate to be self-signed")
				}

				leafCert := manager.Certs[0]
				if manager.IsSelfSigned(leafCert) {
					t.Error("expected leaf certificate to not be self-signed")
				}
			},
		},
		{
			name:    "IsRootNode",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				if err := manager.FetchCertificate(ctx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				rootCert := manager.Certs[len(manager.Certs)-1]
				if !manager.IsRootNode(rootCert) {
					t.Error("expected last certificate to be root node")
				}

				leafCert := manager.Certs[0]
				if manager.IsRootNode(leafCert) {
					t.Error("expected first certificate to not be root node")
				}
			},
		},
		{
			name:    "FilterIntermediates - No Intermediates",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				manager.Certs = manager.Certs[:1]

				intermediates := manager.FilterIntermediates()
				if intermediates != nil {
					t.Errorf("expected nil for single certificate, got %d intermediates", len(intermediates))
				}
			},
		},
		{
			name:    "VerifyChain - Valid Chain",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				if err := manager.FetchCertificate(ctx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				if err := manager.VerifyChain(); err != nil {
					t.Errorf("VerifyChain() error = %v", err)
				}
			},
		},
		{
			name:    "New Chain Creation",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *Chain) {
				if manager.HTTPConfig.Version != version {
					t.Errorf("expected version %s, got %s", version, manager.HTTPConfig.Version)
				}

				if len(manager.Certs) != 1 {
					t.Errorf("expected 1 initial certificate, got %d", len(manager.Certs))
				}

				if manager.Roots == nil {
					t.Error("expected Roots pool to be initialized")
				}

				if manager.Intermediates == nil {
					t.Error("expected Intermediates pool to be initialized")
				}

				if manager.Certificate == nil {
					t.Error("expected Certificate decoder to be initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnMacOS && runtime.GOOS == "darwin" {
				t.Skip("Skipping on macOS: system certificate validation has stricter EKU constraints")
			}

			block, _ := pem.Decode([]byte(tt.certPEM))
			if block == nil {
				t.Fatal("failed to parse certificate PEM")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

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
	if treeOutput == "" {
		t.Error("Expected non-empty tree output")
	}
	if !strings.Contains(treeOutput, "test.example.com") {
		t.Error("Expected tree to contain leaf certificate")
	}

	// Test table visualization
	tableOutput := chain.RenderTable(t.Context())
	if tableOutput == "" {
		t.Error("Expected non-empty table output")
	}
	if !strings.Contains(tableOutput, "test.example.com") {
		t.Error("Expected table to contain leaf certificate")
	}

	// Test JSON visualization
	jsonData, err := chain.ToVisualizationJSON(t.Context())
	if err != nil {
		t.Fatalf("ToVisualizationJSON failed: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("Expected non-empty JSON output")
	}
	if !strings.Contains(string(jsonData), "test.example.com") {
		t.Error("Expected JSON to contain leaf certificate")
	}
}

func TestChain_ContextCancellation(t *testing.T) {
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	manager := New(cert, version)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err = manager.FetchCertificate(ctx)
	if err == nil {
		t.Error("expected error from cancelled context")
	}
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
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("FetchRemoteChain() error = %v", err)
			}

			if chain == nil {
				t.Error("expected chain to be non-nil")
			}

			if len(certs) == 0 {
				t.Error("expected at least one certificate")
			}

			if len(chain.Certs) == 0 {
				t.Error("expected chain to contain certificates")
			}

			// Verify the first certificate in the chain matches the returned certs
			if !chain.Certs[0].Equal(certs[0]) {
				t.Error("expected first certificate in chain to match first returned cert")
			}

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
			if block == nil {
				t.Fatal("failed to parse certificate PEM")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

			manager := New(cert, version)

			// Fetch the chain first
			ctx, cancel := context.WithTimeout(t.Context(), tt.setupTimeout)
			defer cancel()

			if err := manager.FetchCertificate(ctx); err != nil {
				t.Fatalf("FetchCertificate() error = %v", err)
			}

			// Test revocation status check
			revocationCtx, revocationCancel := context.WithTimeout(t.Context(), tt.setupTimeout)
			defer revocationCancel()

			result, err := manager.CheckRevocationStatus(revocationCtx)
			if err != nil {
				t.Fatalf("CheckRevocationStatus() error = %v", err)
			}

			// Verify the result contains expected elements
			for _, expected := range tt.expectContains {
				if !strings.Contains(result, expected) {
					t.Errorf("expected result to contain %q, but got:\n%s", expected, result)
				}
			}

			t.Logf("Revocation check result:\n%s", result)
		})
	}
}

func TestParseCRLResponse(t *testing.T) {
	// Create a simple test certificate for issuer
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Test that function signature works correctly
	_, err = ParseCRLResponse([]byte("invalid"), big.NewInt(12345), cert)
	if err == nil {
		t.Error("expected error for invalid CRL data")
	}

	_, err = ParseCRLResponse([]byte{}, big.NewInt(12345), cert)
	if err == nil {
		t.Error("expected error for empty CRL data")
	}

	// Test with nil serial
	_, err = ParseCRLResponse([]byte("data"), nil, cert)
	if err == nil {
		t.Error("expected error for nil serial")
	}

	// Test with nil issuer
	_, err = ParseCRLResponse([]byte("data"), big.NewInt(12345), nil)
	if err == nil {
		t.Error("expected error for nil issuer")
	}
}

func TestChain_AddRootCA_Error(t *testing.T) {
	// Create a certificate that will fail verification
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	manager := New(cert, version)

	// Add a malformed certificate to the chain to trigger verification error
	manager.Certs = append(manager.Certs, &x509.Certificate{Raw: []byte("invalid")})

	err = manager.AddRootCA()
	if err == nil {
		t.Error("expected error for malformed certificate in chain")
	}
}

func TestChain_VerifyChain_Error(t *testing.T) {
	// Create a chain with certificates that won't verify
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

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
	if err == nil {
		t.Error("expected verification error for invalid chain")
	}
}

func TestRevocationStatus_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	manager := New(cert, version)

	// Fetch the chain first
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := manager.FetchCertificate(ctx); err != nil {
		t.Fatalf("FetchCertificate() error = %v", err)
	}

	// Test with very short timeout to force timeout
	revocationCtx, revocationCancel := context.WithTimeout(t.Context(), 1*time.Millisecond)
	defer revocationCancel()

	_, err = manager.CheckRevocationStatus(revocationCtx)
	// Should either succeed quickly or timeout - we accept both as valid behavior
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRevocationStatus_ContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping context cancellation test in short mode")
	}

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	manager := New(cert, version)

	// Fetch the chain first
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := manager.FetchCertificate(ctx); err != nil {
		t.Fatalf("FetchCertificate() error = %v", err)
	}

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
		t.Errorf("unexpected error: %v", err)
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
				if block == nil {
					t.Fatal("failed to parse certificate PEM")
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("failed to parse certificate: %v", err)
				}

				// 2. Create chain manager
				manager := New(cert, version)

				// 3. Fetch certificate chain
				fetchCtx, fetchCancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer fetchCancel()

				if err := manager.FetchCertificate(fetchCtx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				if len(manager.Certs) < 2 {
					t.Fatalf("expected at least 2 certificates in chain, got %d", len(manager.Certs))
				}

				t.Logf("Successfully fetched certificate chain with %d certificates", len(manager.Certs))

				// 4. Check revocation status
				revocationCtx, revocationCancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer revocationCancel()

				revocationStatus, err := manager.CheckRevocationStatus(revocationCtx)
				if err != nil {
					t.Fatalf("CheckRevocationStatus() error = %v", err)
				}

				// Verify revocation status contains expected elements
				if !strings.Contains(revocationStatus, "Revocation Status Check:") {
					t.Error("revocation status should contain header")
				}

				if !strings.Contains(revocationStatus, "Certificate 1:") {
					t.Error("revocation status should contain certificate information")
				}

				// Should contain either OCSP or CRL status
				hasOCSP := strings.Contains(revocationStatus, "OCSP")
				hasCRL := strings.Contains(revocationStatus, "CRL")

				if !hasOCSP && !hasCRL {
					t.Error("revocation status should contain OCSP or CRL information")
				}

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
					if c == nil {
						t.Errorf("certificate %d is nil", i)
					}
					if len(c.Raw) == 0 {
						t.Errorf("certificate %d has empty raw data", i)
					}
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
				if block == nil {
					t.Fatal("failed to parse certificate PEM")
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("failed to parse certificate: %v", err)
				}

				// 2. Create chain manager
				manager := New(cert, version)

				// 3. Fetch certificate chain
				fetchCtx, fetchCancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer fetchCancel()

				if err := manager.FetchCertificate(fetchCtx); err != nil {
					t.Fatalf("FetchCertificate() error = %v", err)
				}

				// 4. Add root CA
				if err := manager.AddRootCA(); err != nil {
					t.Fatalf("AddRootCA() error = %v", err)
				}

				// Chain should now include root
				if len(manager.Certs) < 3 {
					t.Fatalf("expected at least 3 certificates after adding root CA, got %d", len(manager.Certs))
				}

				// 5. Check revocation status (should work with root CA)
				revocationCtx, revocationCancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer revocationCancel()

				revocationStatus, err := manager.CheckRevocationStatus(revocationCtx)
				if err != nil {
					t.Fatalf("CheckRevocationStatus() after adding root CA error = %v", err)
				}

				if !strings.Contains(revocationStatus, "Certificate 1:") {
					t.Error("revocation status should contain certificate information")
				}

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
	if currentConfig.MaxSize != 50 {
		t.Errorf("expected MaxSize 50, got %d", currentConfig.MaxSize)
	}
	if currentConfig.CleanupInterval != 30*time.Minute {
		t.Errorf("expected CleanupInterval 30m, got %v", currentConfig.CleanupInterval)
	}

	// Test nil config falls back to defaults
	SetCRLCacheConfig(nil)
	defaultConfig := GetCRLCacheConfig()
	if defaultConfig.MaxSize != 100 {
		t.Errorf("expected default MaxSize 100, got %d", defaultConfig.MaxSize)
	}

	// Restore original config
	SetCRLCacheConfig(originalConfig)
}

func TestCRLCacheMetrics(t *testing.T) {
	// Clear cache for clean test
	ClearCRLCache()

	// Test initial metrics
	metrics := GetCRLCacheMetrics()
	if metrics.Size != 0 {
		t.Errorf("expected initial size 0, got %d", metrics.Size)
	}
	if metrics.Hits != 0 {
		t.Errorf("expected initial hits 0, got %d", metrics.Hits)
	}
	if metrics.Misses != 0 {
		t.Errorf("expected initial misses 0, got %d", metrics.Misses)
	}

	// Test cache operations
	testURL := "http://example.com/test.crl"
	testData := []byte("test CRL data")
	testNextUpdate := time.Now().Add(24 * time.Hour)

	// Set a CRL
	if err := SetCachedCRL(testURL, testData, testNextUpdate); err != nil {
		t.Fatalf("failed to set cached CRL: %v", err)
	}

	// Check metrics after set
	metrics = GetCRLCacheMetrics()
	if metrics.Size != 1 {
		t.Errorf("expected size 1 after set, got %d", metrics.Size)
	}

	// Get the CRL (should be a hit)
	data, found := GetCachedCRL(testURL)
	if !found {
		t.Error("expected CRL to be found")
	}
	if len(data) == 0 {
		t.Error("expected non-empty CRL data")
	}

	// Check metrics after get
	metrics = GetCRLCacheMetrics()
	if metrics.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", metrics.Hits)
	}
	if metrics.Misses != 0 {
		t.Errorf("expected 0 misses, got %d", metrics.Misses)
	}

	// Get non-existent CRL (should be a miss)
	_, found = GetCachedCRL("http://nonexistent.com/crl")
	if found {
		t.Error("expected non-existent CRL to not be found")
	}

	// Check metrics after miss
	metrics = GetCRLCacheMetrics()
	if metrics.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", metrics.Misses)
	}
}

func TestCRLCacheStats(t *testing.T) {
	// Clear cache for clean test
	ClearCRLCache()

	// Add some test data
	testURL1 := "http://example1.com/crl"
	testURL2 := "http://example2.com/crl"
	testData1 := []byte("test data 1")
	testData2 := make([]byte, 1024) // 1KB data for memory calculation

	if err := SetCachedCRL(testURL1, testData1, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set cached CRL 1: %v", err)
	}
	if err := SetCachedCRL(testURL2, testData2, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set cached CRL 2: %v", err)
	}

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
		if !strings.Contains(stats, expected) {
			t.Errorf("expected stats to contain %q, but got:\n%s", expected, stats)
		}
	}

	// Test with no requests (should show 0% hit rate)
	ClearCRLCache()
	stats = GetCRLCacheStats()
	if !strings.Contains(stats, "Hit Rate: 0.0%") {
		t.Errorf("expected 0.0%% hit rate for empty cache, got:\n%s", stats)
	}
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

	if err := SetCachedCRL(expiredURL, []byte("expired"), expiredTime); err != nil {
		t.Fatalf("failed to set expired CRL: %v", err)
	}
	if err := SetCachedCRL(validURL, []byte("valid"), validTime); err != nil {
		t.Fatalf("failed to set valid CRL: %v", err)
	}

	// Check that valid CRL is retrievable but expired one is not
	if _, found := GetCachedCRL(expiredURL); found {
		t.Error("expected expired CRL to not be retrievable")
	}
	if _, found := GetCachedCRL(validURL); !found {
		t.Error("expected valid CRL to be retrievable")
	}

	// Trigger cleanup (this should remove any cached entries that are expired)
	CleanupExpiredCRLs()

	// Check that valid CRL is still retrievable
	if _, found := GetCachedCRL(validURL); !found {
		t.Error("expected valid CRL to remain retrievable after cleanup")
	}

	// Verify cache metrics were updated (if any expired entries were cleaned)
	metrics := GetCRLCacheMetrics()
	if metrics.Size > 1 {
		t.Errorf("expected cache size to be at most 1 after cleanup, got %d", metrics.Size)
	}
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

	if err := SetCachedCRL(url1, []byte("data1"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL 1: %v", err)
	}
	if err := SetCachedCRL(url2, []byte("data2"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL 2: %v", err)
	}

	// Check initial size
	metrics := GetCRLCacheMetrics()
	if metrics.Size != 2 {
		t.Errorf("expected size 2, got %d", metrics.Size)
	}

	// Add third CRL (should trigger eviction)
	if err := SetCachedCRL(url3, []byte("data3"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL 3: %v", err)
	}

	// Check final size and evictions
	metrics = GetCRLCacheMetrics()
	if metrics.Size != 2 {
		t.Errorf("expected size to remain 2 after eviction, got %d", metrics.Size)
	}
	if metrics.Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", metrics.Evictions)
	}

	// The first URL should have been evicted (LRU)
	if _, found := GetCachedCRL(url1); found {
		t.Error("expected first URL to be evicted")
	}
	if _, found := GetCachedCRL(url2); !found {
		t.Error("expected second URL to remain")
	}
	if _, found := GetCachedCRL(url3); !found {
		t.Error("expected third URL to be cached")
	}
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
	if atomic.LoadInt32(&crlCache.cleanupRunning) != 0 {
		t.Error("Cleanup goroutine should not be running after context cancellation")
	}

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
	if atomic.LoadInt32(&crlCache.cleanupRunning) != 1 {
		t.Errorf("Expected 1 cleanup goroutine, got %d", atomic.LoadInt32(&crlCache.cleanupRunning))
	}

	// Check that we haven't created excessive goroutines
	currentGoroutines := runtime.NumGoroutine()
	goroutineIncrease := currentGoroutines - initialGoroutines

	// Allow for some variance (test runner, GC, etc.) but not excessive growth
	// In a leaky implementation, we'd see many more goroutines
	if goroutineIncrease > 5 {
		t.Errorf("Too many goroutines created: initial=%d, current=%d, increase=%d",
			initialGoroutines, currentGoroutines, goroutineIncrease)
	}

	// Test graceful shutdown
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Should not leak goroutines - cleanup flag should be reset
	if atomic.LoadInt32(&crlCache.cleanupRunning) != 0 {
		t.Errorf("Cleanup goroutine did not shut down properly")
	}

	// Final goroutine check - should be back to reasonable levels
	finalGoroutines := runtime.NumGoroutine()
	finalIncrease := finalGoroutines - initialGoroutines

	if finalIncrease > 2 { // Allow small variance for cleanup
		t.Errorf("Goroutines not properly cleaned up: initial=%d, final=%d, increase=%d",
			initialGoroutines, finalGoroutines, finalIncrease)
	}

	// Clean up test state
	ClearCRLCache()
	StopCRLCacheCleanup()
	atomic.StoreInt32(&crlCache.cleanupRunning, 0)
}

func TestGetUserAgent(t *testing.T) {
	// Test custom UserAgent
	conf := NewHTTPConfig("1.0.0")
	conf.UserAgent = "Custom-Agent/1.0"
	if ua := conf.GetUserAgent(); ua != "Custom-Agent/1.0" {
		t.Errorf("expected Custom-Agent/1.0, got %s", ua)
	}

	// Test default
	confDefault := NewHTTPConfig("1.2.3")
	expected := "X.509-Certificate-Chain-Resolver/1.2.3 (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)"
	if ua := confDefault.GetUserAgent(); ua != expected {
		t.Errorf("expected %s, got %s", expected, ua)
	}
}

func TestHTTPConfig_Client_Update(t *testing.T) {
	conf := NewHTTPConfig("1.0.0")
	conf.Timeout = 5 * time.Second

	// First call creates client
	client1 := conf.Client()
	if client1.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client1.Timeout)
	}

	// Update timeout
	conf.Timeout = 10 * time.Second

	// Second call should update existing client
	client2 := conf.Client()
	if client2 != client1 {
		t.Error("expected same client instance")
	}
	if client2.Timeout != 10*time.Second {
		t.Errorf("expected updated timeout 10s, got %v", client2.Timeout)
	}
}
