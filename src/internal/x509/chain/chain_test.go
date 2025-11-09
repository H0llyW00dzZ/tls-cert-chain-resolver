// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"runtime"
	"strings"
	"testing"
	"time"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
)

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
		testFunc    func(t *testing.T, manager *x509chain.Chain)
	}{
		{
			name:    "Fetch Certificate Chain",
			certPEM: testCertPEM,
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
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
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			testFunc: func(t *testing.T, manager *x509chain.Chain) {
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

			manager := x509chain.New(cert, version)
			tt.testFunc(t, manager)
		})
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

	manager := x509chain.New(cert, version)

	ctx, cancel := context.WithCancel(context.Background())
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

			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			chain, certs, err := x509chain.FetchRemoteChain(ctx, tt.hostname, tt.port, tt.timeout, version)

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

			manager := x509chain.New(cert, version)

			// Fetch the chain first
			ctx, cancel := context.WithTimeout(context.Background(), tt.setupTimeout)
			defer cancel()

			if err := manager.FetchCertificate(ctx); err != nil {
				t.Fatalf("FetchCertificate() error = %v", err)
			}

			// Test revocation status check
			revocationCtx, revocationCancel := context.WithTimeout(context.Background(), tt.setupTimeout)
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
	_, err = x509chain.ParseCRLResponse([]byte("invalid"), big.NewInt(12345), cert)
	if err == nil {
		t.Error("expected error for invalid CRL data")
	}

	_, err = x509chain.ParseCRLResponse([]byte{}, big.NewInt(12345), cert)
	if err == nil {
		t.Error("expected error for empty CRL data")
	}

	// Test with nil serial
	_, err = x509chain.ParseCRLResponse([]byte("data"), nil, cert)
	if err == nil {
		t.Error("expected error for nil serial")
	}

	// Test with nil issuer
	_, err = x509chain.ParseCRLResponse([]byte("data"), big.NewInt(12345), nil)
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

	manager := x509chain.New(cert, version)

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

	manager := x509chain.New(cert, version)

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

	manager := x509chain.New(cert, version)

	// Fetch the chain first
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := manager.FetchCertificate(ctx); err != nil {
		t.Fatalf("FetchCertificate() error = %v", err)
	}

	// Test with very short timeout to force timeout
	revocationCtx, revocationCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
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

	manager := x509chain.New(cert, version)

	// Fetch the chain first
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := manager.FetchCertificate(ctx); err != nil {
		t.Fatalf("FetchCertificate() error = %v", err)
	}

	// Test with context that gets cancelled mid-operation
	revocationCtx, revocationCancel := context.WithCancel(context.Background())

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
