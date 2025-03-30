// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
)

const testCertPEM = `
-----BEGIN CERTIFICATE-----
MIIEmTCCBD+gAwIBAgIRANFjRCmF+Y2bUYHbhxwkEpowCgYIKoZIzj0EAwIwgY8x
CzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV
BAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDE3MDUGA1UEAxMu
U2VjdGlnbyBFQ0MgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTAe
Fw0yNDA4MDMwMDAwMDBaFw0yNTA4MDMyMzU5NTlaMBUxEzARBgNVBAMMCiouYjB6
YWwuaW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT4H+0uaWVx6QswsVFJowNe
3XZwU/f87SG8wPNw2KVqCVZadVJjQPwe25L9YGTd28+BQQeNlYEs+U55tw2QCcK2
o4IC8zCCAu8wHwYDVR0jBBgwFoAU9oUKOxGG4QR9DqoLLNLuzGR7e64wHQYDVR0O
BBYEFHx3QpYNdTAzKFZiWKZjmQBq2l31MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMB
Af8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBJBgNVHSAEQjBA
MDQGCysGAQQBsjEBAgIHMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5j
b20vQ1BTMAgGBmeBDAECATCBhAYIKwYBBQUHAQEEeDB2ME8GCCsGAQUFBzAChkNo
dHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29FQ0NEb21haW5WYWxpZGF0aW9u
U2VjdXJlU2VydmVyQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
aWdvLmNvbTAfBgNVHREEGDAWggoqLmIwemFsLmlvgghiMHphbC5pbzCCAXsGCisG
AQQB1nkCBAIEggFrBIIBZwFlAHUA3dzKNJXX4RYF55Uy+sef+D0cUN/bADoUEnYK
LKy7yCoAAAGRFvE4ZAAABAMARjBEAiEAlCcfiQwzgdfWcGfJ/sXXeqD6P9YYuRjG
BMc30Q7qnEYCHw2D//Y35VSxyUk6MA+yTcKyfdhYi1Ti4Br2UEpTSZQAdQAN4fIw
K9MNwUBiEgnqVS78R3R8sdfpMO8OQh60fk6qNAAAAZEW8ThFAAAEAwBGMEQCIBB2
EHVXwqwTsPYvPifDcfgEJUXydVfxPHFfdy1WjkP2AiBYALfEiqmaPC3TuNfu9ZIG
rRLA+i8qb5efmc2KKj9ExgB1ABLxTjS9U3JMhAYZw48/ehP457Vih4icbTAFhOvl
hiY6AAABkRbxOEUAAAQDAEYwRAIgYN3vBCjmliQn7Mx8WtkF0VM/2HMDi2WvZexk
KTIjfnQCIFrMBXGaIMVjhWzB1SQTc97nKzKR0JJ+7+qeDTbMaG1tMAoGCCqGSM49
BAMCA0gAMEUCIQDZvkt1o9z268fmvTInaG72M2UXDCbWDmir1+GHxDHwwQIgPOkc
6s6BVzxMGgtunrmn+je/71iM6E+OCZwM7Qvmamg=
-----END CERTIFICATE-----
`

func TestFetchCertificateChain(t *testing.T) {
	tests := []struct {
		name           string
		certPEM        string
		expectChainLen int
		expectError    bool
	}{
		{
			name:           "Valid Leaf Certificate",
			certPEM:        testCertPEM,
			expectChainLen: 3,
			expectError:    false,
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

			manager := x509chain.New(cert)

			if err = manager.FetchCertificate(); (err != nil) != tt.expectError {
				t.Fatalf("FetchCertificate() error = %v, expectError %v", err, tt.expectError)
			}

			if len(manager.Certs) != tt.expectChainLen {
				t.Errorf("expected chain length %d, got %d", tt.expectChainLen, len(manager.Certs))
			}

			decoder := x509certs.New()
			for _, c := range manager.Certs {
				t.Logf("Certificate Subject: %s", c.Subject.CommonName)
				pemData := decoder.EncodePEM(c)
				t.Logf("Certificate PEM:\n%s", pemData)
			}
		})
	}
}

func TestAddRootCA(t *testing.T) {
	tests := []struct {
		name        string
		certPEM     string
		expectError bool
	}{
		{
			name:        "Add Root CA",
			certPEM:     testCertPEM,
			expectError: false,
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

			manager := x509chain.New(cert)

			if err = manager.FetchCertificate(); err != nil {
				t.Fatalf("FetchCertificate() error = %v", err)
			}

			if err = manager.AddRootCA(); (err != nil) != tt.expectError {
				t.Fatalf("AddRootCA() error = %v, expectError %v", err, tt.expectError)
			}

			decoder := x509certs.New()
			for _, c := range manager.Certs {
				t.Logf("Certificate Subject: %s", c.Subject.CommonName)
				pemData := decoder.EncodePEM(c)
				t.Logf("Certificate PEM:\n%s", pemData)
			}
		})
	}
}

func TestFilterIntermediates(t *testing.T) {
	tests := []struct {
		name                  string
		certPEM               string
		expectedIntermediates int
	}{
		{
			name:                  "Valid Chain with Intermediates",
			certPEM:               testCertPEM,
			expectedIntermediates: 1, // Assuming the test chain has one intermediate
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

			manager := x509chain.New(cert)

			// Simulate fetching the certificate chain
			if err = manager.FetchCertificate(); err != nil {
				t.Fatalf("FetchCertificate() error = %v", err)
			}

			// Filter intermediates
			intermediates := manager.FilterIntermediates()

			if len(intermediates) != tt.expectedIntermediates {
				t.Errorf("expected %d intermediates, got %d", tt.expectedIntermediates, len(intermediates))
			}

			decoder := x509certs.New()
			for _, c := range intermediates {
				t.Logf("Intermediate Certificate Subject: %s", c.Subject.CommonName)
				pemData := decoder.EncodePEM(c)
				t.Logf("Intermediate Certificate PEM:\n%s", pemData)
			}
		})
	}
}
