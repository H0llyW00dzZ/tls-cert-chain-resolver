// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509certs_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
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

func TestCertificateOperations(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T, decoder *x509certs.Certificate, testCert *x509.Certificate)
	}{
		{
			name: "Decode Multiple Certificates",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, _ *x509.Certificate) {
				certs, err := decoder.DecodeMultiple([]byte(testCertPEM))
				if err != nil {
					t.Fatalf("DecodeMultiple() error = %v", err)
				}

				if len(certs) != 1 {
					t.Errorf("expected 1 certificate, got %d", len(certs))
				}
			},
		},
		{
			name: "Encode Certificate to DER",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encodedDER := decoder.EncodeDER(cert)
				if len(encodedDER) == 0 {
					t.Fatal("EncodeDER() returned empty result")
				}

				if !x509CertEqual(cert, encodedDER) {
					t.Error("original and encoded DER certificates are not equal")
				}
			},
		},
		{
			name: "Encode Single Certificate to PEM",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encoded := decoder.EncodeMultiplePEM([]*x509.Certificate{cert})
				if len(encoded) == 0 {
					t.Fatal("EncodeMultiplePEM() returned empty result")
				}

				decodedBlock, _ := pem.Decode(encoded)
				if decodedBlock == nil {
					t.Fatal("failed to decode encoded certificates PEM")
				}

				decodedCert, err := x509.ParseCertificate(decodedBlock.Bytes)
				if err != nil {
					t.Fatalf("ParseCertificate() error = %v", err)
				}

				if !cert.Equal(decodedCert) {
					t.Error("original and decoded certificates are not equal")
				}
			},
		},
		{
			name: "Encode Multiple Certificates to DER",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encodedDER := decoder.EncodeMultipleDER([]*x509.Certificate{cert})
				if len(encodedDER) == 0 {
					t.Fatal("EncodeMultipleDER() returned empty result")
				}

				if !x509CertEqual(cert, encodedDER) {
					t.Error("original and encoded DER certificates are not equal")
				}
			},
		},
		{
			name: "Decode Certificate",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, _ *x509.Certificate) {
				block, _ := pem.Decode([]byte(testCertPEM))
				if block == nil {
					t.Fatal("failed to parse certificate PEM")
				}

				cert, err := decoder.Decode(block.Bytes)
				if err != nil {
					t.Fatalf("Decode() error = %v", err)
				}

				if cert.Subject.CommonName != "www.google.com" {
					t.Errorf("expected CommonName www.google.com, got %s", cert.Subject.CommonName)
				}
			},
		},
		{
			name: "Decode-Encode-Decode Round Trip",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encodedDER := decoder.EncodeDER(cert)
				if len(encodedDER) == 0 {
					t.Fatal("EncodeDER() returned empty result")
				}

				decodedCert, err := decoder.Decode(encodedDER)
				if err != nil {
					t.Fatalf("Decode() error = %v", err)
				}

				if !cert.Equal(decodedCert) {
					t.Error("original and decoded certificates are not equal")
				}
			},
		},
	}

	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM for test setup")
	}

	testCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t, decoder, testCert)
		})
	}
}

func x509CertEqual(cert *x509.Certificate, derBytes []byte) bool {
	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return false
	}
	return cert.Equal(parsedCert)
}

const (
	invalidPEM = `
-----BEGIN INVALID-----
MIIEmTCCBD+gAwIBAgIRANFjRCmF+Y2bUYHbhxwkEpowCgYIKoZIzj0EAwIwgY8x
-----END INVALID-----
`

	invalidCERT = `
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz6e5VV5F8rF2sFJ0Q4vA
-----END CERTIFICATE-----
`
)

func TestDecodeCertificate_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{
			name:     "Invalid PEM Block",
			input:    invalidPEM,
			expected: x509certs.ErrInvalidBlockType,
		},
		{
			name:     "Invalid Certificate",
			input:    invalidCERT,
			expected: x509certs.ErrParseCertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := x509certs.New()
			if _, err := decoder.Decode([]byte(tt.input)); err != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, err)
			}
		})
	}
}

func TestCertificate_IsPEM(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "Valid PEM",
			input:    []byte(testCertPEM),
			expected: true,
		},
		{
			name:     "Invalid PEM",
			input:    []byte("not a pem block"),
			expected: false,
		},
		{
			name:     "Empty Input",
			input:    []byte(""),
			expected: false,
		},
	}

	decoder := x509certs.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decoder.IsPEM(tt.input)
			if result != tt.expected {
				t.Errorf("IsPEM() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCertificate_EncodeMultiplePEM(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	tests := []struct {
		name         string
		certs        []*x509.Certificate
		expectBlocks int
	}{
		{
			name:         "Single Certificate",
			certs:        []*x509.Certificate{cert},
			expectBlocks: 1,
		},
		{
			name:         "Multiple Certificates",
			certs:        []*x509.Certificate{cert, cert},
			expectBlocks: 2,
		},
		{
			name:         "Empty List",
			certs:        []*x509.Certificate{},
			expectBlocks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := decoder.EncodeMultiplePEM(tt.certs)

			if tt.expectBlocks == 0 {
				if len(encoded) != 0 {
					t.Errorf("expected empty result, got %d bytes", len(encoded))
				}
				return
			}

			blockCount := 0
			rest := encoded
			for len(rest) > 0 {
				block, remainder := pem.Decode(rest)
				if block == nil {
					break
				}
				blockCount++
				rest = remainder
			}

			if blockCount != tt.expectBlocks {
				t.Errorf("expected %d PEM blocks, got %d", tt.expectBlocks, blockCount)
			}
		})
	}
}

func TestCertificate_DecodeMultiple(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	tests := []struct {
		name        string
		input       []byte
		expectCount int
		expectError error
	}{
		{
			name:        "Single PEM Certificate",
			input:       []byte(testCertPEM),
			expectCount: 1,
			expectError: nil,
		},
		{
			name:        "Multiple PEM Certificates",
			input:       decoder.EncodeMultiplePEM([]*x509.Certificate{cert, cert}),
			expectCount: 2,
			expectError: nil,
		},
		{
			name:        "DER Format",
			input:       cert.Raw,
			expectCount: 1,
			expectError: nil,
		},
		{
			name:        "Invalid PEM Type",
			input:       []byte(invalidPEM),
			expectCount: 0,
			expectError: x509certs.ErrInvalidBlockType,
		},
		{
			name:        "Invalid Certificate Data",
			input:       []byte(invalidCERT),
			expectCount: 0,
			expectError: x509certs.ErrParseCertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := decoder.DecodeMultiple(tt.input)

			if tt.expectError != nil {
				if err != tt.expectError {
					t.Errorf("expected error %v, got %v", tt.expectError, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(certs) != tt.expectCount {
				t.Errorf("expected %d certificates, got %d", tt.expectCount, len(certs))
			}
		})
	}
}

func TestCertificate_EncodePEM(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	encoded := decoder.EncodePEM(cert)
	if len(encoded) == 0 {
		t.Fatal("EncodePEM() returned empty result")
	}

	decodedBlock, _ := pem.Decode(encoded)
	if decodedBlock == nil {
		t.Fatal("failed to decode encoded PEM")
	}

	if decodedBlock.Type != "CERTIFICATE" {
		t.Errorf("expected block type CERTIFICATE, got %s", decodedBlock.Type)
	}

	decodedCert, err := x509.ParseCertificate(decodedBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse decoded certificate: %v", err)
	}

	if !cert.Equal(decodedCert) {
		t.Error("original and decoded certificates are not equal")
	}
}
