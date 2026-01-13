// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509certs_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
)

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

func TestCertificateOperations(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T, decoder *x509certs.Certificate, testCert *x509.Certificate)
	}{
		{
			name: "Decode Multiple Certificates",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, _ *x509.Certificate) {
				certs, err := decoder.DecodeMultiple([]byte(testCertPEM))
				require.NoError(t, err, "DecodeMultiple() error")

				assert.Len(t, certs, 1, "expected 1 certificate")
			},
		},
		{
			name: "Encode Certificate to DER",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encodedDER := decoder.EncodeDER(cert)
				assert.NotEmpty(t, encodedDER, "EncodeDER() returned empty result")

				assert.True(t, x509CertEqual(cert, encodedDER), "original and encoded DER certificates are not equal")
			},
		},
		{
			name: "Encode Single Certificate to PEM",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encoded := decoder.EncodeMultiplePEM([]*x509.Certificate{cert})
				assert.NotEmpty(t, encoded, "EncodeMultiplePEM() returned empty result")

				decodedBlock, _ := pem.Decode(encoded)
				assert.NotNil(t, decodedBlock, "failed to decode encoded certificates PEM")

				decodedCert, err := x509.ParseCertificate(decodedBlock.Bytes)
				require.NoError(t, err, "ParseCertificate() error")

				assert.True(t, cert.Equal(decodedCert), "original and decoded certificates are not equal")
			},
		},
		{
			name: "Encode Multiple Certificates to DER",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encodedDER := decoder.EncodeMultipleDER([]*x509.Certificate{cert})
				assert.NotEmpty(t, encodedDER, "EncodeMultipleDER() returned empty result")

				assert.True(t, x509CertEqual(cert, encodedDER), "original and encoded DER certificates are not equal")
			},
		},
		{
			name: "Decode Certificate",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, _ *x509.Certificate) {
				block, _ := pem.Decode([]byte(testCertPEM))
				assert.NotNil(t, block, "failed to parse certificate PEM")

				cert, err := decoder.Decode(block.Bytes)
				require.NoError(t, err, "Decode() error")

				assert.Equal(t, "www.google.com", cert.Subject.CommonName, "expected CommonName www.google.com")
			},
		},
		{
			name: "Decode-Encode-Decode Round Trip",
			testFunc: func(t *testing.T, decoder *x509certs.Certificate, cert *x509.Certificate) {
				encodedDER := decoder.EncodeDER(cert)
				assert.NotEmpty(t, encodedDER, "EncodeDER() returned empty result")

				decodedCert, err := decoder.Decode(encodedDER)
				require.NoError(t, err, "Decode() error")

				assert.True(t, cert.Equal(decodedCert), "original and decoded certificates are not equal")
			},
		},
	}

	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM for test setup")

	testCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse test certificate")

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
			_, err := decoder.Decode([]byte(tt.input))
			assert.Equal(t, tt.expected, err, "expected specific error")
		})
	}
}

func TestCertificate_DecodeDER(t *testing.T) {
	decoder := x509certs.New()

	// Parse test certificate to get DER data
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	testCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse test certificate")

	// Test decoding DER data directly
	t.Run("Valid DER Certificate", func(t *testing.T) {
		cert, err := decoder.Decode(testCert.Raw)
		require.NoError(t, err, "Decode() error")

		assert.True(t, cert.Equal(testCert), "decoded certificate does not match original")
	})

	// Test invalid DER data
	t.Run("Invalid DER Data", func(t *testing.T) {
		invalidDER := []byte("not a certificate")
		_, err := decoder.Decode(invalidDER)
		assert.Equal(t, x509certs.ErrParseCertificate, err, "expected ErrParseCertificate")
	})
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
		{
			name:     "PEM-like but invalid base64",
			input:    []byte("-----BEGIN CERTIFICATE-----\ninvalid-base64\n-----END CERTIFICATE-----"),
			expected: false, // pem.Decode fails on invalid base64
		},
		{
			name:     "DER format (binary)",
			input:    []byte{0x30, 0x82, 0x01, 0x23}, // DER sequence
			expected: false,
		},
	}

	decoder := x509certs.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decoder.IsPEM(tt.input)
			assert.Equal(t, tt.expected, result, "IsPEM() result incorrect")
		})
	}
}

func TestCertificate_EncodeMultiplePEM(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

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
				assert.Empty(t, encoded, "expected empty result")
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

			assert.Equal(t, tt.expectBlocks, blockCount, "expected correct number of PEM blocks")
		})
	}
}

func TestCertificate_DecodeMultiple(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

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
				assert.Equal(t, tt.expectError, err, "expected specific error")
				return
			}

			require.NoError(t, err, "unexpected error")

			assert.Len(t, certs, tt.expectCount, "expected correct number of certificates")
		})
	}
}

func TestCertificate_EncodePEM(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")

	encoded := decoder.EncodePEM(cert)
	assert.NotEmpty(t, encoded, "EncodePEM() returned empty result")

	decodedBlock, _ := pem.Decode(encoded)
	assert.NotNil(t, decodedBlock, "failed to decode encoded PEM")

	assert.Equal(t, "CERTIFICATE", decodedBlock.Type, "expected block type CERTIFICATE")

	decodedCert, err := x509.ParseCertificate(decodedBlock.Bytes)
	require.NoError(t, err, "failed to parse decoded certificate")

	assert.True(t, cert.Equal(decodedCert), "original and decoded certificates are not equal")
}
