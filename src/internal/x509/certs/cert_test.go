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

func TestDecodeCertificates(t *testing.T) {
	decoder := x509certs.New()

	certs, err := decoder.DecodeMultiple([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("DecodeMultiple() error = %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestEncodeCertificateDER(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	encodedDER := decoder.EncodeDER(cert)
	if len(encodedDER) == 0 {
		t.Fatal("EncodeDER() returned empty result")
	}

	if !x509CertEqual(cert, encodedDER) {
		t.Error("original and encoded DER certificates are not equal")
	}
}

func TestEncodeCertificates(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

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
}

func TestEncodeCertificatesDER(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	encodedDER := decoder.EncodeMultipleDER([]*x509.Certificate{cert})
	if len(encodedDER) == 0 {
		t.Fatal("EncodeCertificatesDER() returned empty result")
	}

	if !x509CertEqual(cert, encodedDER) {
		t.Error("original and encoded DER certificates are not equal")
	}
}

func x509CertEqual(cert *x509.Certificate, derBytes []byte) bool {
	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return false
	}
	return cert.Equal(parsedCert)
}

func TestDecodeCertificate(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := decoder.Decode(block.Bytes)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if cert.Subject.CommonName != "*.b0zal.io" {
		t.Errorf("expected CommonName *.b0zal.io, got %s", cert.Subject.CommonName)
	}
}

const invalidPEM = `
-----BEGIN INVALID-----
MIIEmTCCBD+gAwIBAgIRANFjRCmF+Y2bUYHbhxwkEpowCgYIKoZIzj0EAwIwgY8x
-----END INVALID-----
`

func TestDecodeCertificate_InvalidPEM(t *testing.T) {
	decoder := x509certs.New()
	if _, err := decoder.Decode([]byte(invalidPEM)); err != x509certs.ErrInvalidBlockType {
		t.Fatalf("expected ErrInvalidBlockType, got %v", err)
	}
}

func TestDecodeCertificate_InvalidBlockType(t *testing.T) {
	decoder := x509certs.New()

	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}
	block.Type = "INVALID"

	if _, err := decoder.Decode(pem.EncodeToMemory(block)); err != x509certs.ErrInvalidBlockType {
		t.Fatalf("expected ErrInvalidBlockType, got %v", err)
	}
}

func TestDecodeEncodeDecode(t *testing.T) {
	decoder := x509certs.New()

	// Decode PEM to x509.Certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Encode to DER
	encodedDER := decoder.EncodeDER(cert)
	if len(encodedDER) == 0 {
		t.Fatal("EncodeDER() returned empty result")
	}

	// Decode the DER back to x509.Certificate
	decodedCert, err := decoder.Decode(encodedDER)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if !cert.Equal(decodedCert) {
		t.Error("original and decoded certificates are not equal")
	}
}
