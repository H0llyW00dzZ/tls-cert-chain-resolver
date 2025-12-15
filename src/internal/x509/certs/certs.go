// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/cloudflare/cfssl/crypto/pkcs7"
)

var (
	// ErrInvalidPEMBlock indicates that the provided data does not contain a valid PEM block.
	ErrInvalidPEMBlock = errors.New("x509certs: invalid PEM block")

	// ErrInvalidBlockType indicates that the PEM block type is not the expected certificate type.
	ErrInvalidBlockType = errors.New("x509certs: invalid block type")

	// ErrParseCertificate indicates a failure to parse the certificate from the provided data.
	ErrParseCertificate = errors.New("x509certs: failed to parse certificate")

	// ErrNoCertificatesInPKCS indicates that no certificates were found in the PKCS7 data.
	ErrNoCertificatesInPKCS = errors.New("x509certs: no certificates found in PKCS7 data")
)

// Certificate provides methods to decode and encode [X.509] certificates.
//
// It maintains internal configuration such as the certificate block type
// and provides a unified interface for handling different certificate formats.
//
// [X.509]: https://grokipedia.com/page/X.509
type Certificate struct {
	// certBlockType: PEM block type identifier (defaults to "CERTIFICATE")
	certBlockType string
}

// New creates a new Certificate with default settings.
//
// It initializes a Certificate helper with the standard "CERTIFICATE"
// block type for PEM encoding/decoding.
//
// Returns:
//   - *Certificate: New initialized Certificate instance
func New() *Certificate {
	return &Certificate{
		certBlockType: "CERTIFICATE",
	}
}

// IsPEM checks if the data is in PEM format.
//
// It attempts to decode the data as a PEM block. If successful, it returns true.
//
// Parameters:
//   - data: Raw byte slice to check
//
// Returns:
//   - bool: true if data contains a PEM block, false otherwise
func (c *Certificate) IsPEM(data []byte) bool {
	block, _ := pem.Decode(data)
	return block != nil
}

// decodePEMBlock decodes a PEM block and checks its type.
//
// Parameters:
//   - data: Raw byte slice containing PEM data
//
// Returns:
//   - *pem.Block: Decoded PEM block
//   - error: ErrInvalidPEMBlock if decoding fails, or ErrInvalidBlockType if type mismatch
func (c *Certificate) decodePEMBlock(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEMBlock
	}
	if block.Type != c.certBlockType {
		return nil, ErrInvalidBlockType
	}
	return block, nil
}

// DecodeMultiple decodes one or more certificates from data.
//
// It handles both PEM and DER formats. For PEM, it iterates through all blocks
// in the data. For DER, it attempts to parse using x509.ParseCertificates.
//
// Parameters:
//   - data: Raw certificate data (PEM or DER)
//
// Returns:
//   - []*x509.Certificate: Slice of decoded certificates
//   - error: Error if decoding or parsing fails
func (c *Certificate) DecodeMultiple(data []byte) ([]*x509.Certificate, error) {
	if c.IsPEM(data) {
		var certs []*x509.Certificate

		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type != c.certBlockType {
				return nil, ErrInvalidBlockType
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, ErrParseCertificate
			}

			certs = append(certs, cert)
			data = rest
		}

		return certs, nil
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, ErrParseCertificate
	}

	return certs, nil
}

// Decode decodes a single certificate from data.
//
// It attempts to decode the input as:
//  1. PEM encoded certificate
//  2. DER encoded certificate (x509.ParseCertificate)
//  3. PKCS7 encoded data containing certificates
//
// Parameters:
//   - data: Raw certificate data
//
// Returns:
//   - *x509.Certificate: Decoded certificate
//   - error: Error if decoding or parsing fails
func (c *Certificate) Decode(data []byte) (*x509.Certificate, error) {
	if c.IsPEM(data) {
		block, err := c.decodePEMBlock(data)
		if err != nil {
			return nil, err
		}

		data = block.Bytes
	}

	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// Attempt to parse as PKCS7 using Cloudflare's library
	p, err := pkcs7.ParsePKCS7(data)
	if err != nil {
		return nil, ErrParseCertificate
	}
	if len(p.Content.SignedData.Certificates) == 0 {
		return nil, ErrNoCertificatesInPKCS
	}

	return p.Content.SignedData.Certificates[0], nil
}

// EncodePEM encodes a certificate to PEM format.
//
// Parameters:
//   - cert: Certificate to encode
//
// Returns:
//   - []byte: PEM encoded certificate data
func (c *Certificate) EncodePEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  c.certBlockType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

// EncodeDER encodes a certificate to DER format.
//
// Parameters:
//   - cert: Certificate to encode
//
// Returns:
//   - []byte: DER encoded certificate data (Raw bytes)
func (c *Certificate) EncodeDER(cert *x509.Certificate) []byte { return cert.Raw }

// EncodeMultiplePEM encodes multiple certificates to PEM format.
//
// It concatenates the PEM encoding of each certificate in the slice.
//
// Parameters:
//   - certs: Slice of certificates to encode
//
// Returns:
//   - []byte: Concatenated PEM encoded data
func (c *Certificate) EncodeMultiplePEM(certs []*x509.Certificate) []byte {
	var data []byte

	for _, cert := range certs {
		data = append(data, c.EncodePEM(cert)...)
	}

	return data
}

// EncodeMultipleDER encodes multiple certificates to DER format.
//
// It concatenates the DER encoding of each certificate in the slice.
//
// Parameters:
//   - certs: Slice of certificates to encode
//
// Returns:
//   - []byte: Concatenated DER encoded data
func (c *Certificate) EncodeMultipleDER(certs []*x509.Certificate) []byte {
	var data []byte

	for _, cert := range certs {
		data = append(data, c.EncodeDER(cert)...)
	}

	return data
}
