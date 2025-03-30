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

	// ErrParsePKCS7 indicates a failure to parse PKCS7 formatted data.
	ErrParsePKCS7 = errors.New("x509certs: failed to parse PKCS7 data")

	// ErrNoCertificatesInPKCS indicates that no certificates were found in the PKCS7 data.
	ErrNoCertificatesInPKCS = errors.New("x509certs: no certificates found in PKCS7 data")
)

// Certificate provides methods to decode and encode [X.509] certificates.
// It maintains internal configuration such as the certificate block type.
//
// [X.509]: https://en.wikipedia.org/wiki/X.509
type Certificate struct {
	certBlockType string
}

// New creates a new Certificate with default settings.
func New() *Certificate {
	return &Certificate{
		certBlockType: "CERTIFICATE",
	}
}

// IsPEM checks if the data is in PEM format.
func (c *Certificate) IsPEM(data []byte) bool {
	block, _ := pem.Decode(data)
	return block != nil
}

// decodePEMBlock decodes a PEM block and checks its type.
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
		return nil, ErrParsePKCS7
	}
	if len(p.Content.SignedData.Certificates) == 0 {
		return nil, ErrNoCertificatesInPKCS
	}

	return p.Content.SignedData.Certificates[0], nil
}

// EncodePEM encodes a certificate to PEM format.
func (c *Certificate) EncodePEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  c.certBlockType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

// EncodeDER encodes a certificate to DER format.
func (c *Certificate) EncodeDER(cert *x509.Certificate) []byte { return cert.Raw }

// EncodeMultiplePEM encodes multiple certificates to PEM format.
func (c *Certificate) EncodeMultiplePEM(certs []*x509.Certificate) []byte {
	var data []byte

	for _, cert := range certs {
		data = append(data, c.EncodePEM(cert)...)
	}

	return data
}

// EncodeMultipleDER encodes multiple certificates to DER format.
func (c *Certificate) EncodeMultipleDER(certs []*x509.Certificate) []byte {
	var data []byte

	for _, cert := range certs {
		data = append(data, c.EncodeDER(cert)...)
	}

	return data
}
