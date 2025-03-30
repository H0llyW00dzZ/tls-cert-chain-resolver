// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
)

// Chain manages [X.509] certificates.
//
// [X.509]: https://en.wikipedia.org/wiki/X.509
type Chain struct {
	Certs []*x509.Certificate
	*x509certs.Certificate
}

// New creates a new Chain.
func New(cert *x509.Certificate) *Chain {
	return &Chain{
		Certs:       []*x509.Certificate{cert},
		Certificate: x509certs.New(),
	}
}

// FetchCertificate retrieves the certificate chain starting from the given certificate.
func (ch *Chain) FetchCertificate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for ch.Certs[len(ch.Certs)-1].IssuingCertificateURL != nil {
		parentURL := ch.Certs[len(ch.Certs)-1].IssuingCertificateURL[0]

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, parentURL, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		// Get a buffer from the pool
		buf := gc.BufferPool.Get()

		defer func() {
			buf.Reset()            // Reset the buffer to prevent data leaks
			gc.BufferPool.Put(buf) // Return the buffer to the pool for reuse
		}()

		// Read the response body into the buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return err
		}

		data := buf.Bytes()

		cert, err := ch.Certificate.Decode(data)
		if err != nil {
			return err
		}

		if ch.IsRootNode(cert) {
			break
		}

		ch.Certs = append(ch.Certs, cert)
	}

	return nil
}

// AddRootCA adds a root CA to the certificate chain if necessary.
func (ch *Chain) AddRootCA() error {
	lastCert := ch.Certs[len(ch.Certs)-1]

	chains, err := lastCert.Verify(x509.VerifyOptions{})
	if err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); ok {
			return nil
		}
		return err
	}

	for _, cert := range chains[0] {
		if lastCert.Equal(cert) {
			continue
		}
		ch.Certs = append(ch.Certs, cert)
	}

	return nil
}

// IsSelfSigned checks if a certificate is self-signed.
func (ch *Chain) IsSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// IsRootNode determines if a certificate is a root node in the chain.
func (ch *Chain) IsRootNode(cert *x509.Certificate) bool {
	return ch.IsSelfSigned(cert)
}

// FilterIntermediates filters out the root and leaf certificates, returning only intermediates.
func (ch *Chain) FilterIntermediates() []*x509.Certificate {
	if len(ch.Certs) <= 2 {
		return nil // No intermediates if 2 or fewer certs
	}
	return ch.Certs[1 : len(ch.Certs)-1] // Skip the first (leaf) and last (root)
}
