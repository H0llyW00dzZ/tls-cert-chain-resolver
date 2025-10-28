// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
)

// Chain manages [X.509] certificates.
//
// [X.509]: https://grokipedia.com/page/X.509
type Chain struct {
	Certs []*x509.Certificate
	*x509certs.Certificate
	Version       string
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

// New creates a new Chain.
func New(cert *x509.Certificate, version string) *Chain {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	return &Chain{
		Certs:         []*x509.Certificate{cert},
		Certificate:   x509certs.New(),
		Version:       version,
		Roots:         roots,
		Intermediates: intermediates,
	}
}

// FetchCertificate retrieves the certificate chain starting from the given certificate.
//
// Note: This is most effective for chaining written in Go due to the power of the standard library.
// Previously, I attempted to implement this in [Rust], but the results were different and buggy.
// This might be because I am new to [Rust], or due to the challenges posed by [Rust]'s borrow checker.
//
// [Rust]: https://www.rust-lang.org/
func (ch *Chain) FetchCertificate(ctx context.Context) error {
	for ch.Certs[len(ch.Certs)-1].IssuingCertificateURL != nil {
		parentURL := ch.Certs[len(ch.Certs)-1].IssuingCertificateURL[0]

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, parentURL, nil)
		if err != nil {
			return err
		}

		// Set the User-Agent header with version information and GitHub link
		req.Header.Set("User-Agent", "TLS-Certificate-Chain-Resolver/"+ch.Version+" (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		// Get a buffer from the pool
		buf := gc.Default.Get()

		defer func() {
			buf.Reset()         // Reset the buffer to prevent data leaks
			gc.Default.Put(buf) // Return the buffer to the pool for reuse
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

		ch.Certs = append(ch.Certs, cert)

		if ch.IsRootNode(cert) {
			break
		}
	}

	return ch.VerifyChain()
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

// VerifyChain checks that each certificate in the chain is validly signed by its predecessor.
func (ch *Chain) VerifyChain() error {
	for i, cert := range ch.Certs {
		if i == len(ch.Certs)-1 {
			ch.Roots.AddCert(cert)
		} else {
			ch.Intermediates.AddCert(cert)
		}
	}

	leaf := ch.Certs[0]
	opts := x509.VerifyOptions{
		Roots:         ch.Roots,
		Intermediates: ch.Intermediates,
	}

	if _, err := leaf.Verify(opts); err != nil {
		// Return the original error from the verification process to preserve
		// detailed diagnostic information (e.g., expiration, unknown authority).
		return err
	}

	return nil
}
