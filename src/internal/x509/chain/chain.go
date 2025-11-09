// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
)

// HTTPConfig holds HTTP client configuration for certificate operations
type HTTPConfig struct {
	Timeout   time.Duration // HTTP request timeout
	Version   string        // Application version for User-Agent
	UserAgent string        // Custom User-Agent string, if empty will be constructed from Version

	mu     sync.Mutex
	client *http.Client
}

// NewHTTPConfig creates a new HTTP configuration with default values
func NewHTTPConfig(version string) *HTTPConfig {
	return &HTTPConfig{
		Timeout:   10 * time.Second,
		Version:   version,
		UserAgent: "",
	}
}

// GetUserAgent returns the User-Agent string, constructing it if not set
func (c *HTTPConfig) GetUserAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return fmt.Sprintf("X.509-Certificate-Chain-Resolver/%s (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)", c.Version)
}

// Client returns an HTTP client configured with the current timeout.
func (c *HTTPConfig) Client() *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil {
		c.client = &http.Client{Timeout: c.Timeout}
		return c.client
	}

	if c.client.Timeout != c.Timeout {
		c.client.Timeout = c.Timeout
	}

	return c.client
}

// Chain manages [X.509] certificates.
//
// [X.509]: https://grokipedia.com/page/X.509
type Chain struct {
	Certs []*x509.Certificate
	*x509certs.Certificate
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	HTTPConfig    *HTTPConfig // HTTP client configuration
}

// New creates a new Chain.
func New(cert *x509.Certificate, version string) *Chain {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	return &Chain{
		Certs:         []*x509.Certificate{cert},
		Certificate:   x509certs.New(),
		Roots:         roots,
		Intermediates: intermediates,
		HTTPConfig:    NewHTTPConfig(version),
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
		req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

		// Use custom HTTP client with configured timeout
		resp, err := ch.HTTPConfig.Client().Do(req)
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

// findIssuerForCertificate finds the certificate that issued the given cert in the chain
func (ch *Chain) findIssuerForCertificate(cert *x509.Certificate) *x509.Certificate {
	// For each certificate in the chain (starting from intermediates up)
	for i := len(ch.Certs) - 1; i >= 0; i-- {
		potentialIssuer := ch.Certs[i]
		// Skip self
		if potentialIssuer == cert {
			continue
		}
		// Check if this cert could have issued our cert
		if err := cert.CheckSignatureFrom(potentialIssuer); err == nil {
			return potentialIssuer
		}
	}
	return nil
}
