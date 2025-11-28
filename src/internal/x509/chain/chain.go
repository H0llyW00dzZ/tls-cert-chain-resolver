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

// NewHTTPConfig creates a new HTTP configuration with default values.
//
// It initializes the configuration with a default timeout of 10 seconds
// and the provided application version.
//
// Parameters:
//   - version: Application version string
//
// Returns:
//   - *HTTPConfig: New HTTP configuration
func NewHTTPConfig(version string) *HTTPConfig {
	return &HTTPConfig{
		Timeout:   10 * time.Second,
		Version:   version,
		UserAgent: "",
	}
}

// GetUserAgent returns the User-Agent string, constructing it if not set.
//
// If a custom User-Agent is configured, it returns that. Otherwise, it
// constructs a default one including the application version and GitHub URL.
//
// Returns:
//   - string: User-Agent string
func (c *HTTPConfig) GetUserAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return fmt.Sprintf("X.509-Certificate-Chain-Resolver/%s (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)", c.Version)
}

// Client returns an HTTP client configured with the current timeout.
//
// It creates or reuses an http.Client, ensuring it uses the configured timeout.
//
// Returns:
//   - *http.Client: Configured HTTP client
//
// Thread Safety: Safe for concurrent use.
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
	mu    sync.RWMutex
	Certs []*x509.Certificate
	*x509certs.Certificate
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	HTTPConfig    *HTTPConfig // HTTP client configuration
}

// New creates a new Chain.
//
// It initializes a new certificate chain manager with the starting certificate
// and default configuration.
//
// Parameters:
//   - cert: Starting certificate (leaf)
//   - version: Application version for HTTP configuration
//
// Returns:
//   - *Chain: New Chain instance
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
// It iteratively fetches the issuing certificate using the AIA (Authority Information Access)
// extension URL until a root certificate is reached or no further issuer can be found.
// It uses buffer pooling for efficient download handling.
//
// Note: This is most effective for chaining written in Go due to the power of the standard library.
// Previously, I attempted to implement this in [Rust], but the results were different and buggy.
// This might be because I am new to [Rust], or due to the challenges posed by [Rust]'s borrow checker.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//
// Returns:
//   - error: Error if fetching fails or chain verification fails
//
// Thread Safety: Safe for concurrent use.
//
// [Rust]: https://www.rust-lang.org/
func (ch *Chain) FetchCertificate(ctx context.Context) error {
	for {
		ch.mu.RLock()
		last := ch.Certs[len(ch.Certs)-1]
		if last.IssuingCertificateURL == nil {
			ch.mu.RUnlock()
			break
		}
		parentURL := last.IssuingCertificateURL[0]
		ch.mu.RUnlock()

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

		// Get a buffer from the pool
		buf := gc.Default.Get()
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			resp.Body.Close()
			buf.Reset()
			gc.Default.Put(buf)
			return err
		}
		resp.Body.Close()

		data := append([]byte(nil), buf.Bytes()...)
		buf.Reset()
		gc.Default.Put(buf)

		cert, err := ch.Certificate.Decode(data)
		if err != nil {
			return err
		}

		ch.mu.Lock()
		current := ch.Certs[len(ch.Certs)-1]
		if current != last {
			ch.mu.Unlock()
			continue
		}
		ch.Certs = append(ch.Certs, cert)
		isRoot := ch.IsRootNode(cert)
		ch.mu.Unlock()

		if isRoot {
			break
		}
	}

	return ch.VerifyChain()
}

// AddRootCA adds a root CA to the certificate chain if necessary.
//
// It attempts to verify the last certificate in the chain against system roots.
// If successful, it appends the root certificate found to the chain.
//
// Returns:
//   - error: Error if verification fails (excluding UnknownAuthorityError)
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) AddRootCA() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()

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
//
// It verifies the certificate's signature against itself.
//
// Parameters:
//   - cert: Certificate to check
//
// Returns:
//   - bool: true if self-signed, false otherwise
func (ch *Chain) IsSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// IsRootNode determines if a certificate is a root node in the chain.
//
// Parameters:
//   - cert: Certificate to check
//
// Returns:
//   - bool: true if it's a root certificate (currently checks if self-signed)
func (ch *Chain) IsRootNode(cert *x509.Certificate) bool {
	return ch.IsSelfSigned(cert)
}

// FilterIntermediates filters out the root and leaf certificates, returning only intermediates.
//
// It returns a slice containing all certificates in the chain except the first
// (leaf) and last (root).
//
// Returns:
//   - []*x509.Certificate: Slice of intermediate certificates, or nil if none
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) FilterIntermediates() []*x509.Certificate {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if len(ch.Certs) <= 2 {
		return nil // No intermediates if 2 or fewer certs
	}
	return ch.Certs[1 : len(ch.Certs)-1] // Skip the first (leaf) and last (root)
}

// VerifyChain checks that each certificate in the chain is validly signed by its predecessor.
//
// It builds separate pools for roots and intermediates from the chain itself
// and attempts to verify the leaf certificate.
//
// Returns:
//   - error: Error if verification fails
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

// findIssuerForCertificate finds the certificate that issued the given cert in the chain.
//
// It iterates backwards through the chain to find a certificate that has signed
// the provided certificate.
//
// Parameters:
//   - cert: Certificate to find issuer for
//
// Returns:
//   - *x509.Certificate: Issuer certificate, or nil if not found
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) findIssuerForCertificate(cert *x509.Certificate) *x509.Certificate {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

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
