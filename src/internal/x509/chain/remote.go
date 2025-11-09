// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// FetchRemoteChain establishes a TLS connection to the target host and
// constructs a chain using the certificates presented during the handshake.
// The returned Chain includes the leaf certificate and any intermediates
// provided by the server. The caller may invoke [FetchCertificate] to
// download additional intermediates if necessary.
func FetchRemoteChain(ctx context.Context, hostname string, port int, timeout time.Duration, version string) (*Chain, []*x509.Certificate, error) {
	// Establish TLS connection to get certificate chain
	dialer := &net.Dialer{Timeout: timeout}

	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", hostname, port),
		// We just want the cert chain, not to verify
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %s:%d: %w", hostname, port, err)
	}
	defer conn.Close()

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	// Get the certificate chain from the connection
	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, nil, fmt.Errorf("no certificates received from server")
	}

	chain := New(peerCerts[0], version)
	if len(peerCerts) > 1 {
		chain.Certs = append(chain.Certs, peerCerts[1:]...)
	}

	return chain, peerCerts, nil
}
