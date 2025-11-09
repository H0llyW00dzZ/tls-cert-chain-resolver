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
	"strconv"
	"time"
)

// FetchRemoteChain establishes a TLS connection to the target host and
// constructs a chain using the certificates presented during the handshake.
// The returned Chain includes the leaf certificate and any intermediates
// provided by the server. The caller may invoke [FetchCertificate] to
// download additional intermediates if necessary.
func FetchRemoteChain(ctx context.Context, hostname string, port int, timeout time.Duration, version string) (*Chain, []*x509.Certificate, error) {
	// Establish TLS connection to get certificate chain
	netDialer := &net.Dialer{Timeout: timeout}

	if deadline, ok := ctx.Deadline(); ok {
		netDialer.Deadline = deadline
	}

	tlsDialer := &tls.Dialer{
		NetDialer: netDialer,
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		},
	}

	conn, err := tlsDialer.DialContext(ctx, "tcp", net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %s:%d: %w", hostname, port, err)
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, nil, fmt.Errorf("unexpected connection type %T", conn)
	}
	defer tlsConn.Close()

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	// Get the certificate chain from the connection
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, nil, fmt.Errorf("no certificates received from server")
	}

	copiedCerts := make([]*x509.Certificate, len(peerCerts))
	copy(copiedCerts, peerCerts)

	chain := New(copiedCerts[0], version)
	if len(copiedCerts) > 1 {
		chain.Certs = append(chain.Certs, copiedCerts[1:]...)
	}

	return chain, copiedCerts, nil
}
