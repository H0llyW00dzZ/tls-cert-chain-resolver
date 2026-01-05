// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

// tls-cert-chain-resolver is a command-line tool for building, validating,
// and inspecting TLS certificate chains.
//
// # Installation
//
// Install with Go 1.25.5 or later:
//
//	go install github.com/H0llyW00dzZ/tls-cert-chain-resolver/cmd/tls-cert-chain-resolver@latest
//
// # Usage
//
//	tls-cert-chain-resolver -f INPUT_CERT [FLAGS]
//
// # Flags
//
//	-f, --file              Input certificate file (PEM, DER, or base64) [required]
//	-o, --output            Destination file (default: stdout)
//	-i, --intermediate-only Emit only intermediate certificates
//	-d, --der               Output bundle in DER format
//	-s, --include-system    Append system trust root (where available)
//	-j, --json              Emit JSON summary with PEM-encoded certificates
//	-t, --tree              Display certificate chain as ASCII tree diagram
//	    --table             Display certificate chain as markdown table
//
// # Examples
//
// Resolve a leaf certificate into a PEM bundle:
//
//	tls-cert-chain-resolver -f cert.pem -o chain.pem
//
// Produce JSON output:
//
//	tls-cert-chain-resolver -f cert.pem --json > chain.json
//
// Visualize certificate chain as ASCII tree:
//
//	tls-cert-chain-resolver -f cert.pem --tree
//
// Display certificate chain as markdown table:
//
//	tls-cert-chain-resolver -f cert.pem --table
//
// Verify the output with OpenSSL:
//
//	openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
//	  -untrusted chain.pem chain.pem
package main
