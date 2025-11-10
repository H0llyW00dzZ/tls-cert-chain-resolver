// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"
)

func BenchmarkFetchCertificateChain(b *testing.B) {
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		b.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager := New(cert, version)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		if err := manager.FetchCertificate(ctx); err != nil {
			b.Fatalf("FetchCertificate() error = %v", err)
		}
		cancel()
	}
}

func BenchmarkCheckRevocationStatus(b *testing.B) {
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		b.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	// Set up manager with fetched chain
	manager := New(cert, version)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := manager.FetchCertificate(ctx); err != nil {
		b.Fatalf("FetchCertificate() setup error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		revocationCtx, revocationCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := manager.CheckRevocationStatus(revocationCtx)
		revocationCancel()
		if err != nil {
			b.Fatalf("CheckRevocationStatus() error = %v", err)
		}
	}
}

func BenchmarkVerifyChain(b *testing.B) {
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		b.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	// Set up manager with fetched chain
	manager := New(cert, version)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := manager.FetchCertificate(ctx); err != nil {
		b.Fatalf("FetchCertificate() setup error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := manager.VerifyChain(); err != nil && !strings.Contains(err.Error(), "issuer name does not match") {
			b.Fatalf("VerifyChain() error = %v", err)
		}
	}
}

func BenchmarkConcurrentRevocationChecks(b *testing.B) {
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		b.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	// Set up manager with fetched chain
	manager := New(cert, version)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := manager.FetchCertificate(ctx); err != nil {
		b.Fatalf("FetchCertificate() setup error = %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			revocationCtx, revocationCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := manager.CheckRevocationStatus(revocationCtx)
			revocationCancel()
			if err != nil {
				b.Fatalf("CheckRevocationStatus() error = %v", err)
			}
		}
	})
}

func BenchmarkCRLCacheOperations(b *testing.B) {
	// Create a mock CRL data
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i%1000) // Simulate different URLs

		// Benchmark cache set operation
		SetCachedCRL(url, mockCRLData, mockNextUpdate)

		// Benchmark cache get operation
		if _, found := GetCachedCRL(url); !found {
			b.Fatalf("CRL should be in cache")
		}
	}
}
