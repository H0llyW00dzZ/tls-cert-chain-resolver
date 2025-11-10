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

// clearCRLCache is a helper function to clear the cache for benchmark isolation
func clearCRLCache() {
	// Stop any running cleanup to prevent interference during benchmarks
	StopCRLCacheCleanup()

	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()
	crlCache = make(map[string]*CRLCacheEntry)
	crlCacheHead = nil
	crlCacheTail = nil
}

func BenchmarkFetchCertificateChain(b *testing.B) {
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		b.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	for b.Loop() {
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

	for b.Loop() {
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

	for b.Loop() {
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

	for i := 0; b.Loop(); i++ {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i%1000) // Simulate different URLs

		// Benchmark cache set operation
		SetCachedCRL(url, mockCRLData, mockNextUpdate)

		// Benchmark cache get operation
		if _, found := GetCachedCRL(url); !found {
			b.Fatalf("CRL should be in cache")
		}
	}
}

// BenchmarkLRUCacheSet benchmarks LRU cache set operation performance
func BenchmarkLRUCacheSet(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	// Clear cache to ensure clean benchmark
	clearCRLCache()

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i)
		SetCachedCRL(url, mockCRLData, mockNextUpdate)
	}
}

// BenchmarkLRUCacheGet benchmarks LRU cache get operation performance
func BenchmarkLRUCacheGet(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	// Clear cache to ensure clean benchmark
	clearCRLCache()

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i%100) // Use smaller set

		// Set then get to test both operations
		SetCachedCRL(url, mockCRLData, mockNextUpdate)
		data, found := GetCachedCRL(url)

		if !found {
			b.Fatalf("CRL should be in cache for URL: %s", url)
		}
		// Use data to prevent optimization
		if len(data) == 0 {
			b.Fatalf("Expected non-empty CRL data")
		}
	}
}

// BenchmarkLRUCacheMixed benchmarks mixed set/get operations to test LRU behavior
func BenchmarkLRUCacheMixed(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	// Pre-populate half cache
	for i := range 500 {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i)
		SetCachedCRL(url, mockCRLData, mockNextUpdate)
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if i%2 == 0 {
			// Set operation - should trigger eviction when cache is full
			url := fmt.Sprintf("http://example.com/crl%d.crl", 500+i)
			SetCachedCRL(url, mockCRLData, mockNextUpdate)
		} else {
			// Get operation - should be cache hit most of the time
			url := fmt.Sprintf("http://example.com/crl%d.crl", i%500)
			GetCachedCRL(url)
		}
	}
}

// BenchmarkLRUCacheEviction benchmarks eviction performance when cache is full
func BenchmarkLRUCacheEviction(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	// Fill cache to capacity
	for i := range 1000 {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i)
		SetCachedCRL(url, mockCRLData, mockNextUpdate)
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		// Each set should trigger an eviction
		url := fmt.Sprintf("http://example.com/evict%d.crl", i)
		SetCachedCRL(url, mockCRLData, mockNextUpdate)
	}
}

// BenchmarkLRUCacheAccessPattern benchmarks realistic access patterns (temporal locality)
func BenchmarkLRUCacheAccessPattern(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	// Pre-populate cache
	for i := range 1000 {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i)
		SetCachedCRL(url, mockCRLData, mockNextUpdate)
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		// Simulate temporal locality: 80% of accesses go to 20% of items
		var url string
		if i%5 < 4 { // 80% of the time
			url = fmt.Sprintf("http://example.com/crl%d.crl", i%200) // Access hot items
		} else { // 20% of the time
			url = fmt.Sprintf("http://example.com/crl%d.crl", 200+(i%800)) // Access cold items
		}
		GetCachedCRL(url)
	}
}

// BenchmarkLRUCacheConcurrent benchmarks concurrent access to LRU cache
func BenchmarkLRUCacheConcurrent(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	// Pre-populate cache
	for i := range 500 {
		url := fmt.Sprintf("http://example.com/crl%d.crl", i)
		SetCachedCRL(url, mockCRLData, mockNextUpdate)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		localCounter := 0
		for pb.Next() {
			if localCounter%3 == 0 {
				// Set operation
				url := fmt.Sprintf("http://example.com/crl%d.crl", 500+localCounter)
				SetCachedCRL(url, mockCRLData, mockNextUpdate)
			} else {
				// Get operation
				url := fmt.Sprintf("http://example.com/crl%d.crl", localCounter%500)
				GetCachedCRL(url)
			}
			localCounter++
		}
	})
}

// BenchmarkLRUCacheVsMap compares LRU cache performance against a simple map
func BenchmarkLRUCacheVsMap(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	b.Run("LRU_Cache", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			url := fmt.Sprintf("http://example.com/crl%d.crl", i%1000)
			SetCachedCRL(url, mockCRLData, mockNextUpdate)
			GetCachedCRL(url)
		}
	})

	b.Run("Simple_Map", func(b *testing.B) {
		simpleMap := make(map[string][]byte)
		for i := 0; b.Loop(); i++ {
			url := fmt.Sprintf("http://example.com/crl%d.crl", i%1000)
			simpleMap[url] = mockCRLData
			_ = simpleMap[url]
		}
	})
}

// BenchmarkLRUCacheScalability tests performance with different cache sizes
func BenchmarkLRUCacheScalability(b *testing.B) {
	mockCRLData := []byte("mock CRL data for benchmarking")
	mockNextUpdate := time.Now().Add(24 * time.Hour)

	sizes := []int{100, 500, 1000, 2000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			// Temporarily modify cache size for this benchmark
			originalConfig := crlCacheConfig.Load().(*CRLCacheConfig)
			newConfig := &CRLCacheConfig{
				MaxSize:         size,
				CleanupInterval: time.Hour,
			}
			crlCacheConfig.Store(newConfig)
			defer func() {
				crlCacheConfig.Store(originalConfig)
				// Clear cache to reset state
				crlCacheMutex.Lock()
				crlCache = make(map[string]*CRLCacheEntry)
				crlCacheHead = nil
				crlCacheTail = nil
				crlCacheMutex.Unlock()
			}()

			// Reset cache with new size
			crlCacheMutex.Lock()
			crlCache = make(map[string]*CRLCacheEntry)
			crlCacheHead = nil
			crlCacheTail = nil
			crlCacheMutex.Unlock()

			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				url := fmt.Sprintf("http://example.com/crl%d.crl", i%size)
				SetCachedCRL(url, mockCRLData, mockNextUpdate)
				GetCachedCRL(url)
			}
		})
	}
}
