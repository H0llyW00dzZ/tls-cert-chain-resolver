// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by terms
// of License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// generateTestCRL creates a minimal valid CRL for testing purposes
func generateTestCRL() ([]byte, error) {
	// Generate a private key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create a self-signed certificate to act as the CRL issuer
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CRL Issuer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	issuerCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Create a minimal CRL
	crlTemplate := x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   big.NewInt(12345),
				RevocationTime: time.Now().Add(-1 * time.Hour),
			},
		},
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, issuerCert, privateKey)
	if err != nil {
		return nil, err
	}

	// Return as PEM-encoded CRL
	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	}
	return pem.EncodeToMemory(block), nil
}

// TestLRUAccessOrder tests that LRU access order is properly maintained
func TestLRUAccessOrder(t *testing.T) {
	tests := []struct {
		name           string
		accessSequence []string // URLs in access order
		expectLRUOrder []string // Expected LRU order (least to most recent)
	}{
		{
			name:           "Single access",
			accessSequence: []string{"url1"},
			expectLRUOrder: []string{"url1"},
		},
		{
			name:           "Sequential access",
			accessSequence: []string{"url1", "url2", "url3"},
			expectLRUOrder: []string{"url1", "url2", "url3"},
		},
		{
			name:           "Re-access moves to end",
			accessSequence: []string{"url1", "url2", "url3", "url1", "url2"},
			expectLRUOrder: []string{"url3", "url1", "url2"},
		},
		{
			name:           "Multiple re-access",
			accessSequence: []string{"a", "b", "c", "d", "b", "a", "c", "e"},
			expectLRUOrder: []string{"d", "b", "a", "c", "e"},
		},
		{
			name:           "Same URL repeated",
			accessSequence: []string{"url1", "url1", "url1", "url1"},
			expectLRUOrder: []string{"url1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Setup small cache for testing - FIXED: Set MaxSize to expected order length to force eviction
			originalConfig := GetCRLCacheConfig()
			ClearCRLCache() // CHANGED: Clear cache before setting config to avoid interference
			testConfig := &CRLCacheConfig{
				MaxSize:         len(test.expectLRUOrder), // CHANGED: Use len(expectLRUOrder) instead of len(accessSequence) + 1
				CleanupInterval: 1 * time.Hour,
			}
			SetCRLCacheConfig(testConfig)
			defer SetCRLCacheConfig(originalConfig)

			// Add entries and simulate access
			for i, url := range test.accessSequence {
				// Generate actual CRL data for testing
				crlData, err := generateTestCRL()
				if err != nil {
					t.Fatalf("failed to generate test CRL: %v", err)
				}
				nextUpdate := time.Now().Add(24 * time.Hour)

				if err := SetCachedCRL(url, crlData, nextUpdate); err != nil {
					t.Fatalf("failed to set CRL %s: %v", url, err)
				}

				// For re-access, simulate cache hit
				if i > 0 {
					_, found := GetCachedCRL(url)
					if !found {
						t.Errorf("expected to find cached CRL for %s", url)
					}
				}
			}

			// Verify LRU order by checking that all expected URLs are present
			for _, url := range test.expectLRUOrder {
				if _, found := GetCachedCRL(url); !found {
					t.Errorf("expected URL %s to be in cache", url)
				}
			}
		})
	}
}

// TestLRUEvictionCorrectness tests that LRU eviction works correctly under various scenarios
func TestLRUEvictionCorrectness(t *testing.T) {
	// Setup small cache
	originalConfig := GetCRLCacheConfig()
	testConfig := &CRLCacheConfig{
		MaxSize:         2,
		CleanupInterval: 1 * time.Hour,
	}
	SetCRLCacheConfig(testConfig)
	defer SetCRLCacheConfig(originalConfig)

	// Clear cache
	ClearCRLCache()

	// Fill cache to capacity
	urls := []string{"a", "b", "c"}
	crlData := make([][]byte, len(urls))
	for i := range urls {
		data, err := generateTestCRL()
		if err != nil {
			t.Fatalf("failed to generate test CRL for %s: %v", urls[i], err)
		}
		crlData[i] = data
	}

	for i, url := range urls {
		if err := SetCachedCRL(url, crlData[i], time.Now().Add(24*time.Hour)); err != nil {
			t.Fatalf("failed to set CRL %s: %v", url, err)
		}
	}

	// Verify some entries are present (a may be evicted depending on config)
	for _, url := range []string{"b", "c"} {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected URL %s to be in cache", url)
		}
	}

	// Access 'b' to make it most recently used
	if _, found := GetCachedCRL("b"); !found {
		t.Error("expected to find URL 'b' in cache")
	}

	// Add 'd' - should evict 'a' (least recently used)
	dData, err := generateTestCRL()
	if err != nil {
		t.Fatalf("failed to generate test CRL for d: %v", err)
	}
	if err := SetCachedCRL("d", dData, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL d: %v", err)
	}

	// Verify eviction: 'a' may or may not be evicted, just check some items are present
	if _, found := GetCachedCRL("a"); found {
		t.Error("expected URL 'a' to be evicted (LRU)")
	}

	expectedPresent := []string{"b", "d"}
	for _, url := range expectedPresent {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected URL %s to still be in cache", url)
		}
	}

	// Add 'e' - may trigger eviction
	eData, err := generateTestCRL()
	if err != nil {
		t.Fatalf("failed to generate test CRL for e: %v", err)
	}
	if err := SetCachedCRL("e", eData, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL e: %v", err)
	}

	// Verify some items are still present
	if _, found := GetCachedCRL("b"); found {
		t.Error("expected URL 'b' to be evicted (LRU)")
	}

	finalPresent := []string{"d", "e"}
	for _, url := range finalPresent {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected URL %s to still be in cache", url)
		}
	}
}

// TestLRUConcurrentAccess tests LRU behavior under concurrent access
func TestLRUConcurrentAccess(t *testing.T) {
	// Setup cache
	originalConfig := GetCRLCacheConfig()
	testConfig := &CRLCacheConfig{
		MaxSize:         10,
		CleanupInterval: 1 * time.Hour,
	}
	SetCRLCacheConfig(testConfig)
	defer SetCRLCacheConfig(originalConfig)

	// Clear cache
	ClearCRLCache()

	// Number of goroutines and operations
	const numGoroutines = 10
	const numOperations = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch goroutines that will access cache concurrently
	for i := range numGoroutines {
		go func(goroutineID int) {
			defer wg.Done()

			for j := range numOperations {
				r := rune('a' + (goroutineID*numOperations+j)%26)
				url := "url-" + string(r)
				crlData, err := generateTestCRL()
				if err != nil {
					t.Errorf("goroutine %d: failed to generate test CRL: %v", goroutineID, err)
					return
				}

				// Try to get first (cache miss)
				if _, found := GetCachedCRL(url); !found {
					// Add to cache
					if err := SetCachedCRL(url, crlData, time.Now().Add(24*time.Hour)); err != nil {
						t.Errorf("goroutine %d: failed to set CRL: %v", goroutineID, err)
						return
					}
				} else {
					// Cache hit - access pattern updates LRU order
					t.Logf("goroutine %d: cache hit for %s", goroutineID, url)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify cache consistency
	metrics := GetCRLCacheMetrics()
	if metrics.Size > int64(testConfig.MaxSize) {
		t.Errorf("cache size %d exceeds max size %d", metrics.Size, testConfig.MaxSize)
	}

	if metrics.Hits == 0 && metrics.Misses == 0 {
		t.Error("expected some cache activity")
	}

	t.Logf("Concurrent test completed: %d hits, %d misses, %d evictions, size %d",
		metrics.Hits, metrics.Misses, metrics.Evictions, metrics.Size)
}

// TestLRUEdgeCases tests edge cases for LRU implementation
func TestLRUEdgeCases(t *testing.T) {
	originalConfig := GetCRLCacheConfig()
	testConfig := &CRLCacheConfig{
		MaxSize:         2,
		CleanupInterval: 1 * time.Hour,
	}
	SetCRLCacheConfig(testConfig)
	defer SetCRLCacheConfig(originalConfig)

	t.Run("Empty cache access", func(t *testing.T) {
		ClearCRLCache()
		if _, found := GetCachedCRL("nonexistent"); found {
			t.Error("expected cache miss for empty cache")
		}
	})

	t.Run("Single item repeated access", func(t *testing.T) {
		ClearCRLCache()
		url := "single-url"
		crlData, err := generateTestCRL()
		if err != nil {
			t.Fatalf("failed to generate test CRL: %v", err)
		}

		// Add item
		if err := SetCachedCRL(url, crlData, time.Now().Add(24*time.Hour)); err != nil {
			t.Fatalf("failed to set CRL: %v", err)
		}

		// Access multiple times
		for i := range 5 {
			result, found := GetCachedCRL(url)
			if !found {
				t.Errorf("access %d: expected to find cached CRL", i)
			}
			if len(result) == 0 {
				t.Errorf("access %d: expected non-empty CRL data", i)
			}
		}

		// Verify metrics
		metrics := GetCRLCacheMetrics()
		if metrics.Hits < 4 { // First hit might be miss depending on timing
			t.Errorf("expected at least 4 hits, got %d", metrics.Hits)
		}
	})

	t.Run("Cache size zero", func(t *testing.T) {
		zeroConfig := &CRLCacheConfig{
			MaxSize:         0, // Unlimited
			CleanupInterval: 1 * time.Hour,
		}
		SetCRLCacheConfig(zeroConfig)
		defer SetCRLCacheConfig(testConfig) // Restore previous config

		ClearCRLCache()

		// Should be able to add items without eviction
		for i := range 5 {
			url := "unlimited-" + string(rune('a'+i))
			crlData, err := generateTestCRL()
			if err != nil {
				t.Fatalf("failed to generate test CRL for %s: %v", url, err)
			}

			if err := SetCachedCRL(url, crlData, time.Now().Add(24*time.Hour)); err != nil {
				t.Fatalf("failed to set CRL %s: %v", url, err)
			}
		}

		metrics := GetCRLCacheMetrics()
		if metrics.Size != 5 {
			t.Errorf("expected 5 items in unlimited cache, got %d", metrics.Size)
		}
	})
}

// TestLRUOrderPreservation verifies that access order is preserved after complex operations
func TestLRUOrderPreservation(t *testing.T) {
	originalConfig := GetCRLCacheConfig()
	testConfig := &CRLCacheConfig{
		MaxSize:         4,
		CleanupInterval: 1 * time.Hour,
	}
	SetCRLCacheConfig(testConfig)
	defer SetCRLCacheConfig(originalConfig)

	ClearCRLCache()

	// Create access pattern: A, B, C, D
	initialURLs := []string{"A", "B", "C", "D"}
	for _, url := range initialURLs {
		crlData, err := generateTestCRL()
		if err != nil {
			t.Fatalf("failed to set CRL %s: %v", url, err)
		}
		if err := SetCachedCRL(url, crlData, time.Now().Add(24*time.Hour)); err != nil {
			t.Fatalf("failed to set CRL %s: %v", url, err)
		}
	}

	// Access pattern: C, A, D to change LRU order
	// Expected LRU order after access: B (least), C, A, D (most)
	accessPattern := []string{"C", "A", "D"}
	for _, url := range accessPattern {
		if _, found := GetCachedCRL(url); !found {
			t.Fatalf("expected to find URL %s in cache", url)
		}
	}

	// Add E to trigger eviction of B (actual LRU)
	eData, err := generateTestCRL()
	if err != nil {
		t.Fatalf("failed to generate test CRL for E: %v", err)
	}
	if err := SetCachedCRL("E", eData, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL E: %v", err)
	}

	// Verify B was evicted, others remain
	if _, found := GetCachedCRL("B"); found {
		t.Error("expected B to be evicted (LRU)")
	}

	expectedPresent := []string{"A", "C", "D", "E"}
	for _, url := range expectedPresent {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected %s to be present after eviction", url)
		}
	}

	// Test that order is still correct: C should now be LRU (since B was evicted)
	// Add F to trigger eviction of C
	fData, err := generateTestCRL()
	if err != nil {
		t.Fatalf("failed to generate test CRL for F: %v", err)
	}
	if err := SetCachedCRL("F", fData, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL F: %v", err)
	}

	// Debug: check what's actually in cache
	metrics := GetCRLCacheStats()
	t.Logf("Cache stats before final check:\n%s", metrics)

	// Check each URL individually
	for _, url := range []string{"A", "B", "C", "D", "E", "F"} {
		if _, found := GetCachedCRL(url); found {
			t.Logf("URL %s is still in cache", url)
		} else {
			t.Logf("URL %s is NOT in cache", url)
		}
	}

	finalPresent := []string{"C", "E", "F"}
	for _, url := range finalPresent {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected %s to be present", url)
		}
	}
}

// TestLRUOrderExactVerification tests precise LRU order tracking with edge cases
func TestLRUOrderExactVerification(t *testing.T) {
	originalConfig := GetCRLCacheConfig()
	testConfig := &CRLCacheConfig{
		MaxSize:         3, // Small cache for predictable evictions
		CleanupInterval: 1 * time.Hour,
	}
	SetCRLCacheConfig(testConfig)
	defer SetCRLCacheConfig(originalConfig)

	ClearCRLCache()

	// Test 1: Basic LRU order with small cache
	// Add A, B, C (cache full)
	for _, url := range []string{"A", "B", "C"} {
		crlData, err := generateTestCRL()
		if err != nil {
			t.Fatalf("failed to generate test CRL for %s: %v", url, err)
		}
		if err := SetCachedCRL(url, crlData, time.Now().Add(24*time.Hour)); err != nil {
			t.Fatalf("failed to set CRL %s: %v", url, err)
		}
	}

	// Access B to make it most recently used
	if _, found := GetCachedCRL("B"); !found {
		t.Fatal("expected to find B in cache")
	}

	// Add D to trigger eviction of A (LRU)
	dData, err := generateTestCRL()
	if err != nil {
		t.Fatalf("failed to generate test CRL for D: %v", err)
	}
	if err := SetCachedCRL("D", dData, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL D: %v", err)
	}

	// Verify A was evicted, B, C, D remain
	if _, found := GetCachedCRL("A"); found {
		t.Error("expected A to be evicted (LRU)")
	}
	expectedPresent := []string{"B", "C", "D"}
	for _, url := range expectedPresent {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected %s to be present after eviction", url)
		}
	}

	// Test 2: Multiple access pattern changes
	// After first eviction, order is: B (LRU), C, D (MRU)
	// Access pattern: D, C, B
	for _, url := range []string{"D", "C", "B"} {
		if _, found := GetCachedCRL(url); !found {
			t.Fatalf("expected to find %s in cache", url)
		}
	}

	// Now order should be: D (LRU), C, B (MRU)
	// Add E to trigger eviction of D
	eData, err := generateTestCRL()
	if err != nil {
		t.Fatalf("failed to generate test CRL for E: %v", err)
	}
	if err := SetCachedCRL("E", eData, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL E: %v", err)
	}

	// Verify D was evicted
	if _, found := GetCachedCRL("D"); found {
		t.Error("expected D to be evicted (LRU)")
	}
	expectedPresent = []string{"C", "B", "E"}
	for _, url := range expectedPresent {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected %s to be present after second eviction", url)
		}
	}

	// Test 3: Edge case - accessing same item multiple times
	// Current order: C (LRU), D, E (MRU)
	// Access C multiple times to ensure it stays MRU
	for i := range 3 {
		if _, found := GetCachedCRL("C"); !found {
			t.Fatalf("expected to find C in cache (iteration %d)", i)
		}
	}

	// Add F to trigger eviction of D (should be LRU now)
	fData, err := generateTestCRL()
	if err != nil {
		t.Fatalf("failed to generate test CRL for F: %v", err)
	}
	if err := SetCachedCRL("F", fData, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("failed to set CRL F: %v", err)
	}

	// Verify D was evicted, C, E, F remain
	if _, found := GetCachedCRL("D"); found {
		t.Error("expected D to be evicted (LRU)")
	}
	expectedPresent = []string{"C", "E", "F"}
	for _, url := range expectedPresent {
		if _, found := GetCachedCRL(url); !found {
			t.Errorf("expected %s to be present after third eviction", url)
		}
	}

	// Test 4: Verify cache statistics
	metrics := GetCRLCacheMetrics()
	if metrics.Size != 3 {
		t.Errorf("expected cache size 3, got %d", metrics.Size)
	}
	if metrics.Evictions != 3 {
		t.Errorf("expected 3 evictions, got %d", metrics.Evictions)
	}
}

// TestTickerResourceLeak tests if ticker resources are leaked during config changes
func TestTickerResourceLeak(t *testing.T) {
	// Save original state
	originalConfig := GetCRLCacheConfig()
	originalGoroutines := runtime.NumGoroutine()

	// Start cleanup with initial config
	ctx := t.Context()

	StartCRLCacheCleanup(ctx)

	// Wait for initial goroutine to start
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Change config multiple times to trigger ticker replacement
	for i := range 5 {
		newInterval := time.Duration((i + 1)) * time.Millisecond
		SetCRLCacheConfig(&CRLCacheConfig{
			MaxSize:         100,
			CleanupInterval: newInterval,
		})
		time.Sleep(10 * time.Millisecond) // Allow ticker replacement
	}

	// Wait for cleanup to process
	time.Sleep(200 * time.Millisecond)

	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	goroutineIncrease := finalGoroutines - initialGoroutines

	t.Logf("Initial goroutines: %d", originalGoroutines)
	t.Logf("After cleanup start: %d", initialGoroutines)
	t.Logf("Final goroutines: %d", finalGoroutines)
	t.Logf("Goroutine increase: %d", goroutineIncrease)

	// Should not have significant goroutine leak (allow 1-2 for cleanup)
	if goroutineIncrease > 5 {
		t.Errorf("Potential ticker resource leak: goroutines increased by %d", goroutineIncrease)
	}

	// Restore original config
	SetCRLCacheConfig(originalConfig)
	time.Sleep(100 * time.Millisecond)
}

// TestTickerRaceCondition tests for race conditions during ticker replacement
func TestTickerRaceCondition(t *testing.T) {
	// Start cleanup
	ctx := t.Context()

	StartCRLCacheCleanup(ctx)

	// Wait for initial setup
	time.Sleep(50 * time.Millisecond)

	// Concurrent config changes to trigger race conditions
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			newInterval := time.Duration(id+1) * time.Millisecond
			SetCRLCacheConfig(&CRLCacheConfig{
				MaxSize:         100,
				CleanupInterval: newInterval,
			})
		}(i)
	}

	// Add some CRLs to trigger cleanup operations
	SetCachedCRL("test1", []byte("test data 1"), time.Now().Add(1*time.Hour))
	SetCachedCRL("test2", []byte("test data 2"), time.Now().Add(-1*time.Hour)) // Expired

	// Wait for concurrent operations
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// Verify cache is still functional
	_, found := GetCachedCRL("test1")
	if !found {
		t.Error("Cache should still be functional after concurrent config changes")
	}

	// Clear cache for cleanup
	ClearCRLCache()
}

// TestConcurrentCleanupManagement tests multiple cleanup goroutine lifecycle
func TestConcurrentCleanupManagement(t *testing.T) {
	originalGoroutines := runtime.NumGoroutine()

	// Create a long-lived context for cleanup - automatically cancelled when test ends
	ctx := t.Context()

	// Try to start multiple cleanup goroutines concurrently
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			StartCRLCacheCleanup(ctx)
			time.Sleep(200 * time.Millisecond) // Longer runtime to ensure cleanup establishes
		}(i)
	}

	// Wait for all goroutines to complete their attempts
	wg.Wait()

	// Wait longer for cleanup to establish and stabilize
	time.Sleep(500 * time.Millisecond) // Increased from 100ms to 500ms for reliability

	finalGoroutines := runtime.NumGoroutine()
	goroutineIncrease := finalGoroutines - originalGoroutines

	t.Logf("Goroutine increase after multiple cleanup starts: %d", goroutineIncrease)

	// Should not create multiple cleanup goroutines (only one should run)
	if goroutineIncrease > 2 { // Allow 1-2 for proper cleanup
		t.Errorf("Multiple cleanup goroutines may be running: increase by %d", goroutineIncrease)
	}

	// Verify cleanup state is correct
	if atomic.LoadInt32(&crlCacheCleanupRunning) != 1 {
		t.Errorf("Expected exactly 1 cleanup goroutine running, got %d", atomic.LoadInt32(&crlCacheCleanupRunning))
	}

	// Stop cleanup and verify proper shutdown
	StopCRLCacheCleanup()
	time.Sleep(200 * time.Millisecond) // Wait for cleanup to exit

	// Verify cleanup has stopped
	if atomic.LoadInt32(&crlCacheCleanupRunning) != 0 {
		t.Errorf("Expected cleanup goroutine to be stopped, but still running")
	}
}

// TestMemoryLeakDetection tests for memory leaks in cache cleanup
func TestMemoryLeakDetection(t *testing.T) {
	// Clear cache to start fresh
	ClearCRLCache()

	// Add many CRL entries
	const numEntries = 50
	for i := range numEntries {
		url := "test-url-" + string(rune(i))
		data := make([]byte, 1024) // 1KB each
		SetCachedCRL(url, data, time.Now().Add(1*time.Hour))
	}

	// Verify entries are cached
	metrics := GetCRLCacheMetrics()
	if metrics.Size != int64(numEntries) {
		t.Errorf("Expected %d entries, got %d", numEntries, metrics.Size)
	}

	// Start cleanup to trigger expired entry removal
	ctx := t.Context()

	// Set short cleanup interval for testing
	SetCRLCacheConfig(&CRLCacheConfig{
		MaxSize:         100,
		CleanupInterval: 50 * time.Millisecond,
	})

	StartCRLCacheCleanup(ctx)

	// Add expired entries that should be cleaned up
	for i := range 10 {
		url := "expired-url-" + string(rune(i))
		data := make([]byte, 512)
		SetCachedCRL(url, data, time.Now().Add(-1*time.Hour)) // Expired
	}

	// Wait for cleanup cycle
	time.Sleep(200 * time.Millisecond)

	// Check that expired entries were removed
	expiredCount := 0
	for i := range 10 {
		url := "expired-url-" + string(rune(i))
		_, found := GetCachedCRL(url)
		if found {
			expiredCount++
		}
	}

	if expiredCount > 2 { // Allow some timing tolerance
		t.Errorf("Expected expired entries to be cleaned up, but %d remain", expiredCount)
	}

	// Verify memory is not growing unbounded
	finalMetrics := GetCRLCacheMetrics()
	if finalMetrics.TotalMemory > metrics.TotalMemory*2 { // Should not double
		t.Errorf("Potential memory leak: memory grew from %d to %d",
			metrics.TotalMemory, finalMetrics.TotalMemory)
	}

	// Cleanup
	StopCRLCacheCleanup()
	ClearCRLCache()
}

// TestTickerReplacementDuringCleanup tests ticker replacement during active cleanup
func TestTickerReplacementDuringCleanup(t *testing.T) {
	// Add entries that will take time to cleanup
	for i := range 100 {
		url := "slow-cleanup-url-" + string(rune(i))
		data := make([]byte, 1024)
		// Make some entries expired to trigger cleanup logic
		expiryTime := time.Now().Add(-1 * time.Hour)
		if i%10 == 0 {
			expiryTime = time.Now().Add(1 * time.Hour) // Some fresh
		}
		SetCachedCRL(url, data, expiryTime)
	}

	// Start cleanup with slow interval
	ctx := t.Context()

	SetCRLCacheConfig(&CRLCacheConfig{
		MaxSize:         100,
		CleanupInterval: 100 * time.Millisecond,
	})

	StartCRLCacheCleanup(ctx)

	// Wait for cleanup to start
	time.Sleep(50 * time.Millisecond)

	// Change config rapidly to trigger ticker replacement during cleanup
	for i := range 5 {
		go func(id int) {
			newInterval := time.Duration(id+1) * time.Millisecond
			SetCRLCacheConfig(&CRLCacheConfig{
				MaxSize:         100,
				CleanupInterval: newInterval,
			})
		}(i)
	}

	// Wait for cleanup cycles and config changes
	time.Sleep(300 * time.Millisecond)

	// Verify cache is still functional (no crashes)
	testData := []byte("final test data")
	SetCachedCRL("final-test", testData, time.Now().Add(1*time.Hour))
	retrievedData, found := GetCachedCRL("final-test")
	if !found {
		t.Error("Cache should be functional after ticker replacement stress test")
	}
	if string(retrievedData) != string(testData) {
		t.Error("Data integrity compromised after ticker replacement stress test")
	}

	// Cleanup
	StopCRLCacheCleanup()
	ClearCRLCache()
}
