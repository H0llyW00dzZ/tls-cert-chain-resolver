// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// CRLCacheEntry represents a cached CRL with metadata
type CRLCacheEntry struct {
	Data       []byte    // Raw CRL data
	FetchedAt  time.Time // When this CRL was fetched
	NextUpdate time.Time // When this CRL expires (from CRL.NextUpdate)
	URL        string    // Source URL for debugging
}

// isFresh checks if the cached CRL is still fresh
func (entry *CRLCacheEntry) isFresh() bool {
	now := time.Now()
	// CRL is fresh if NextUpdate is in the future and we fetched it recently
	return entry.NextUpdate.After(now) && entry.FetchedAt.After(now.Add(-24*time.Hour))
}

// isExpired checks if the CRL has expired and should be cleaned up
func (entry *CRLCacheEntry) isExpired() bool {
	now := time.Now()
	// CRL is expired if NextUpdate has passed (with some buffer time)
	return entry.NextUpdate.Before(now.Add(-1 * time.Hour)) // Allow 1 hour grace period
}

// CRLCacheConfig holds configuration for the CRL cache
type CRLCacheConfig struct {
	MaxSize         int           // Maximum number of CRLs to cache (0 = unlimited, but not recommended)
	CleanupInterval time.Duration // How often to run cleanup (default: 1 hour)
}

// CRLCacheMetrics tracks cache performance and usage
type CRLCacheMetrics struct {
	Size        int64 // Current number of cached CRLs
	Hits        int64 // Number of cache hits
	Misses      int64 // Number of cache misses
	Evictions   int64 // Number of LRU evictions
	Cleanups    int64 // Number of expired CRL cleanups
	TotalMemory int64 // Approximate memory usage in bytes
}

// Default CRL cache configuration
var defaultCRLCacheConfig = CRLCacheConfig{
	MaxSize:         100,
	CleanupInterval: 1 * time.Hour,
}

// crlCache is a simple LRU cache for CRLs
var crlCache = make(map[string]*CRLCacheEntry)
var crlCacheMutex sync.RWMutex
var crlCacheOrder []string      // Maintains access order for LRU eviction
var crlCacheConfig atomic.Value // Stores *CRLCacheConfig
var crlCacheMetrics CRLCacheMetrics
var crlCacheCleanupRunning int32 // Atomic flag to ensure only one cleanup goroutine

// init initializes the CRL cache with default configuration
func init() {
	crlCacheConfig.Store(&defaultCRLCacheConfig)
	startCRLCacheCleanup()
}

// SetCRLCacheConfig sets the CRL cache configuration
func SetCRLCacheConfig(config *CRLCacheConfig) {
	cfg := &CRLCacheConfig{
		MaxSize:         defaultCRLCacheConfig.MaxSize,
		CleanupInterval: defaultCRLCacheConfig.CleanupInterval,
	}

	if config != nil {
		cfg.MaxSize = config.MaxSize
		cfg.CleanupInterval = config.CleanupInterval
	}

	// Validate configuration
	if cfg.MaxSize < 0 {
		cfg.MaxSize = 0 // 0 means unlimited, but not recommended
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 1 * time.Hour
	}

	// Store a copy to prevent external mutation
	crlCacheConfig.Store(&CRLCacheConfig{
		MaxSize:         cfg.MaxSize,
		CleanupInterval: cfg.CleanupInterval,
	})

	pruneCRLCache(cfg.MaxSize)
}

func pruneCRLCache(maxSize int) {
	if maxSize <= 0 {
		return
	}

	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	if len(crlCache) <= maxSize {
		return
	}

	removed := int64(0)
	for len(crlCache) > maxSize {
		if len(crlCacheOrder) == 0 {
			break
		}

		lruURL := crlCacheOrder[0]
		delete(crlCache, lruURL)
		crlCacheOrder = crlCacheOrder[1:]
		removed++
	}

	if removed > 0 {
		atomic.AddInt64(&crlCacheMetrics.Evictions, removed)
	}
}

// GetCRLCacheConfig returns the current CRL cache configuration
func GetCRLCacheConfig() *CRLCacheConfig {
	config := crlCacheConfig.Load().(*CRLCacheConfig)
	// Return a copy to prevent external mutation
	return &CRLCacheConfig{
		MaxSize:         config.MaxSize,
		CleanupInterval: config.CleanupInterval,
	}
}

// GetCRLCacheMetrics returns current cache metrics
func GetCRLCacheMetrics() CRLCacheMetrics {
	crlCacheMutex.RLock()
	defer crlCacheMutex.RUnlock()

	// Calculate total memory usage
	var totalMemory int64
	for _, entry := range crlCache {
		totalMemory += int64(len(entry.Data)) + int64(len(entry.URL)) + 24 // Approximate overhead
	}

	metrics := crlCacheMetrics
	metrics.Size = int64(len(crlCache))
	metrics.TotalMemory = totalMemory

	return metrics
}

// startCRLCacheCleanup starts the background cleanup goroutine
func startCRLCacheCleanup() {
	// Only start if not already running
	if !atomic.CompareAndSwapInt32(&crlCacheCleanupRunning, 0, 1) {
		return
	}

	go func() {
		ticker := time.NewTicker(GetCRLCacheConfig().CleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			cleanupExpiredCRLs()
			// Update ticker interval in case config changed
			ticker.Reset(GetCRLCacheConfig().CleanupInterval)
		}
	}()
}

// cleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time
func cleanupExpiredCRLs() {
	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	var expiredURLs []string
	for url, entry := range crlCache {
		if entry.isExpired() {
			expiredURLs = append(expiredURLs, url)
		}
	}

	// Remove expired entries
	for _, url := range expiredURLs {
		delete(crlCache, url)
		// Also remove from access order
		for i, u := range crlCacheOrder {
			if u == url {
				crlCacheOrder = append(crlCacheOrder[:i], crlCacheOrder[i+1:]...)
				break
			}
		}
	}

	if len(expiredURLs) > 0 {
		atomic.AddInt64(&crlCacheMetrics.Cleanups, int64(len(expiredURLs)))
	}
}

// updateCacheOrder updates the access order for LRU eviction
func updateCacheOrder(url string) {
	// Remove from current position
	for i, u := range crlCacheOrder {
		if u == url {
			crlCacheOrder = append(crlCacheOrder[:i], crlCacheOrder[i+1:]...)
			break
		}
	}
	// Add to end (most recently used)
	crlCacheOrder = append(crlCacheOrder, url)
}

// GetCachedCRL retrieves a fresh CRL from cache and updates access order
func GetCachedCRL(url string) ([]byte, bool) {
	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	entry, exists := crlCache[url]
	if !exists || !entry.isFresh() {
		atomic.AddInt64(&crlCacheMetrics.Misses, 1)
		return nil, false
	}

	atomic.AddInt64(&crlCacheMetrics.Hits, 1)

	// Update access order (move to end for LRU)
	updateCacheOrder(url)

	// Return a copy to prevent external modification
	dataCopy := make([]byte, len(entry.Data))
	copy(dataCopy, entry.Data)
	return dataCopy, true
}

// SetCachedCRL stores a CRL in cache with metadata and implements LRU eviction
func SetCachedCRL(url string, data []byte, nextUpdate time.Time) {
	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	config := GetCRLCacheConfig()

	// Evict least recently used entry if cache is full
	for len(crlCache) >= config.MaxSize && config.MaxSize > 0 {
		if len(crlCacheOrder) > 0 {
			// Remove the least recently used (first in order)
			lruURL := crlCacheOrder[0]
			delete(crlCache, lruURL)
			crlCacheOrder = crlCacheOrder[1:]
			atomic.AddInt64(&crlCacheMetrics.Evictions, 1)
		} else {
			break // No more entries to evict
		}
	}

	// Make a copy of the data to store
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	crlCache[url] = &CRLCacheEntry{
		Data:       dataCopy,
		FetchedAt:  time.Now(),
		NextUpdate: nextUpdate,
		URL:        url,
	}

	// Add to access order (most recently used)
	updateCacheOrder(url)
}

// ClearCRLCache clears all cached CRLs (useful for testing)
func ClearCRLCache() {
	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	crlCache = make(map[string]*CRLCacheEntry)
	crlCacheOrder = nil

	// Reset metrics
	atomic.StoreInt64(&crlCacheMetrics.Hits, 0)
	atomic.StoreInt64(&crlCacheMetrics.Misses, 0)
	atomic.StoreInt64(&crlCacheMetrics.Evictions, 0)
	atomic.StoreInt64(&crlCacheMetrics.Cleanups, 0)
}

// CleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time
func CleanupExpiredCRLs() {
	cleanupExpiredCRLs()
}

// GetCRLCacheStats returns a formatted string with cache statistics
func GetCRLCacheStats() string {
	metrics := GetCRLCacheMetrics()
	config := GetCRLCacheConfig()

	hitRate := float64(0)
	totalRequests := metrics.Hits + metrics.Misses
	if totalRequests > 0 {
		hitRate = float64(metrics.Hits) / float64(totalRequests) * 100
	}

	return fmt.Sprintf("CRL Cache Statistics:\n"+
		"  Size: %d/%d entries\n"+
		"  Memory Usage: %.2f KB\n"+
		"  Hit Rate: %.1f%% (%d hits, %d misses)\n"+
		"  Evictions: %d\n"+
		"  Cleanups: %d\n"+
		"  Cleanup Interval: %v",
		metrics.Size, config.MaxSize,
		float64(metrics.TotalMemory)/1024,
		hitRate, metrics.Hits, metrics.Misses,
		metrics.Evictions,
		metrics.Cleanups,
		config.CleanupInterval)
}
