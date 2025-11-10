// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
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

// memoryUsage calculates the approximate memory usage of this entry
func (entry *CRLCacheEntry) memoryUsage() int64 {
	// Calculate memory usage more accurately
	dataSize := int64(len(entry.Data))
	urlSize := int64(len(entry.URL))

	// Approximate struct overhead: 3 pointers + 2 time.Time (24 bytes each) + string header
	structOverhead := int64(3*8 + 2*24 + 16) // ~88 bytes

	return dataSize + urlSize + structOverhead
}

// isFresh checks if the cached CRL is still fresh
func (entry *CRLCacheEntry) isFresh() bool {
	now := time.Now()
	// CRL is fresh if NextUpdate is in the future (with 1 hour grace period)
	// and we fetched it within the last 24 hours
	return entry.NextUpdate.After(now.Add(-1*time.Hour)) && entry.FetchedAt.After(now.Add(-24*time.Hour))
}

// isExpired checks if the CRL has expired and should be cleaned up
func (entry *CRLCacheEntry) isExpired() bool {
	now := time.Now()
	// CRL is expired if NextUpdate has passed (with 1 hour grace period)
	return entry.NextUpdate.Before(now.Add(-1 * time.Hour))
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
var (
	crlCache                = make(map[string]*CRLCacheEntry)
	crlCacheMutex           sync.RWMutex
	crlCacheOrder           []string     // Maintains access order for LRU eviction
	crlCacheConfig          atomic.Value // Stores *CRLCacheConfig
	crlCacheMetrics         CRLCacheMetrics
	crlCacheCleanupRunning  int32 // Atomic flag to ensure only one cleanup goroutine
	crlCacheCleanupCancelMu sync.Mutex
	crlCacheCleanupCancel   context.CancelFunc
)

// init initializes the CRL cache with default configuration
func init() {
	crlCacheConfig.Store(&defaultCRLCacheConfig)
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

		// Remove the least recently used (first in order)
		if len(crlCacheOrder) > 0 {
			lruURL := crlCacheOrder[0]
			delete(crlCache, lruURL)
			// Manually remove from order slice (more efficient than calling removeFromCacheOrder)
			crlCacheOrder = crlCacheOrder[1:]
			removed++
		}
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

	// Calculate total memory usage more accurately
	var totalMemory int64
	for _, entry := range crlCache {
		totalMemory += entry.memoryUsage()
	}

	// Read all metrics atomically to avoid race conditions
	metrics := CRLCacheMetrics{
		Size:        int64(len(crlCache)),
		TotalMemory: totalMemory,
		Hits:        atomic.LoadInt64(&crlCacheMetrics.Hits),
		Misses:      atomic.LoadInt64(&crlCacheMetrics.Misses),
		Evictions:   atomic.LoadInt64(&crlCacheMetrics.Evictions),
		Cleanups:    atomic.LoadInt64(&crlCacheMetrics.Cleanups),
	}

	return metrics
}

// StartCRLCacheCleanup starts the background cleanup goroutine with context for cancellation
func StartCRLCacheCleanup(ctx context.Context) {
	// If context is already cancelled, don't start the goroutine
	if ctx.Err() != nil {
		return
	}

	// Only start if not already running
	if !atomic.CompareAndSwapInt32(&crlCacheCleanupRunning, 0, 1) {
		return
	}

	ctx, cancel := context.WithCancel(ctx)

	crlCacheCleanupCancelMu.Lock()
	crlCacheCleanupCancel = cancel
	crlCacheCleanupCancelMu.Unlock()

	go func() {
		defer func() {
			crlCacheCleanupCancelMu.Lock()
			if crlCacheCleanupCancel != nil {
				crlCacheCleanupCancel()
				crlCacheCleanupCancel = nil
			}
			crlCacheCleanupCancelMu.Unlock()
			atomic.StoreInt32(&crlCacheCleanupRunning, 0)
		}()

		config := GetCRLCacheConfig()
		ticker := time.NewTicker(config.CleanupInterval)

		for {
			select {
			case <-ticker.C:
				cleanupExpiredCRLs()
				// Check if config changed and update ticker if needed
				newConfig := GetCRLCacheConfig()
				if newConfig.CleanupInterval != config.CleanupInterval {
					ticker.Stop()
					config = newConfig
					ticker = time.NewTicker(config.CleanupInterval)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// StopCRLCacheCleanup stops the running cleanup goroutine if any.
func StopCRLCacheCleanup() {
	crlCacheCleanupCancelMu.Lock()
	cancel := crlCacheCleanupCancel
	crlCacheCleanupCancel = nil
	crlCacheCleanupCancelMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// cleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time
func cleanupExpiredCRLs() {
	// First pass: collect expired URLs without holding lock
	var expiredURLs []string

	crlCacheMutex.RLock()
	for url, entry := range crlCache {
		if entry.isExpired() {
			expiredURLs = append(expiredURLs, url)
		}
	}
	crlCacheMutex.RUnlock()

	// Second pass: remove expired entries with write lock (brief)
	if len(expiredURLs) > 0 {
		crlCacheMutex.Lock()
		for _, url := range expiredURLs {
			if entry, exists := crlCache[url]; exists && entry.isExpired() {
				delete(crlCache, url)
				removeFromCacheOrder(url)
			}
		}
		crlCacheMutex.Unlock()

		atomic.AddInt64(&crlCacheMetrics.Cleanups, int64(len(expiredURLs)))
	}
}

// updateCacheOrder updates the access order for LRU eviction
func updateCacheOrder(url string) {
	// Remove from current position (more efficient)
	for i, u := range crlCacheOrder {
		if u == url {
			// Swap with last element and truncate (O(1) removal)
			crlCacheOrder[i] = crlCacheOrder[len(crlCacheOrder)-1]
			crlCacheOrder = crlCacheOrder[:len(crlCacheOrder)-1]
			break
		}
	}
	// Add to end (most recently used)
	crlCacheOrder = append(crlCacheOrder, url)
}

// removeFromCacheOrder removes a URL from the access order
func removeFromCacheOrder(url string) {
	for i, u := range crlCacheOrder {
		if u == url {
			// Swap with last element and truncate for O(1) removal
			crlCacheOrder[i] = crlCacheOrder[len(crlCacheOrder)-1]
			crlCacheOrder = crlCacheOrder[:len(crlCacheOrder)-1]
			break
		}
	}
}

// GetCachedCRL retrieves a fresh CRL from cache and updates access order
func GetCachedCRL(url string) ([]byte, bool) {
	// Use read lock initially for checking entry
	crlCacheMutex.RLock()
	entry, exists := crlCache[url]
	if !exists || !entry.isFresh() {
		crlCacheMutex.RUnlock()
		atomic.AddInt64(&crlCacheMetrics.Misses, 1)
		return nil, false
	}

	// Store data to copy before releasing read lock
	dataToCopy := entry.Data
	crlCacheMutex.RUnlock()

	atomic.AddInt64(&crlCacheMetrics.Hits, 1)

	// Need write lock to update access order
	crlCacheMutex.Lock()
	updateCacheOrder(url)
	crlCacheMutex.Unlock()

	// Return a copy to prevent external modification
	dataCopy := make([]byte, len(dataToCopy))
	copy(dataCopy, dataToCopy)
	return dataCopy, true
}

// SetCachedCRL stores a CRL in cache with metadata and implements LRU eviction
func SetCachedCRL(url string, data []byte, nextUpdate time.Time) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot cache empty CRL data")
	}

	if url == "" {
		return fmt.Errorf("cannot cache CRL with empty URL")
	}

	// Validate nextUpdate is reasonable (not too far in the past or future)
	now := time.Now()
	if nextUpdate.Before(now.Add(-365 * 24 * time.Hour)) { // More than 1 year ago
		return fmt.Errorf("CRL nextUpdate time is too far in the past: %v", nextUpdate)
	}
	if nextUpdate.After(now.Add(365 * 24 * time.Hour)) { // More than 1 year from now
		return fmt.Errorf("CRL nextUpdate time is too far in the future: %v", nextUpdate)
	}

	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	config := GetCRLCacheConfig()

	// Evict least recently used entry if cache is full
	for len(crlCache) >= config.MaxSize && config.MaxSize > 0 {
		if len(crlCacheOrder) == 0 {
			break // No more entries to evict
		}

		// Remove the least recently used (first in order)
		lruURL := crlCacheOrder[0]
		delete(crlCache, lruURL)
		crlCacheOrder = crlCacheOrder[1:]
		atomic.AddInt64(&crlCacheMetrics.Evictions, 1)
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

	return nil
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
