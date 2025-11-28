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

// CRLCacheEntry represents a cached CRL with metadata.
//
// It stores the raw CRL data, fetch timestamp, next update time, and a reference
// to the LRU node for efficient O(1) access and updates.
//
// Fields:
//   - Data: Raw CRL data
//   - FetchedAt: When this CRL was fetched
//   - NextUpdate: When this CRL expires (from CRL.NextUpdate)
//   - URL: Source URL for debugging
//   - node: Pointer to LRU node for O(1) access
type CRLCacheEntry struct {
	Data       []byte    // Raw CRL data
	FetchedAt  time.Time // When this CRL was fetched
	NextUpdate time.Time // When this CRL expires (from CRL.NextUpdate)
	URL        string    // Source URL for debugging
	node       *LRUNode  // Pointer to LRU node for O(1) access
}

// LRUNode represents a node in LRU doubly-linked list.
//
// It maintains pointers to the previous and next nodes in the list,
// enabling O(1) insertion, deletion, and movement.
type LRUNode struct {
	url  string
	prev *LRUNode
	next *LRUNode
}

// memoryUsage calculates approximate memory usage of this entry.
//
// It sums the size of raw data, URL string, and structural overhead.
//
// Returns:
//   - int64: Approximate memory usage in bytes
func (entry *CRLCacheEntry) memoryUsage() int64 {
	// Calculate memory usage more accurately
	dataSize := int64(len(entry.Data))
	urlSize := int64(len(entry.URL))

	// Approximate struct overhead: 4 pointers + 2 time.Time (24 bytes each) + string header + LRUNode
	structOverhead := int64(4*8 + 2*24 + 16 + 8) // ~120 bytes

	return dataSize + urlSize + structOverhead
}

// isFresh checks if cached CRL is still fresh.
//
// A CRL is considered fresh if its NextUpdate time is in the future (with 1 hour grace period)
// and it was fetched within the last 24 hours.
//
// Returns:
//   - bool: true if fresh, false otherwise
func (entry *CRLCacheEntry) isFresh() bool {
	now := time.Now()
	// CRL is fresh if NextUpdate is in the future (with 1 hour grace period)
	// and we fetched it within the last 24 hours
	return entry.NextUpdate.After(now.Add(-1*time.Hour)) && entry.FetchedAt.After(now.Add(-24*time.Hour))
}

// isExpired checks if CRL has expired and should be cleaned up.
//
// A CRL is expired if its NextUpdate time has passed (with 1 hour grace period).
//
// Returns:
//   - bool: true if expired, false otherwise
func (entry *CRLCacheEntry) isExpired() bool {
	now := time.Now()
	// CRL is expired if NextUpdate has passed (with 1 hour grace period)
	return entry.NextUpdate.Before(now.Add(-1 * time.Hour))
}

// CRLCacheConfig holds configuration for CRL cache.
type CRLCacheConfig struct {
	MaxSize         int           // Maximum number of CRLs to cache (0 = unlimited, but not recommended)
	CleanupInterval time.Duration // How often to run cleanup (default: 1 hour)
}

// CRLCacheMetrics tracks cache performance and usage.
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

// crlCache is an O(1) LRU cache for CRLs using hashmap + doubly-linked list.
var (
	crlCache                = make(map[string]*CRLCacheEntry)
	crlCacheMutex           sync.RWMutex
	crlCacheHead            *LRUNode     // LRU (least recently used)
	crlCacheTail            *LRUNode     // MRU (most recently used)
	crlCacheConfig          atomic.Value // Stores *CRLCacheConfig
	crlCacheMetrics         CRLCacheMetrics
	crlCacheCleanupRunning  int32 // Atomic flag to ensure only one cleanup goroutine
	crlCacheCleanupCancelMu sync.Mutex
	crlCacheCleanupCancel   context.CancelFunc
)

// init initializes the CRL cache with default configuration.
func init() {
	crlCacheConfig.Store(&defaultCRLCacheConfig)
}

// SetCRLCacheConfig sets CRL cache configuration.
//
// It validates and applies the new configuration, potentially triggering
// immediate pruning if the new max size is smaller than current cache size.
//
// Parameters:
//   - config: New configuration options
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

// addToTail adds a node to the tail (most recently used position).
//
// Parameters:
//   - node: Node to add
func addToTail(node *LRUNode) {
	node.prev = crlCacheTail
	node.next = nil

	if crlCacheTail != nil {
		crlCacheTail.next = node
	} else {
		// List is empty, this is both head and tail
		crlCacheHead = node
	}

	crlCacheTail = node
}

// moveToTail moves a node to the tail (most recently used position).
//
// Parameters:
//   - node: Node to move
func moveToTail(node *LRUNode) {
	if node == crlCacheTail {
		// Already at tail, nothing to do
		return
	}

	// Remove from current position
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		// Node is at head
		crlCacheHead = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	}

	// Add to tail
	node.prev = crlCacheTail
	node.next = nil

	if crlCacheTail != nil {
		crlCacheTail.next = node
	} else {
		// List is now empty (shouldn't happen in normal operation)
		crlCacheHead = node
	}

	crlCacheTail = node
}

// removeFromList removes a node from the linked list.
//
// Parameters:
//   - node: Node to remove
func removeFromList(node *LRUNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		// Node is at head
		crlCacheHead = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	} else {
		// Node is at tail
		crlCacheTail = node.prev
	}
}

// pruneCRLCache enforces cache size limits by evicting LRU entries.
//
// It removes entries from the head of the list (least recently used) until
// the cache size is within the specified maximum.
//
// Parameters:
//   - maxSize: Maximum number of entries allowed
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
		if crlCacheHead == nil {
			break
		}

		// Remove least recently used (head of list)
		lruURL := crlCacheHead.url
		lruNode := crlCacheHead

		// Update head pointer
		crlCacheHead = lruNode.next
		if crlCacheHead != nil {
			crlCacheHead.prev = nil
		} else {
			// Cache is now empty
			crlCacheTail = nil
		}

		// Remove from cache map
		delete(crlCache, lruURL)
		removed++
	}

	if removed > 0 {
		atomic.AddInt64(&crlCacheMetrics.Evictions, removed)
	}
}

// GetCRLCacheConfig returns current CRL cache configuration.
//
// Returns:
//   - *CRLCacheConfig: Copy of current configuration
func GetCRLCacheConfig() *CRLCacheConfig {
	config := crlCacheConfig.Load().(*CRLCacheConfig)
	// Return a copy to prevent external mutation
	return &CRLCacheConfig{
		MaxSize:         config.MaxSize,
		CleanupInterval: config.CleanupInterval,
	}
}

// GetCRLCacheMetrics returns current cache metrics.
//
// It calculates total memory usage on demand and reads atomic counters.
//
// Returns:
//   - CRLCacheMetrics: Snapshot of current metrics
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

// StartCRLCacheCleanup starts background cleanup goroutine with context for cancellation.
//
// It ensures only one cleanup goroutine is running at a time. The goroutine
// periodically removes expired CRLs based on the configured cleanup interval.
//
// Parameters:
//   - ctx: Context for lifecycle management
func StartCRLCacheCleanup(ctx context.Context) {
	// If context is already cancelled, don't start goroutine
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
//
// It cancels the context associated with the cleanup goroutine.
func StopCRLCacheCleanup() {
	crlCacheCleanupCancelMu.Lock()
	cancel := crlCacheCleanupCancel
	crlCacheCleanupCancel = nil
	crlCacheCleanupCancelMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// cleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time.
//
// It uses a two-pass approach to minimize lock contention:
//  1. Identify expired URLs under read lock
//  2. Remove expired entries under write lock
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
		var actuallyRemoved int
		crlCacheMutex.Lock()
		for _, url := range expiredURLs {
			if entry, exists := crlCache[url]; exists && entry.isExpired() {
				// Remove from linked list
				if entry.node != nil {
					removeFromList(entry.node)
				}
				// Remove from cache map
				delete(crlCache, url)
				actuallyRemoved++
			}
		}
		crlCacheMutex.Unlock()

		atomic.AddInt64(&crlCacheMetrics.Cleanups, int64(actuallyRemoved))
	}
}

// GetCachedCRL retrieves a fresh CRL from cache and updates access order.
//
// It checks if the CRL exists and is fresh. If found, it moves the entry
// to the tail of the LRU list (mark as recently used) and returns a copy
// of the data.
//
// Parameters:
//   - url: URL of the CRL
//
// Returns:
//   - []byte: Raw CRL data if found and fresh, nil otherwise
//   - bool: true if found and fresh, false otherwise
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
	// Re-fetch map entry after acquiring write lock to ensure node still exists and is valid
	if currentEntry, exists := crlCache[url]; exists && currentEntry.node != nil {
		// Additional safety check: ensure node is still part of the list
		if currentEntry.node.prev != nil || currentEntry.node == crlCacheHead {
			moveToTail(currentEntry.node)
		}
	}
	crlCacheMutex.Unlock()

	// Return a copy to prevent external modification
	dataCopy := make([]byte, len(dataToCopy))
	copy(dataCopy, dataToCopy)
	return dataCopy, true
}

// validateCRLData validates CRL data and metadata before caching.
//
// Parameters:
//   - url: Source URL
//   - data: Raw CRL data
//   - nextUpdate: Expiration time from CRL
//
// Returns:
//   - error: Error if validation fails
func validateCRLData(url string, data []byte, nextUpdate time.Time) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot cache empty CRL data")
	}

	if url == "" {
		return fmt.Errorf("cannot cache CRL with empty URL")
	}

	// Validate nextUpdate is reasonable (not too far in past or future)
	now := time.Now()
	if nextUpdate.Before(now.Add(-365 * 24 * time.Hour)) { // More than 1 year ago
		return fmt.Errorf("CRL nextUpdate time is too far in past: %v", nextUpdate)
	}
	if nextUpdate.After(now.Add(365 * 24 * time.Hour)) { // More than 1 year from now
		return fmt.Errorf("CRL nextUpdate time is too far in future: %v", nextUpdate)
	}

	return nil
}

// evictLRUEntries evicts entries to make room for new one if needed.
//
// It removes entries until cache size is within the limit.
//
// Parameters:
//   - maxSize: Maximum number of entries allowed
func evictLRUEntries(maxSize int) {
	for len(crlCache) >= maxSize && maxSize > 0 {
		if crlCacheHead == nil {
			break // No more entries to evict
		}

		// Remove least recently used (head of list)
		lruURL := crlCacheHead.url
		lruNode := crlCacheHead

		// Update head pointer
		crlCacheHead = lruNode.next
		if crlCacheHead != nil {
			crlCacheHead.prev = nil
		} else {
			// Cache is now empty
			crlCacheTail = nil
		}

		// Remove from cache map
		delete(crlCache, lruURL)
		atomic.AddInt64(&crlCacheMetrics.Evictions, 1)
	}
}

// createNewCacheEntry creates a new cache entry and adds it to the cache.
//
// It initializes a new LRU node and cache entry, then adds it to the
// tail of the list.
//
// Parameters:
//   - url: Source URL
//   - data: Raw CRL data
//   - nextUpdate: Expiration time
func createNewCacheEntry(url string, data []byte, nextUpdate time.Time) {
	// Make a copy of data to store
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// Create new LRU node
	node := &LRUNode{
		url:  url,
		prev: nil,
		next: nil,
	}

	// Create cache entry with node reference
	crlCache[url] = &CRLCacheEntry{
		Data:       dataCopy,
		FetchedAt:  time.Now(),
		NextUpdate: nextUpdate,
		URL:        url,
		node:       node,
	}

	// Add to tail (most recently used)
	addToTail(node)
}

// SetCachedCRL stores a CRL in cache with metadata and implements LRU eviction.
//
// It validates the data, handles LRU eviction if cache is full, and updates
// the cache. If an entry already exists, it updates it and moves it to the
// tail of the list.
//
// Parameters:
//   - url: Source URL
//   - data: Raw CRL data
//   - nextUpdate: Expiration time from CRL
//
// Returns:
//   - error: Error if validation fails
func SetCachedCRL(url string, data []byte, nextUpdate time.Time) error {
	if err := validateCRLData(url, data, nextUpdate); err != nil {
		return err
	}

	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	// Try to update existing entry first
	if existingEntry, exists := crlCache[url]; exists {
		// Update existing entry
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		existingEntry.Data = dataCopy
		existingEntry.FetchedAt = time.Now()
		existingEntry.NextUpdate = nextUpdate

		// Move to tail (most recently used)
		if existingEntry.node != nil {
			moveToTail(existingEntry.node)
		}

		return nil
	}

	// Need to create new entry, so ensure space is available
	config := GetCRLCacheConfig()

	// Evict entries if needed (this function assumes we hold the lock)
	evictLRUEntries(config.MaxSize)

	// Create new entry (this function assumes we hold the lock)
	createNewCacheEntry(url, data, nextUpdate)

	return nil
}

// ClearCRLCache clears all cached CRLs (useful for testing).
//
// It resets the cache map, list, and metrics.
//
// Thread Safety: Safe for concurrent use.
func ClearCRLCache() {
	crlCacheMutex.Lock()
	defer crlCacheMutex.Unlock()

	crlCache = make(map[string]*CRLCacheEntry)
	crlCacheHead = nil
	crlCacheTail = nil

	// Reset metrics
	atomic.StoreInt64(&crlCacheMetrics.Hits, 0)
	atomic.StoreInt64(&crlCacheMetrics.Misses, 0)
	atomic.StoreInt64(&crlCacheMetrics.Evictions, 0)
	atomic.StoreInt64(&crlCacheMetrics.Cleanups, 0)
}

// CleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time.
//
// This is a convenience wrapper around the internal cleanupExpiredCRLs function.
// It removes any entries whose NextUpdate time has passed.
//
// Thread Safety: Safe for concurrent use.
func CleanupExpiredCRLs() {
	cleanupExpiredCRLs()
}

// GetCRLCacheStats returns a formatted string with cache statistics.
//
// It formats current metrics and configuration into a human-readable string.
//
// Returns:
//   - string: Formatted statistics
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
