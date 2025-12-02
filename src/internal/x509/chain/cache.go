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

// crlCacheCounters holds atomic counters for internal use.
type crlCacheCounters struct {
	Hits      atomic.Int64
	Misses    atomic.Int64
	Evictions atomic.Int64
	Cleanups  atomic.Int64
}

// crlCache is the global CRL cache instance.
var crlCache = newCRLCache()

// Default CRL cache configuration
var defaultCRLCacheConfig = CRLCacheConfig{
	MaxSize:         100,
	CleanupInterval: 1 * time.Hour,
}

// CRLCache implements an O(1) LRU cache for CRLs using hashmap + doubly-linked list.
//
// It provides thread-safe operations for storing, retrieving, and managing
// Certificate Revocation Lists with automatic expiration and size limits.
type CRLCache struct {
	sync.RWMutex
	entries         map[string]*CRLCacheEntry
	head            *LRUNode     // LRU (least recently used)
	tail            *LRUNode     // MRU (most recently used)
	config          atomic.Value // Stores *CRLCacheConfig
	stats           crlCacheCounters
	cleanupRunning  int32 // Atomic flag to ensure only one cleanup goroutine
	cleanupCancelMu sync.Mutex
	cleanupCancel   context.CancelFunc
}

// newCRLCache creates a new CRL cache instance with default configuration.
func newCRLCache() *CRLCache {
	cache := &CRLCache{
		entries: make(map[string]*CRLCacheEntry),
	}
	cache.config.Store(&defaultCRLCacheConfig)
	return cache
}

// setConfig sets the cache configuration and triggers pruning if needed.
func (c *CRLCache) setConfig(config *CRLCacheConfig) {
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
	c.config.Store(&CRLCacheConfig{
		MaxSize:         cfg.MaxSize,
		CleanupInterval: cfg.CleanupInterval,
	})

	c.prune(cfg.MaxSize)
}

// getConfig returns a copy of the current configuration.
func (c *CRLCache) getConfig() *CRLCacheConfig {
	config := c.config.Load().(*CRLCacheConfig)
	return &CRLCacheConfig{
		MaxSize:         config.MaxSize,
		CleanupInterval: config.CleanupInterval,
	}
}

// getMetrics returns current cache metrics with calculated memory usage.
func (c *CRLCache) getMetrics() CRLCacheMetrics {
	c.RLock()
	defer c.RUnlock()

	// Calculate total memory usage
	var totalMemory int64
	for _, entry := range c.entries {
		totalMemory += entry.memoryUsage()
	}

	// Read all metrics atomically to avoid race conditions
	return CRLCacheMetrics{
		Size:        int64(len(c.entries)),
		TotalMemory: totalMemory,
		Hits:        c.stats.Hits.Load(),
		Misses:      c.stats.Misses.Load(),
		Evictions:   c.stats.Evictions.Load(),
		Cleanups:    c.stats.Cleanups.Load(),
	}
}

// addToTail adds a node to the tail (most recently used position).
func (c *CRLCache) addToTail(node *LRUNode) {
	node.prev = c.tail
	node.next = nil

	if c.tail != nil {
		c.tail.next = node
	} else {
		// List is empty, this is both head and tail
		c.head = node
	}

	c.tail = node
}

// moveToTail moves a node to the tail (most recently used position).
func (c *CRLCache) moveToTail(node *LRUNode) {
	if node == c.tail {
		// Already at tail, nothing to do
		return
	}

	// Remove from current position
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		// Node is at head
		c.head = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	}

	// Add to tail
	node.prev = c.tail
	node.next = nil

	if c.tail != nil {
		c.tail.next = node
	} else {
		// List is now empty (shouldn't happen in normal operation)
		c.head = node
	}

	c.tail = node
}

// removeFromList removes a node from the linked list.
func (c *CRLCache) removeFromList(node *LRUNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		// Node is at head
		c.head = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	} else {
		// Node is at tail
		c.tail = node.prev
	}
}

// removeOldest removes the least recently used entry (head).
//
// Caller must hold the lock.
func (c *CRLCache) removeOldest() {
	if c.head == nil {
		return
	}

	// Remove least recently used (head of list)
	lruURL := c.head.url
	lruNode := c.head

	// Update list pointers
	c.head = lruNode.next
	if c.head != nil {
		c.head.prev = nil
	} else {
		// Cache is now empty
		c.tail = nil
	}

	// Remove from cache map
	delete(c.entries, lruURL)

	// Update metrics
	c.stats.Evictions.Add(1)
}

// prune enforces cache size limits by evicting LRU entries.
func (c *CRLCache) prune(maxSize int) {
	if maxSize <= 0 {
		return
	}

	c.Lock()
	defer c.Unlock()

	for len(c.entries) > maxSize {
		if c.head == nil {
			break
		}
		c.removeOldest()
	}
}

// evictLRUEntries evicts entries to make room for new one if needed.
//
// Caller must hold the lock.
func (c *CRLCache) evictLRUEntries(maxSize int) {
	for len(c.entries) >= maxSize && maxSize > 0 {
		if c.head == nil {
			break // No more entries to evict
		}
		c.removeOldest()
	}
}

// createNewCacheEntry creates a new cache entry and adds it to the cache.
func (c *CRLCache) createNewCacheEntry(url string, data []byte, nextUpdate time.Time) {
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
	c.entries[url] = &CRLCacheEntry{
		Data:       dataCopy,
		FetchedAt:  time.Now(),
		NextUpdate: nextUpdate,
		URL:        url,
		node:       node,
	}

	// Add to tail (most recently used)
	c.addToTail(node)
}

// cleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time.
func (c *CRLCache) cleanupExpiredCRLs() {
	// First pass: collect expired URLs without holding lock
	var expiredURLs []string

	c.RLock()
	for url, entry := range c.entries {
		if entry.isExpired() {
			expiredURLs = append(expiredURLs, url)
		}
	}
	c.RUnlock()

	// Second pass: remove expired entries with write lock (brief)
	if len(expiredURLs) > 0 {
		var actuallyRemoved int64
		c.Lock()
		for _, url := range expiredURLs {
			if entry, exists := c.entries[url]; exists && entry.isExpired() {
				// Remove from linked list
				if entry.node != nil {
					c.removeFromList(entry.node)
				}
				// Remove from cache map
				delete(c.entries, url)
				actuallyRemoved++
			}
		}
		c.Unlock()

		c.stats.Cleanups.Add(actuallyRemoved)
	}
}

// get retrieves a fresh CRL from cache and updates access order.
func (c *CRLCache) get(url string) ([]byte, bool) {
	// Use read lock initially for checking entry
	c.RLock()
	entry, exists := c.entries[url]
	if !exists || !entry.isFresh() {
		c.RUnlock()
		c.stats.Misses.Add(1)
		return nil, false
	}

	// Store data to copy before releasing read lock
	dataToCopy := entry.Data
	c.RUnlock()

	c.stats.Hits.Add(1)

	// Need write lock to update access order
	c.Lock()
	// Re-fetch map entry after acquiring write lock to ensure node still exists and is valid
	if currentEntry, exists := c.entries[url]; exists && currentEntry.node != nil {
		// Additional safety check: ensure node is still part of the list
		if currentEntry.node.prev != nil || currentEntry.node == c.head {
			c.moveToTail(currentEntry.node)
		}
	}
	c.Unlock()

	// Return a copy to prevent external modification
	dataCopy := make([]byte, len(dataToCopy))
	copy(dataCopy, dataToCopy)
	return dataCopy, true
}

// set stores a CRL in cache with metadata and implements LRU eviction.
func (c *CRLCache) set(url string, data []byte, nextUpdate time.Time) error {
	if err := validateCRLData(url, data, nextUpdate); err != nil {
		return err
	}

	c.Lock()
	defer c.Unlock()

	// Try to update existing entry first
	if existingEntry, exists := c.entries[url]; exists {
		// Update existing entry
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		existingEntry.Data = dataCopy
		existingEntry.FetchedAt = time.Now()
		existingEntry.NextUpdate = nextUpdate

		// Move to tail (most recently used)
		if existingEntry.node != nil {
			c.moveToTail(existingEntry.node)
		}

		return nil
	}

	// Need to create new entry, so ensure space is available
	config := c.getConfig()

	// Evict entries if needed (this function assumes we hold the lock)
	c.evictLRUEntries(config.MaxSize)

	// Create new entry (this function assumes we hold the lock)
	c.createNewCacheEntry(url, data, nextUpdate)

	return nil
}

// clear clears all cached CRLs (useful for testing).
func (c *CRLCache) clear() {
	c.Lock()
	defer c.Unlock()

	c.entries = make(map[string]*CRLCacheEntry)
	c.head = nil
	c.tail = nil

	// Reset metrics
	c.stats.Hits.Store(0)
	c.stats.Misses.Store(0)
	c.stats.Evictions.Store(0)
	c.stats.Cleanups.Store(0)
}

// startCleanup starts background cleanup goroutine with context for cancellation.
func (c *CRLCache) startCleanup(ctx context.Context) {
	// If context is already cancelled, don't start goroutine
	if ctx.Err() != nil {
		return
	}

	// Only start if not already running
	if !atomic.CompareAndSwapInt32(&c.cleanupRunning, 0, 1) {
		return
	}

	ctx, cancel := context.WithCancel(ctx)

	c.cleanupCancelMu.Lock()
	c.cleanupCancel = cancel
	c.cleanupCancelMu.Unlock()

	go func() {
		defer func() {
			c.cleanupCancelMu.Lock()
			if c.cleanupCancel != nil {
				c.cleanupCancel()
				c.cleanupCancel = nil
			}
			c.cleanupCancelMu.Unlock()
			atomic.StoreInt32(&c.cleanupRunning, 0)
		}()

		config := c.getConfig()
		ticker := time.NewTicker(config.CleanupInterval)

		for {
			select {
			case <-ticker.C:
				c.cleanupExpiredCRLs()
				// Check if config changed and update ticker if needed
				newConfig := c.getConfig()
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

// stopCleanup stops the running cleanup goroutine if any.
func (c *CRLCache) stopCleanup() {
	c.cleanupCancelMu.Lock()
	cancel := c.cleanupCancel
	c.cleanupCancel = nil
	c.cleanupCancelMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// getStats returns a formatted string with cache statistics.
func (c *CRLCache) getStats() string {
	metrics := c.getMetrics()
	config := c.getConfig()

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

// init initializes the CRL cache with default configuration.
func init() {
	crlCache.setConfig(&defaultCRLCacheConfig)
}

// SetCRLCacheConfig sets CRL cache configuration.
//
// It validates and applies the new configuration, potentially triggering
// immediate pruning if the new max size is smaller than current cache size.
//
// Parameters:
//   - config: New configuration options
func SetCRLCacheConfig(config *CRLCacheConfig) {
	crlCache.setConfig(config)
}

// GetCRLCacheConfig returns current CRL cache configuration.
//
// Returns:
//   - *CRLCacheConfig: Copy of current configuration
func GetCRLCacheConfig() *CRLCacheConfig {
	return crlCache.getConfig()
}

// GetCRLCacheMetrics returns current cache metrics.
//
// It calculates total memory usage on demand and reads atomic counters.
//
// Returns:
//   - CRLCacheMetrics: Snapshot of current metrics
func GetCRLCacheMetrics() CRLCacheMetrics {
	return crlCache.getMetrics()
}

// StartCRLCacheCleanup starts background cleanup goroutine with context for cancellation.
//
// It ensures only one cleanup goroutine is running at a time. The goroutine
// periodically removes expired CRLs based on the configured cleanup interval.
//
// Parameters:
//   - ctx: Context for lifecycle management
func StartCRLCacheCleanup(ctx context.Context) {
	crlCache.startCleanup(ctx)
}

// StopCRLCacheCleanup stops the running cleanup goroutine if any.
//
// It cancels the context associated with the cleanup goroutine.
func StopCRLCacheCleanup() {
	crlCache.stopCleanup()
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
	return crlCache.get(url)
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
	return crlCache.set(url, data, nextUpdate)
}

// ClearCRLCache clears all cached CRLs (useful for testing).
//
// It resets the cache map, list, and metrics.
//
// Thread Safety: Safe for concurrent use.
func ClearCRLCache() {
	crlCache.clear()
}

// CleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time.
//
// It removes any entries whose NextUpdate time has passed.
//
// Thread Safety: Safe for concurrent use.
func CleanupExpiredCRLs() {
	crlCache.cleanupExpiredCRLs()
}

// GetCRLCacheStats returns a formatted string with cache statistics.
//
// It formats current metrics and configuration into a human-readable string.
//
// Returns:
//   - string: Formatted statistics
func GetCRLCacheStats() string {
	return crlCache.getStats()
}
