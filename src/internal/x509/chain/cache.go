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
// to the LRU node for efficient O(1) access and updates. The entry includes
// freshness validation logic and memory usage calculations.
//
// Fields:
//   - Data: Raw CRL data bytes
//   - FetchedAt: Timestamp when this CRL was fetched from the source
//   - NextUpdate: Expiration time from CRL.NextUpdate field
//   - URL: Source URL for debugging and logging purposes
//   - node: Pointer to LRU node for O(1) access order management
type CRLCacheEntry struct {
	// Data: Raw CRL data bytes for revocation checking
	Data []byte
	// FetchedAt: Timestamp when this CRL was retrieved from the source
	FetchedAt time.Time
	// NextUpdate: Expiration time from CRL.NextUpdate field (when CRL becomes stale)
	NextUpdate time.Time
	// URL: Source URL of the CRL (used as cache key and for debugging)
	URL string
	// node: Pointer to LRU node for O(1) access order management (internal use)
	node *LRUNode
}

// LRUNode represents a node in the LRU doubly-linked list.
//
// It maintains pointers to the previous and next nodes in the list,
// enabling O(1) insertion, deletion, and movement operations for LRU eviction.
// The doubly-linked list structure allows efficient reordering of nodes
// when cache entries are accessed.
//
// Fields:
//   - url: The CRL URL this node represents (used as cache key)
//   - prev: Pointer to the previous node in the LRU list
//   - next: Pointer to the next node in the LRU list
type LRUNode struct {
	// url: CRL URL this node represents (used as cache key)
	url string
	// prev: Pointer to the previous node in the LRU doubly-linked list
	prev *LRUNode
	// next: Pointer to the next node in the LRU doubly-linked list
	next *LRUNode
}

// memoryUsage calculates approximate memory usage of this CRL cache entry.
//
// It computes the total memory footprint including raw CRL data, URL string,
// and structural overhead from the doubly-linked list node and time fields.
// This provides a reasonable approximation for memory monitoring and cache
// size management decisions.
//
// The calculation accounts for:
//   - Raw CRL data size in bytes
//   - URL string size and header overhead
//   - Fixed struct overhead (pointers, time.Time structs)
//   - LRU node structural overhead
//
// Returns:
//   - int64: Approximate memory usage in bytes for this cache entry
func (entry *CRLCacheEntry) memoryUsage() int64 {
	// Calculate memory usage more accurately
	dataSize := int64(len(entry.Data))
	urlSize := int64(len(entry.URL))

	// Approximate struct overhead: 4 pointers + 2 time.Time (24 bytes each) + string header + LRUNode
	structOverhead := int64(4*8 + 2*24 + 16 + 8) // ~120 bytes

	return dataSize + urlSize + structOverhead
}

// isFresh checks if the cached CRL is still fresh and valid for use.
//
// A CRL is considered fresh when both conditions are satisfied:
//  1. NextUpdate time is in the future (with 1 hour grace period for clock skew)
//  2. CRL was fetched within the last 24 hours (ensuring reasonable freshness)
//
// This dual validation prevents using stale CRLs while allowing appropriate
// cache reuse within the CRL's validity period. The grace periods account for
// network delays and clock synchronization issues.
//
// Returns:
//   - bool: true if the CRL is fresh and can be used, false otherwise
func (entry *CRLCacheEntry) isFresh() bool {
	now := time.Now()
	// CRL is fresh if NextUpdate is in the future (with 1 hour grace period)
	// and we fetched it within the last 24 hours
	return entry.NextUpdate.After(now.Add(-1*time.Hour)) && entry.FetchedAt.After(now.Add(-24*time.Hour))
}

// isExpired checks if the CRL has expired and should be cleaned up.
//
// A CRL is considered expired when its NextUpdate time has passed, with a
// 1 hour grace period to account for clock skew and network delays. Expired
// CRLs are removed during cleanup operations to prevent cache bloat and
// ensure revocation checking accuracy.
//
// Returns:
//   - bool: true if the CRL has expired and should be removed, false otherwise
func (entry *CRLCacheEntry) isExpired() bool {
	now := time.Now()
	// CRL is expired if NextUpdate has passed (with 1 hour grace period)
	return entry.NextUpdate.Before(now.Add(-1 * time.Hour))
}

// CRLCacheConfig holds configuration for CRL cache.
//
// It defines the operational parameters for the cache including size limits
// and cleanup intervals. These settings control memory usage and maintenance
// behavior of the CRL cache.
//
// Fields:
//   - MaxSize: Maximum number of CRLs to cache (0 = unlimited, but not recommended)
//   - CleanupInterval: How often to run cleanup of expired CRLs
type CRLCacheConfig struct {
	// MaxSize: Maximum number of CRL entries to cache (0 = unlimited, but not recommended)
	MaxSize int
	// CleanupInterval: How often to run cleanup of expired CRLs (default: 1 hour)
	CleanupInterval time.Duration
}

// CRLCacheMetrics tracks cache performance and usage statistics.
//
// It provides comprehensive metrics for monitoring cache efficiency,
// memory usage, and operational health. All counters are atomic for
// thread-safe access.
//
// Fields:
//   - Size: Current number of cached CRL entries
//   - Hits: Number of successful cache retrievals
//   - Misses: Number of cache misses requiring network fetches
//   - Evictions: Number of LRU evictions due to size limits
//   - Cleanups: Number of expired CRL cleanups performed
//   - TotalMemory: Approximate memory usage in bytes for all cached CRLs
type CRLCacheMetrics struct {
	// Size: Current number of CRL entries in the cache
	Size int64
	// Hits: Number of successful cache retrievals (performance metric)
	Hits int64
	// Misses: Number of cache misses requiring network fetches (performance metric)
	Misses int64
	// Evictions: Number of LRU evictions due to size limits
	Evictions int64
	// Cleanups: Number of expired CRL entries removed during cleanup
	Cleanups int64
	// TotalMemory: Approximate memory usage in bytes for all cached CRL data
	TotalMemory int64
}

// crlCacheCounters holds atomic counters for thread-safe metrics tracking.
//
// It provides lock-free access to cache performance statistics, allowing
// concurrent goroutines to increment counters without synchronization overhead.
// Each field uses atomic.Int64 for safe concurrent updates across multiple
// goroutine accesses during cache operations.
type crlCacheCounters struct {
	// Hits: Atomic counter for cache hit operations
	Hits atomic.Int64
	// Misses: Atomic counter for cache miss operations
	Misses atomic.Int64
	// Evictions: Atomic counter for LRU eviction operations
	Evictions atomic.Int64
	// Cleanups: Atomic counter for expired CRL cleanup operations
	Cleanups atomic.Int64
}

// crlCache is the global CRL cache instance.
var crlCache = newCRLCache()

// Default CRL cache configuration
var defaultCRLCacheConfig = CRLCacheConfig{
	MaxSize:         100,
	CleanupInterval: 1 * time.Hour,
}

// CRLCache implements an O(1) LRU cache for Certificate Revocation Lists.
//
// It provides thread-safe operations for storing, retrieving, and managing
// CRLs with automatic expiration and size limits. The implementation uses
// a hashmap for O(1) lookups combined with a doubly-linked list for O(1)
// LRU eviction and access order maintenance.
//
// The cache automatically cleans up expired CRLs based on their NextUpdate
// field and enforces size limits through LRU eviction. All operations are
// thread-safe using RWMutex for optimal concurrent access patterns.
//
// Key Features:
//   - O(1) get, set, and eviction operations
//   - Automatic expiration based on CRL NextUpdate field
//   - Configurable size limits with LRU eviction
//   - Background cleanup of expired entries
//   - Comprehensive metrics and statistics
//   - Thread-safe concurrent access
//
// Fields:
//   - sync.RWMutex: Protects concurrent access with read/write locking
//   - entries: Hashmap for O(1) CRL lookups by URL
//   - head: LRU list head (least recently used)
//   - tail: LRU list tail (most recently used)
//   - config: Atomic configuration storage
//   - stats: Atomic performance counters
//   - cleanupRunning: Atomic flag for cleanup goroutine management
//   - cleanupCancelMu: Mutex protecting cleanup cancellation
//   - cleanupCancel: Context cancellation function for cleanup goroutine
type CRLCache struct {
	// RWMutex: Protects concurrent access with read/write locking for optimal performance
	sync.RWMutex
	// entries: Hashmap for O(1) CRL lookups by URL (cache key -> entry)
	entries map[string]*CRLCacheEntry
	// head: LRU list head (least recently used node) for eviction decisions
	head *LRUNode
	// tail: LRU list tail (most recently used node) for access order updates
	tail *LRUNode
	// config: Atomic configuration storage for thread-safe config access
	config atomic.Value
	// stats: Atomic performance counters for metrics tracking
	stats crlCacheCounters
	// cleanupRunning: Atomic flag ensuring only one cleanup goroutine runs
	cleanupRunning int32
	// cleanupCancelMu: Mutex protecting cleanup cancellation operations
	cleanupCancelMu sync.Mutex
	// cleanupCancel: Context cancellation function for stopping cleanup goroutine
	cleanupCancel context.CancelFunc
}

// newCRLCache creates a new CRL cache instance with default configuration.
//
// It initializes a CRLCache with an empty entries map and applies the default
// configuration settings. This is an internal constructor used to create
// the global cache instance.
//
// Returns:
//   - *CRLCache: Newly initialized CRL cache ready for use
func newCRLCache() *CRLCache {
	cache := &CRLCache{
		entries: make(map[string]*CRLCacheEntry),
	}
	cache.config.Store(&defaultCRLCacheConfig)
	return cache
}

// setConfig sets the cache configuration and triggers pruning if needed.
//
// It validates and applies the new configuration, potentially triggering
// immediate pruning if the new max size is smaller than the current cache size.
// The configuration is stored atomically to ensure thread-safe access.
//
// Parameters:
//   - config: New configuration options (nil uses defaults)
//
// Thread Safety: Must be called with appropriate locking by caller.
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
//
// It safely retrieves the current cache configuration without exposing
// the internal atomic storage. The returned copy prevents external
// modification of the cached settings.
//
// Returns:
//   - *CRLCacheConfig: Copy of current configuration for safe external access
//
// Thread Safety: Safe for concurrent use.
func (c *CRLCache) getConfig() *CRLCacheConfig {
	config := c.config.Load().(*CRLCacheConfig)
	return &CRLCacheConfig{
		MaxSize:         config.MaxSize,
		CleanupInterval: config.CleanupInterval,
	}
}

// getMetrics returns current cache metrics with calculated memory usage.
//
// It calculates total memory usage on demand by summing all cache entries,
// and reads all atomic counters to provide a consistent snapshot of cache
// performance and usage statistics.
//
// Returns:
//   - CRLCacheMetrics: Snapshot of current metrics including size, hits, misses,
//     evictions, cleanups, and calculated memory usage
//
// Thread Safety: Safe for concurrent use (uses read lock).
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
//
// It inserts the node at the end of the doubly-linked LRU list, updating
// both head and tail pointers as necessary. This marks the node as the
// most recently used entry.
//
// Parameters:
//   - node: LRU node to add to the tail of the list
//
// Thread Safety: Caller must hold write lock.
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
//
// It removes the node from its current position in the LRU list and
// reinserts it at the tail, marking it as the most recently used entry.
// If the node is already at the tail, no operation is performed.
//
// Parameters:
//   - node: LRU node to move to the tail
//
// Thread Safety: Caller must hold write lock.
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

// removeFromList removes a node from the LRU linked list.
//
// It safely removes the node from the doubly-linked list, updating
// the previous and next node pointers as well as the head and tail
// pointers if necessary.
//
// Parameters:
//   - node: LRU node to remove from the list
//
// Thread Safety: Caller must hold write lock.
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

// removeOldest removes the least recently used entry (head of LRU list).
//
// It removes the head node from the LRU list (least recently used),
// updates the list pointers, and removes the corresponding entry from
// the cache map. This is called during LRU eviction when the cache
// exceeds its maximum size.
//
// Thread Safety: Caller must hold write lock.
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
//
// It removes the least recently used entries until the cache size
// is within the specified maximum. If maxSize is 0 or negative,
// no pruning is performed (unlimited cache).
//
// Parameters:
//   - maxSize: Maximum number of entries allowed in cache
//
// Thread Safety: Caller must hold write lock.
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

// evictLRUEntries evicts LRU entries to make room for new entries if needed.
//
// It removes the least recently used entries until the cache size is
// below the maximum allowed size, making room for new cache entries.
// If maxSize is 0 or negative, no eviction is performed.
//
// Parameters:
//   - maxSize: Maximum number of entries allowed in cache
//
// Thread Safety: Caller must hold write lock.
func (c *CRLCache) evictLRUEntries(maxSize int) {
	for len(c.entries) >= maxSize && maxSize > 0 {
		if c.head == nil {
			break // No more entries to evict
		}
		c.removeOldest()
	}
}

// createNewCacheEntry creates a new cache entry and adds it to the LRU list.
//
// It creates a new CRLCacheEntry with the provided data, adds it to the
// cache map, creates an LRU node, and places the node at the tail of the
// LRU list (marking it as most recently used).
//
// Parameters:
//   - url: CRL source URL (used as cache key)
//   - data: Raw CRL data bytes
//   - nextUpdate: CRL expiration time from NextUpdate field
//
// Thread Safety: Caller must hold write lock.
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
//
// It performs a two-phase cleanup: first collecting expired URLs without
// holding locks, then removing them with minimal lock contention. This
// approach minimizes lock duration while ensuring consistency.
//
// Only CRLs that have passed their NextUpdate time (with grace period)
// are removed. The operation updates cleanup metrics atomically.
//
// Thread Safety: Safe for concurrent use (uses minimal locking).
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
//
// It checks if a CRL exists for the given URL and is still fresh (not expired
// and recently fetched). If found, it moves the entry to the tail of the LRU
// list (marking as recently used) and returns a copy of the data to prevent
// external modification.
//
// Parameters:
//   - url: CRL source URL to look up in cache
//
// Returns:
//   - []byte: Raw CRL data if found and fresh, nil otherwise
//   - bool: true if found and fresh, false otherwise
//
// Thread Safety: Safe for concurrent use.
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
//
// It validates the CRL data and metadata before caching, handles LRU eviction
// if the cache is full, and stores the CRL. If an entry already exists for
// the URL, it updates the existing entry and moves it to the tail of the LRU list.
//
// Parameters:
//   - url: CRL source URL (used as cache key)
//   - data: Raw CRL data bytes
//   - nextUpdate: CRL expiration time from NextUpdate field
//
// Returns:
//   - error: Validation error if data is invalid, nil on success
//
// Thread Safety: Safe for concurrent use.
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

// clear clears all cached CRLs and resets metrics (useful for testing).
//
// It removes all entries from the cache map, resets the LRU list pointers,
// and resets all performance metrics to zero. This operation is primarily
// intended for testing scenarios where cache state needs complete reset.
//
// Thread Safety: Safe for concurrent use.
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

// startCleanup starts background cleanup goroutine with context cancellation.
//
// It ensures only one cleanup goroutine is running at a time using atomic
// operations. The goroutine periodically removes expired CRLs based on the
// configured cleanup interval and adapts to configuration changes dynamically.
//
// The cleanup process runs in the background and can be cancelled via context.
// If the context is already cancelled when called, no goroutine is started.
//
// Parameters:
//   - ctx: Context for lifecycle management and cancellation
//
// Thread Safety: Safe for concurrent use.
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
//
// It cancels the context associated with the cleanup goroutine and waits
// for proper cleanup. If no cleanup goroutine is running, this is a no-op.
// The operation ensures graceful shutdown of background cleanup processes.
//
// Thread Safety: Safe for concurrent use.
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
//
// It retrieves current metrics, configuration, and performance data,
// then formats them into a human-readable string suitable for logging
// or monitoring. The output includes cache size, memory usage, hit rate,
// eviction counts, and cleanup statistics.
//
// Returns:
//   - string: Formatted statistics string with cache performance metrics
//
// Thread Safety: Safe for concurrent use.
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

// init initializes the global CRL cache with default configuration.
//
// This package-level init function is called automatically when the package
// is loaded, ensuring the global CRL cache is ready for use with default settings.
// It applies the default configuration (100 max entries, 1 hour cleanup interval).
//
// Thread Safety: Called during package initialization, before any concurrent access.
func init() { crlCache.setConfig(&defaultCRLCacheConfig) }

// SetCRLCacheConfig sets CRL cache configuration.
//
// It validates and applies the new configuration, potentially triggering
// immediate pruning if the new max size is smaller than current cache size.
// The configuration is stored atomically to ensure thread-safe access.
//
// Parameters:
//   - config: New configuration options (nil uses defaults)
//
// Thread Safety: Safe for concurrent use.
func SetCRLCacheConfig(config *CRLCacheConfig) { crlCache.setConfig(config) }

// GetCRLCacheConfig returns current CRL cache configuration.
//
// It returns a copy of the current configuration to prevent external
// modification of the cached settings.
//
// Returns:
//   - *CRLCacheConfig: Copy of current configuration
//
// Thread Safety: Safe for concurrent use.
func GetCRLCacheConfig() *CRLCacheConfig { return crlCache.getConfig() }

// GetCRLCacheMetrics returns current cache metrics.
//
// It calculates total memory usage on demand and reads all atomic counters
// to provide a consistent snapshot of cache performance and usage.
//
// Returns:
//   - CRLCacheMetrics: Snapshot of current metrics including size, hits, misses, and memory usage
//
// Thread Safety: Safe for concurrent use.
func GetCRLCacheMetrics() CRLCacheMetrics { return crlCache.getMetrics() }

// StartCRLCacheCleanup starts background cleanup goroutine with context for cancellation.
//
// It ensures only one cleanup goroutine is running at a time using atomic operations.
// The goroutine periodically removes expired CRLs based on the configured cleanup interval
// and adapts to configuration changes dynamically.
//
// The cleanup process runs in the background and can be cancelled via context.
// If the context is already cancelled when called, no goroutine is started.
//
// Parameters:
//   - ctx: Context for lifecycle management and cancellation
//
// Thread Safety: Safe for concurrent use.
func StartCRLCacheCleanup(ctx context.Context) { crlCache.startCleanup(ctx) }

// StopCRLCacheCleanup stops the running cleanup goroutine if any.
//
// It cancels the context associated with the cleanup goroutine and waits
// for proper cleanup. If no cleanup goroutine is running, this is a no-op.
//
// Thread Safety: Safe for concurrent use.
func StopCRLCacheCleanup() { crlCache.stopCleanup() }

// GetCachedCRL retrieves a fresh CRL from cache and updates access order.
//
// It checks if the CRL exists and is fresh (not expired and recently fetched).
// If found, it moves the entry to the tail of the LRU list (marking as recently used)
// and returns a copy of the data to prevent external modification.
//
// Parameters:
//   - url: URL of the CRL to retrieve
//
// Returns:
//   - []byte: Raw CRL data if found and fresh, nil otherwise
//   - bool: true if found and fresh, false otherwise
//
// Thread Safety: Safe for concurrent use.
func GetCachedCRL(url string) ([]byte, bool) { return crlCache.get(url) }

// validateCRLData validates CRL data and metadata before caching.
//
// It performs comprehensive validation to ensure only valid, reasonable CRLs
// are cached. The validation includes:
//
//   - Data integrity: Non-empty CRL data
//   - URL validation: Non-empty source URL
//   - Timestamp sanity: NextUpdate time within reasonable bounds (not too far past/future)
//
// This prevents caching obviously corrupted or malicious CRL data while
// allowing legitimate CRLs with reasonable validity periods.
//
// Parameters:
//   - url: Source URL of the CRL
//   - data: Raw CRL data bytes
//   - nextUpdate: Expiration time from CRL.NextUpdate field
//
// Returns:
//   - error: Validation error if any check fails, nil if valid
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
// It validates the CRL data and metadata before caching, handles LRU eviction
// if the cache is full, and updates the cache. If an entry already exists for
// the URL, it updates the existing entry and moves it to the tail of the LRU list.
//
// The function performs comprehensive validation including data integrity checks,
// URL validation, and reasonable timestamp validation to prevent caching
// obviously invalid CRLs.
//
// Parameters:
//   - url: Source URL of the CRL (used as cache key)
//   - data: Raw CRL data bytes
//   - nextUpdate: Expiration time from CRL.NextUpdate field
//
// Returns:
//   - error: Error if validation fails or caching operation fails
//
// Thread Safety: Safe for concurrent use.
func SetCachedCRL(url string, data []byte, nextUpdate time.Time) error {
	return crlCache.set(url, data, nextUpdate)
}

// ClearCRLCache clears all cached CRLs (useful for testing).
//
// It resets the cache map, LRU linked list, and all performance metrics.
// This operation is primarily intended for testing scenarios where
// cache state needs to be completely reset.
//
// Thread Safety: Safe for concurrent use.
func ClearCRLCache() { crlCache.clear() }

// CleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time.
//
// It performs a two-phase cleanup: first collecting expired URLs without holding
// locks, then removing them with minimal lock contention. This approach minimizes
// the time locks are held while ensuring consistency.
//
// Only CRLs that have passed their NextUpdate time (with grace period) are removed.
// The operation updates cleanup metrics atomically.
//
// Thread Safety: Safe for concurrent use.
func CleanupExpiredCRLs() { crlCache.cleanupExpiredCRLs() }

// GetCRLCacheStats returns a formatted string with cache statistics.
//
// It formats current metrics, configuration, and performance data into a
// human-readable string suitable for logging or monitoring. The output includes
// cache size, memory usage, hit rate, eviction counts, and cleanup statistics.
//
// Returns:
//   - string: Formatted statistics string with cache performance metrics
//
// Thread Safety: Safe for concurrent use.
func GetCRLCacheStats() string { return crlCache.getStats() }
