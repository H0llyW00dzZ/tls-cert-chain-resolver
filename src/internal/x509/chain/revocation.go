// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
	"golang.org/x/crypto/ocsp"
)

// RevocationStatus represents revocation status of a certificate
type RevocationStatus struct {
	OCSPStatus   string
	CRLStatus    string
	SerialNumber string
}

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
var defaultCRLCacheConfig = &CRLCacheConfig{
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
	crlCacheConfig.Store(defaultCRLCacheConfig)
	startCRLCacheCleanup()
}

// SetCRLCacheConfig sets the CRL cache configuration
func SetCRLCacheConfig(config *CRLCacheConfig) {
	if config == nil {
		config = defaultCRLCacheConfig
	}

	// Validate configuration
	if config.MaxSize < 0 {
		config.MaxSize = 0 // 0 means unlimited, but not recommended
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 1 * time.Hour
	}

	crlCacheConfig.Store(config)
}

// GetCRLCacheConfig returns the current CRL cache configuration
func GetCRLCacheConfig() *CRLCacheConfig {
	return crlCacheConfig.Load().(*CRLCacheConfig)
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

// getCachedCRL retrieves a fresh CRL from cache and updates access order
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

// setCachedCRL stores a CRL in cache with metadata and implements LRU eviction
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

// ParseCRLResponse parses a CRL response to extract status for a specific certificate
func ParseCRLResponse(crlData []byte, certSerial *big.Int, issuer *x509.Certificate) (string, error) {
	if len(crlData) == 0 {
		return "Unknown", fmt.Errorf("empty CRL data")
	}

	if certSerial == nil {
		return "Unknown", fmt.Errorf("certificate serial number is nil")
	}

	if issuer == nil {
		return "Unknown", fmt.Errorf("issuer certificate is nil")
	}

	var lastErr error
	data := crlData

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if strings.Contains(block.Type, "CRL") {
			status, err := parseCRLBlock(block.Bytes, certSerial, issuer)
			if err != nil {
				lastErr = err
			} else {
				return status, nil
			}
		}

		if len(rest) == 0 {
			break
		}
		data = rest
	}

	status, err := parseCRLBlock(crlData, certSerial, issuer)
	if err == nil {
		return status, nil
	}

	if lastErr != nil {
		return "Unknown", lastErr
	}

	return "Unknown", err
}

func parseCRLBlock(der []byte, certSerial *big.Int, issuer *x509.Certificate) (string, error) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return "Unknown", fmt.Errorf("failed to parse CRL data: %w", err)
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return "Unknown", fmt.Errorf("invalid CRL signature: %w", err)
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber != nil && revoked.SerialNumber.Cmp(certSerial) == 0 {
			return "Revoked", nil
		}
	}

	return "Good", nil
}

// checkOCSPStatus performs OCSP check for revocation status, trying all available OCSP servers
func (ch *Chain) checkOCSPStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {
	if len(cert.OCSPServer) == 0 {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Not Available (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, nil
	}

	// Find the issuer certificate
	issuer := ch.findIssuerForCertificate(cert)
	if issuer == nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("could not find issuer certificate for OCSP request")
	}

	// Try all OCSP servers until one succeeds
	var lastErr error
	var failedServers []string
	for _, ocspURL := range cert.OCSPServer {
		status, err := ch.tryOCSPServer(ctx, cert, issuer, ocspURL)
		if err == nil {
			return status, nil
		}
		failedServers = append(failedServers, ocspURL)
		lastErr = err
	}

	// All OCSP servers failed
	return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("all OCSP servers failed for certificate serial %s (failed servers: %s): %w", cert.SerialNumber.String(), strings.Join(failedServers, ", "), lastErr)
}

// tryOCSPServer attempts OCSP check against a specific OCSP server
func (ch *Chain) tryOCSPServer(ctx context.Context, cert, issuer *x509.Certificate, ocspURL string) (*RevocationStatus, error) {
	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Create HTTP POST request with OCSP data
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to create OCSP HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	resp, err := ch.HTTPConfig.Client().Do(req)
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("OCSP request to %s failed: %w", ocspURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("OCSP server %s returned HTTP %d", ocspURL, resp.StatusCode)
	}

	// Read OCSP response
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset the buffer to prevent data leaks
		gc.Default.Put(buf) // Return the buffer to the pool for reuse
	}()

	// Read the response body into the buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspRespData := buf.Bytes()

	// Parse OCSP response
	ocspResp, err := ocsp.ParseResponseForCert(ocspRespData, cert, issuer)
	if err != nil {
		return &RevocationStatus{OCSPStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to parse OCSP response from %s: %w", ocspURL, err)
	}

	// Convert OCSP status to our format
	var status string
	switch ocspResp.Status {
	case ocsp.Good:
		status = "Good"
	case ocsp.Revoked:
		status = "Revoked"
	case ocsp.Unknown:
		status = "Unknown"
	default:
		status = "Unknown"
	}

	return &RevocationStatus{
		OCSPStatus:   fmt.Sprintf("%s (Serial: %s)", status, cert.SerialNumber.String()),
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// checkCRLStatus performs a CRL check for revocation status, trying all available distribution points
func (ch *Chain) checkCRLStatus(ctx context.Context, cert *x509.Certificate) (*RevocationStatus, error) {

	if len(cert.CRLDistributionPoints) == 0 {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Not Available (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, nil
	}

	// Try all CRL distribution points until one succeeds
	var lastErr error
	var failedPoints []string
	for _, crlURL := range cert.CRLDistributionPoints {
		status, err := ch.tryCRLDistributionPoint(ctx, cert, crlURL)
		if err == nil {
			return status, nil
		}
		failedPoints = append(failedPoints, crlURL)
		lastErr = err
	}

	// All CRL distribution points failed
	return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("all CRL distribution points failed for certificate serial %s (failed points: %s): %w", cert.SerialNumber.String(), strings.Join(failedPoints, ", "), lastErr)
}

// tryCRLDistributionPoint attempts CRL check against a specific distribution point with caching
func (ch *Chain) tryCRLDistributionPoint(ctx context.Context, cert *x509.Certificate, crlURL string) (*RevocationStatus, error) {
	// Check cache first
	if cachedData, found := GetCachedCRL(crlURL); found {
		// Use cached CRL data
		return ch.processCRLData(cachedData, cert)
	}

	// Fetch CRL from network
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to create CRL request: %w", err)
	}
	req.Header.Set("User-Agent", ch.HTTPConfig.GetUserAgent())

	resp, err := ch.HTTPConfig.Client().Do(req)
	if err != nil {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("CRL request to %s failed: %w", crlURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("CRL server %s returned HTTP %d", crlURL, resp.StatusCode)
	}

	// Read CRL data
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset the buffer to prevent data leaks
		gc.Default.Put(buf) // Return the buffer to the pool for reuse
	}()

	// Read the response body into the buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("failed to read CRL: %w", err)
	}

	crlData := buf.Bytes()

	// Parse CRL to extract NextUpdate for caching
	crl, parseErr := x509.ParseRevocationList(crlData)
	if parseErr == nil && !crl.NextUpdate.IsZero() {
		// Cache the CRL with its next update time
		SetCachedCRL(crlURL, crlData, crl.NextUpdate)
	}

	// Process the CRL data
	return ch.processCRLData(crlData, cert)
}

// processCRLData processes CRL data and checks revocation status
func (ch *Chain) processCRLData(crlData []byte, cert *x509.Certificate) (*RevocationStatus, error) {
	// Try to find issuer certificate for CRL signature verification
	issuer := ch.findIssuerForCertificate(cert)
	if issuer != nil {
		// Try verified CRL parsing first
		status, err := ParseCRLResponse(crlData, cert.SerialNumber, issuer)
		if err == nil {
			return &RevocationStatus{
				CRLStatus:    fmt.Sprintf("%s (Serial: %s)", status, cert.SerialNumber.String()),
				SerialNumber: cert.SerialNumber.String(),
			}, nil
		}
		// If verified parsing fails, continue to try other potential issuers
	}

	// Try all certificates in chain as potential CRL signers
	for _, potentialIssuer := range ch.Certs {
		if potentialIssuer == cert {
			continue // Skip self
		}
		status, err := ParseCRLResponse(crlData, cert.SerialNumber, potentialIssuer)
		if err == nil {
			return &RevocationStatus{
				CRLStatus:    fmt.Sprintf("%s (Serial: %s)", status, cert.SerialNumber.String()),
				SerialNumber: cert.SerialNumber.String(),
			}, nil
		}
	}

	// If all signature verification attempts fail, we cannot trust this CRL
	return &RevocationStatus{CRLStatus: fmt.Sprintf("Unknown (Serial: %s)", cert.SerialNumber.String()), SerialNumber: cert.SerialNumber.String()}, fmt.Errorf("CRL signature verification failed for certificate serial %s (tried all certificates in chain as potential issuers)", cert.SerialNumber.String())
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

// cleanupExpiredCRLs removes CRLs that have expired beyond their NextUpdate time
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

// CheckRevocationStatus performs OCSP/CRL checks for the certificate chain with priority logic
func (ch *Chain) CheckRevocationStatus(ctx context.Context) (string, error) {
	var result strings.Builder
	result.WriteString("Revocation Status Check:\n\n")

	for i, cert := range ch.Certs {
		// Skip ultimate trust anchor; roots aren't revoked via OCSP/CRL
		if i == len(ch.Certs)-1 {
			continue
		}

		result.WriteString(fmt.Sprintf("Certificate %d: %s\n", i+1, cert.Subject.CommonName))

		// Check OCSP first (higher priority)
		ocspStatus, ocspErr := ch.checkOCSPStatus(ctx, cert)
		if ocspErr != nil {
			result.WriteString(fmt.Sprintf("  OCSP Error: %v\n", ocspErr))
		} else {
			result.WriteString(fmt.Sprintf("  OCSP Status: %s\n", ocspStatus.OCSPStatus))

			// If OCSP says revoked, certificate is revoked - no need to check CRL
			if strings.Contains(ocspStatus.OCSPStatus, "Revoked") {
				result.WriteString("  Final Status: REVOKED (via OCSP)\n\n")
				continue
			}

			// If OCSP says good, certificate is good - CRL check not needed
			if strings.Contains(ocspStatus.OCSPStatus, "Good") {
				result.WriteString("  Final Status: GOOD (via OCSP)\n\n")
				continue
			}
		}

		// OCSP is unavailable or unknown, check CRL
		crlStatus, crlErr := ch.checkCRLStatus(ctx, cert)
		if crlErr != nil {
			result.WriteString(fmt.Sprintf("  CRL Error: %v\n", crlErr))
			result.WriteString("  Final Status: UNKNOWN (both OCSP and CRL unavailable)\n")
		} else {
			result.WriteString(fmt.Sprintf("  CRL Status: %s\n", crlStatus.CRLStatus))
			if strings.Contains(crlStatus.CRLStatus, "Revoked") {
				result.WriteString("  Final Status: REVOKED (via CRL)\n")
			} else if strings.Contains(crlStatus.CRLStatus, "Good") {
				result.WriteString("  Final Status: GOOD (via CRL)\n")
			} else {
				result.WriteString("  Final Status: UNKNOWN\n")
			}
		}

		result.WriteString("\n")
	}

	return result.String(), nil
}
