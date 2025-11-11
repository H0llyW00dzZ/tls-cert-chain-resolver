// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// ResourceUsageData represents the complete resource usage information
type ResourceUsageData struct {
	Timestamp      string         `json:"timestamp"`
	MemoryUsage    map[string]any `json:"memory_usage"`
	GCStats        map[string]any `json:"gc_stats"`
	SystemInfo     map[string]any `json:"system_info"`
	DetailedMemory map[string]any `json:"detailed_memory,omitempty"`
	CRLCache       map[string]any `json:"crl_cache,omitempty"`
}

// CollectResourceUsage gathers current resource usage statistics
func CollectResourceUsage(detailed bool) *ResourceUsageData {
	// Get memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get GC statistics
	gcStats := map[string]any{
		"num_gc":          memStats.NumGC,
		"num_forced_gc":   memStats.NumForcedGC,
		"gc_cpu_fraction": memStats.GCCPUFraction,
		"enable_gc":       memStats.EnableGC,
		"debug_gc":        memStats.DebugGC,
	}

	// Memory usage in MB
	memoryUsage := map[string]any{
		"heap_alloc_mb":    float64(memStats.HeapAlloc) / (1024 * 1024),
		"heap_sys_mb":      float64(memStats.HeapSys) / (1024 * 1024),
		"heap_idle_mb":     float64(memStats.HeapIdle) / (1024 * 1024),
		"heap_inuse_mb":    float64(memStats.HeapInuse) / (1024 * 1024),
		"heap_released_mb": float64(memStats.HeapReleased) / (1024 * 1024),
		"heap_objects":     memStats.HeapObjects,
		"stack_inuse_mb":   float64(memStats.StackInuse) / (1024 * 1024),
		"stack_sys_mb":     float64(memStats.StackSys) / (1024 * 1024),
		"gc_cpu_fraction":  memStats.GCCPUFraction,
	}

	// System info
	systemInfo := map[string]any{
		"go_version":    runtime.Version(),
		"go_os":         runtime.GOOS,
		"go_arch":       runtime.GOARCH,
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}

	data := &ResourceUsageData{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		MemoryUsage: memoryUsage,
		GCStats:     gcStats,
		SystemInfo:  systemInfo,
	}

	// Add detailed breakdown if requested
	if detailed {
		// Additional detailed memory stats
		detailedMemory := map[string]any{
			"alloc_mb":          float64(memStats.Alloc) / (1024 * 1024),
			"total_alloc_mb":    float64(memStats.TotalAlloc) / (1024 * 1024),
			"sys_mb":            float64(memStats.Sys) / (1024 * 1024),
			"lookups":           memStats.Lookups,
			"mallocs":           memStats.Mallocs,
			"frees":             memStats.Frees,
			"heap_live_objects": memStats.HeapObjects,
			"gc_pause_total_ns": memStats.PauseTotalNs,
			"gc_pause_ns":       memStats.PauseNs[:memStats.NumGC],
			"next_gc_mb":        float64(memStats.NextGC) / (1024 * 1024),
			"last_gc_ns":        memStats.LastGC,
		}
		data.DetailedMemory = detailedMemory

		// CRL cache metrics
		cacheMetrics := x509chain.GetCRLCacheMetrics()
		cacheConfig := x509chain.GetCRLCacheConfig()
		data.CRLCache = map[string]any{
			"size":             cacheMetrics.Size,
			"max_size":         cacheConfig.MaxSize,
			"total_memory_mb":  float64(cacheMetrics.TotalMemory) / (1024 * 1024),
			"hits":             cacheMetrics.Hits,
			"misses":           cacheMetrics.Misses,
			"evictions":        cacheMetrics.Evictions,
			"cleanups":         cacheMetrics.Cleanups,
			"hit_rate_percent": calculateHitRate(cacheMetrics.Hits, cacheMetrics.Misses),
		}
	}

	return data
}

// FormatResourceUsageAsJSON formats resource usage data as JSON
func FormatResourceUsageAsJSON(data *ResourceUsageData) (string, error) {
	response := map[string]any{
		"timestamp":    data.Timestamp,
		"memory_usage": data.MemoryUsage,
		"gc_stats":     data.GCStats,
		"system_info":  data.SystemInfo,
	}

	if data.DetailedMemory != nil {
		response["detailed_memory"] = data.DetailedMemory
	}

	if data.CRLCache != nil {
		response["crl_cache"] = data.CRLCache
	}

	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal resource usage: %w", err)
	}

	return string(jsonData), nil
}

// FormatResourceUsageAsMarkdown formats resource usage data as a readable markdown table
func FormatResourceUsageAsMarkdown(data *ResourceUsageData) string {
	var buf strings.Builder

	// Add header
	formatMarkdownHeader(&buf, data.Timestamp)

	// Add system information
	formatSystemInfoSection(&buf, data.SystemInfo)

	// Add memory usage
	formatMemoryUsageSection(&buf, data.MemoryUsage)

	// Add garbage collection stats
	formatGCStatsSection(&buf, data.GCStats)

	// Add detailed sections if available
	if data.DetailedMemory != nil || data.CRLCache != nil {
		formatDetailedSections(&buf, data)
	}

	return buf.String()
}

// formatMarkdownHeader adds the report header with timestamp
func formatMarkdownHeader(buf *strings.Builder, timestamp string) {
	fmt.Fprintf(buf, "# %s Resource Usage Report (v%s)\n\n", "X.509 Certificate Chain Resolver", version.Version)

	// Parse RFC3339 timestamp and format as human-readable
	if parsedTime, err := time.Parse(time.RFC3339, timestamp); err == nil {
		humanTime := parsedTime.Format("January 2, 2006 at 3:04 PM MST")
		fmt.Fprintf(buf, "**Generated:** %s\n\n", humanTime)
	} else {
		// Fallback to original timestamp if parsing fails
		fmt.Fprintf(buf, "**Generated:** %s\n\n", timestamp)
	}
}

// formatSystemInfoSection adds the system information section
func formatSystemInfoSection(buf *strings.Builder, systemInfo map[string]any) {
	buf.WriteString("## System Information\n\n")
	systemFields := []string{
		"Go Version       ", "go_version",
		"Operating System ", "go_os",
		"Architecture     ", "go_arch",
		"CPU Count        ", "num_cpu",
		"Goroutines       ", "num_goroutine",
	}
	buf.WriteString(formatMarkdownTable(systemInfo, systemFields))
}

// formatMemoryUsageSection adds the memory usage section
func formatMemoryUsageSection(buf *strings.Builder, memoryUsage map[string]any) {
	buf.WriteString("## Memory Usage\n\n")
	memoryFields := []string{
		"Heap Allocated ", "heap_alloc_mb",
		"Heap System    ", "heap_sys_mb",
		"Heap In Use    ", "heap_inuse_mb",
		"Heap Idle      ", "heap_idle_mb",
		"Heap Released  ", "heap_released_mb",
		"Heap Objects   ", "heap_objects",
		"Stack In Use   ", "stack_inuse_mb",
		"Stack System   ", "stack_sys_mb",
	}
	buf.WriteString(formatMarkdownTable(memoryUsage, memoryFields))
}

// formatGCStatsSection adds the garbage collection section
func formatGCStatsSection(buf *strings.Builder, gcStats map[string]any) {
	buf.WriteString("## Garbage Collection\n\n")
	gcFields := []string{
		"GC Cycles      ", "num_gc",
		"Forced GC      ", "num_forced_gc",
		"GC CPU Fraction", "gc_cpu_fraction",
		"GC Enabled     ", "enable_gc",
		"Debug GC       ", "debug_gc",
	}
	buf.WriteString(formatMarkdownTable(gcStats, gcFields))
}

// formatDetailedSections adds detailed memory and cache sections
func formatDetailedSections(buf *strings.Builder, data *ResourceUsageData) {
	// Detailed Memory Statistics
	if data.DetailedMemory != nil {
		buf.WriteString("## Detailed Memory Statistics\n\n")
		detailedFields := []string{
			"Current Alloc  ", "alloc_mb",
			"Total Alloc    ", "total_alloc_mb",
			"System Memory  ", "sys_mb",
			"Lookups        ", "lookups",
			"Mallocs        ", "mallocs",
			"Frees          ", "frees",
			"Live Objects   ", "heap_live_objects",
			"GC Pause Total ", "gc_pause_total_ns",
			"Next GC        ", "next_gc_mb",
			"Last GC        ", "last_gc_ns",
		}
		buf.WriteString(formatMarkdownTable(data.DetailedMemory, detailedFields))
	}

	// CRL Cache Metrics
	if data.CRLCache != nil {
		buf.WriteString("## CRL Cache Metrics\n\n")
		cacheFields := []string{
			"Cache Size   ", "size",
			"Max Size     ", "max_size",
			"Total Memory ", "total_memory_mb",
			"Cache Hits   ", "hits",
			"Cache Misses ", "misses",
			"Evictions    ", "evictions",
			"Cleanups     ", "cleanups",
			"Hit Rate     ", "hit_rate_percent",
		}
		buf.WriteString(formatMarkdownTable(data.CRLCache, cacheFields))
	}
}

// formatMarkdownTable creates a markdown table using tablewriter library
func formatMarkdownTable(data map[string]any, fieldPairs []string) string {
	var buf strings.Builder

	// Prepare data rows - no emojis in data, only in headers
	var rows [][]string
	for i := 0; i < len(fieldPairs); i += 2 {
		if i+1 >= len(fieldPairs) {
			break
		}

		label := fieldPairs[i]
		key := fieldPairs[i+1]

		if value, ok := data[key]; ok {
			formattedValue := formatValueForMarkdown(value, key)
			rows = append(rows, []string{label, formattedValue})
		}
	}

	// Create table with emoji headers only
	table := tablewriter.NewTable(&buf,
		tablewriter.WithRenderer(renderer.NewMarkdown(tw.Rendition{Streaming: true})),
	)

	table.Header([]string{"📊 METRIC", "📈 VALUE"})
	table.Bulk(rows)
	table.Render()

	// Add trailing newline for better markdown formatting
	buf.WriteString("\n")
	return buf.String()
}

// formatValueForMarkdown formats a value for markdown display
func formatValueForMarkdown(value any, key string) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		if key == "size" || key == "max_size" {
			return fmt.Sprintf("%d entries", v)
		}
		return fmt.Sprintf("%d", v)
	case uint32:
		return fmt.Sprintf("%d", v)
	case uint64:
		if key == "pause_total_ns" {
			return fmt.Sprintf("%.2f", float64(v)/1e6)
		}
		if key == "last_gc_ns" {
			if v == 0 {
				return "Never"
			}
			gcTime := time.Unix(0, int64(v))
			return gcTime.Format("2006-01-02 15:04:05")
		}
		return fmt.Sprintf("%d", v)
	case float64:
		if key == "gc_cpu_fraction" || key == "hit_rate_percent" {
			return fmt.Sprintf("%.2f%%", v)
		}
		if strings.Contains(key, "mb") || strings.Contains(key, "memory") {
			return fmt.Sprintf("%.2f MB", v)
		}
		return fmt.Sprintf("%.2f", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// calculateHitRate calculates the cache hit rate as a percentage
func calculateHitRate(hits, misses int64) float64 {
	total := hits + misses
	if total == 0 {
		return 0.0
	}
	return float64(hits) / float64(total) * 100.0
}
