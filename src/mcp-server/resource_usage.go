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

// ResourceUsageData represents the complete resource usage information.
//
// ResourceUsageData contains comprehensive statistics about the MCP server's
// current resource utilization, including memory usage, garbage collection
// metrics, system information, and optionally detailed memory statistics
// and CRL cache metrics.
//
// Fields:
//   - Timestamp: [RFC3339]-formatted timestamp when data was collected
//   - MemoryUsage: Basic memory statistics in MB (heap, stack, etc.)
//   - GCStats: Garbage collection cycle counts and CPU usage
//   - SystemInfo: Go runtime and system information
//   - DetailedMemory: Optional detailed memory statistics (allocations, pauses, etc.)
//   - CRLCache: Optional CRL cache metrics (hits, misses, evictions, etc.)
//
// This struct is used by the get_resource_usage MCP tool to provide
// comprehensive monitoring data for performance analysis and debugging.
//
// [RFC3339]: https://www.rfc-editor.org/rfc/rfc3339.html
type ResourceUsageData struct {
	Timestamp      string         `json:"timestamp"`
	MemoryUsage    map[string]any `json:"memory_usage"`
	GCStats        map[string]any `json:"gc_stats"`
	SystemInfo     map[string]any `json:"system_info"`
	DetailedMemory map[string]any `json:"detailed_memory,omitempty"`
	CRLCache       map[string]any `json:"crl_cache,omitempty"`
}

// CollectResourceUsage gathers current resource usage statistics.
//
// CollectResourceUsage collects comprehensive resource usage data from the
// Go runtime and CRL cache. It provides both basic and detailed statistics
// depending on the detailed parameter.
//
// Parameters:
//   - detailed: If true, includes detailed memory stats and CRL cache metrics
//
// Returns:
//   - *ResourceUsageData: Complete resource usage information
//
// The function collects:
//   - Memory statistics from runtime.ReadMemStats()
//   - System information from runtime package
//   - GC statistics and CPU usage
//   - CRL cache metrics when detailed=true (hits, misses, evictions, etc.)
//
// Memory values are converted to MB for readability, and timestamps
// are formatted as [RFC3339]. CRL cache hit rate is calculated as a percentage.
//
// [RFC3339]: https://www.rfc-editor.org/rfc/rfc3339.html
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

// FormatResourceUsageAsJSON formats resource usage data as JSON.
//
// FormatResourceUsageAsJSON converts ResourceUsageData into a formatted
// JSON string with proper indentation. It includes all available data
// fields based on what was collected.
//
// Parameters:
//   - data: The resource usage data to format
//
// Returns:
//   - string: JSON-formatted resource usage data
//   - error: Formatting error if marshaling fails
//
// The output includes:
//   - timestamp: [RFC3339] timestamp
//   - memory_usage: Basic memory statistics
//   - gc_stats: Garbage collection information
//   - system_info: Go runtime and system details
//   - detailed_memory: Optional detailed memory stats
//   - crl_cache: Optional CRL cache metrics
//
// JSON is formatted with 2-space indentation for readability.
//
// [RFC3339]: https://www.rfc-editor.org/rfc/rfc3339.html
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

// FormatResourceUsageAsMarkdown formats resource usage data as a readable markdown table.
//
// FormatResourceUsageAsMarkdown creates a comprehensive markdown report with
// sections for system information, memory usage, garbage collection stats,
// and optionally detailed memory and CRL cache metrics.
//
// Parameters:
//   - data: The resource usage data to format
//
// Returns:
//   - string: Markdown-formatted resource usage report
//
// The report includes:
//   - Header with timestamp and version information
//   - System Information table (Go version, OS, CPU, goroutines)
//   - Memory Usage table (heap, stack statistics in MB)
//   - Garbage Collection table (cycles, CPU fraction, etc.)
//   - Optional Detailed Memory Statistics
//   - Optional CRL Cache Metrics with hit rate
//
// Tables use emoji headers (📊 METRIC, 📈 VALUE) and are formatted
// using the tablewriter library with markdown renderer.
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

// formatMarkdownHeader adds the report header with timestamp.
//
// formatMarkdownHeader creates the markdown report header including
// the application name, version, and formatted timestamp.
//
// Parameters:
//   - buf: String builder to append header to
//   - timestamp: [RFC3339] timestamp string to format
//
// The header includes:
//   - Title with application name and version
//   - Human-readable timestamp (e.g., "January 2, 2006 at 3:04 PM MST")
//   - Fallback to original timestamp if parsing fails
//
// [RFC3339]: https://www.rfc-editor.org/rfc/rfc3339.html
func formatMarkdownHeader(buf *strings.Builder, timestamp string) {
	fmt.Fprintf(buf, "# %s Resource Usage Report (v%s)\n\n", "X.509 Certificate Chain Resolver", version.Version)

	// Parse [RFC3339] timestamp and format as human-readable
	if parsedTime, err := time.Parse(time.RFC3339, timestamp); err == nil {
		humanTime := parsedTime.Format("January 2, 2006 at 3:04 PM MST")
		fmt.Fprintf(buf, "**Generated:** %s\n\n", humanTime)
	} else {
		// Fallback to original timestamp if parsing fails
		fmt.Fprintf(buf, "**Generated:** %s\n\n", timestamp)
	}
}

// formatSystemInfoSection adds the system information section.
//
// formatSystemInfoSection creates a markdown table section displaying
// Go runtime and system information including version, OS, architecture,
// CPU count, and current goroutine count.
//
// Parameters:
//   - buf: String builder to append section to
//   - systemInfo: Map containing system information data
//
// The section includes a "## System Information" header followed by
// a formatted table with fields like Go version, operating system,
// architecture, CPU count, and number of goroutines.
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

// formatMemoryUsageSection adds the memory usage section.
//
// formatMemoryUsageSection creates a markdown table section displaying
// memory usage statistics including heap allocation, system memory,
// stack usage, and heap object counts.
//
// Parameters:
//   - buf: String builder to append section to
//   - memoryUsage: Map containing memory usage data in MB
//
// The section includes a "## Memory Usage" header followed by
// a formatted table with heap statistics (allocated, system, in use, idle),
// heap objects count, and stack statistics (in use, system).
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

// formatGCStatsSection adds the garbage collection section.
//
// formatGCStatsSection creates a markdown table section displaying
// garbage collection statistics including cycle counts, CPU usage,
// and GC settings.
//
// Parameters:
//   - buf: String builder to append section to
//   - gcStats: Map containing garbage collection statistics
//
// The section includes a "## Garbage Collection" header followed by
// a formatted table with GC cycles, forced GC count, CPU fraction,
// GC enabled status, and debug GC settings.
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

// formatDetailedSections adds detailed memory and cache sections.
//
// formatDetailedSections conditionally adds detailed memory statistics
// and CRL cache metrics sections when detailed data is available.
//
// Parameters:
//   - buf: String builder to append sections to
//   - data: Resource usage data containing optional detailed fields
//
// The function adds:
//   - "## Detailed Memory Statistics" section with allocation details,
//     GC pause times, and next GC threshold
//   - "## CRL Cache Metrics" section with cache size, hit rate,
//     evictions, and memory usage
//
// Both sections are only included if the corresponding data fields
// are populated in the ResourceUsageData.
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

// formatMarkdownTable creates a markdown table using tablewriter library.
//
// formatMarkdownTable generates a markdown-formatted table from key-value data
// using the tablewriter library with emoji headers and proper value formatting.
//
// Parameters:
//   - data: Map containing the data to display
//   - fieldPairs: Slice of label-key pairs (even indices are labels, odd are keys)
//
// Returns:
//   - string: Markdown-formatted table with trailing newline
//
// The table uses:
//   - 📊 METRIC and 📈 VALUE as headers with emojis
//   - Markdown renderer for proper formatting
//   - formatValueForMarkdown for appropriate value display
//   - Bulk data insertion for efficient rendering
//
// Field pairs format: ["Label1", "key1", "Label2", "key2", ...]
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

// formatStringValue formats string values by returning them unchanged.
// It ensures string values are passed through without modification in resource usage output.
//
// Parameters:
//   - value: String value to format
//
// Returns:
//   - string: Unchanged string value
func formatStringValue(value string) string {
	return value
}

// formatIntValue formats int values using Go's %d verb, converting integers to decimal string representation.
// It provides standard integer formatting for resource usage metrics.
//
// Parameters:
//   - value: Integer value to format
//
// Returns:
//   - string: Decimal string representation of the integer
func formatIntValue(value int) string {
	return fmt.Sprintf("%d", value)
}

// formatInt64Value formats int64 values with special handling for size-related keys.
// It formats cache sizes as "X entries" when the key indicates a size metric,
// otherwise uses standard decimal formatting.
//
// Parameters:
//   - key: The key name indicating the type of value (e.g., "size", "max_size")
//   - value: The int64 value to format
//
// Returns:
//   - string: Formatted string, either "X entries" for sizes or decimal representation
func formatInt64Value(key string, value int64) string {
	if key == "size" || key == "max_size" {
		return fmt.Sprintf("%d entries", value)
	}
	return fmt.Sprintf("%d", value)
}

// formatUint32Value formats uint32 values using Go's %d verb, converting unsigned 32-bit integers to decimal string representation.
// This provides standard unsigned integer formatting for resource usage metrics.
//
// Parameters:
//   - value: Unsigned 32-bit integer value to format
//
// Returns:
//   - string: Decimal string representation of the uint32 value
func formatUint32Value(value uint32) string {
	return fmt.Sprintf("%d", value)
}

// formatUint64Value formats uint64 values with special handling for time-related keys
func formatUint64Value(key string, value uint64) string {
	if key == "pause_total_ns" {
		return fmt.Sprintf("%.2f", float64(value)/1e6)
	}
	if key == "last_gc_ns" {
		if value == 0 {
			return "Never"
		}
		gcTime := time.Unix(0, int64(value))
		return gcTime.UTC().Format("January 2, 2006 at 3:04 PM MST")
	}
	return fmt.Sprintf("%d", value)
}

// formatFloat64Value formats float64 values with special handling for percentages and memory.
// It formats CPU fractions and hit rates as percentages, memory values as "X.XX MB",
// and other values with standard decimal precision.
//
// Parameters:
//   - key: The key name indicating the type of value (e.g., "gc_cpu_fraction", memory keys)
//   - value: The float64 value to format
//
// Returns:
//   - string: Formatted string with appropriate units (%, MB, or plain decimal)
func formatFloat64Value(key string, value float64) string {
	if key == "gc_cpu_fraction" || key == "hit_rate_percent" {
		return fmt.Sprintf("%.2f%%", value)
	}
	if strings.Contains(key, "mb") || strings.Contains(key, "memory") {
		return fmt.Sprintf("%.2f MB", value)
	}
	return fmt.Sprintf("%.2f", value)
}

// formatBoolValue formats boolean values using Go's %t verb, returning 'true' or 'false' as a string.
// It provides consistent string representation for boolean values in resource usage output.
//
// Parameters:
//   - value: Boolean value to format
//
// Returns:
//   - string: 'true' or 'false' string representation
func formatBoolValue(value bool) string {
	return fmt.Sprintf("%t", value)
}

// formatDefaultValue formats values of unknown types using Go's %v verb.
// It provides a fallback formatting mechanism for any unsupported data types in resource usage output.
//
// Parameters:
//   - value: Value of unknown type to format
//
// Returns:
//   - string: String representation using fmt.Sprintf("%v", value)
func formatDefaultValue(value any) string {
	return fmt.Sprintf("%v", value)
}

// formatValueForMarkdown formats a value for markdown display with appropriate units and formatting.
//
// formatValueForMarkdown converts various data types to human-readable strings
// with context-aware formatting based on the key name. It handles special cases
// for memory values, percentages, timestamps, and cache metrics.
//
// Parameters:
//   - value: The value to format (supports string, int, int64, uint32, uint64, float64, bool)
//   - key: The key name providing context for formatting (e.g., "size", "gc_cpu_fraction")
//
// Returns:
//   - string: Formatted value suitable for markdown table display
//
// Special formatting:
//   - Memory values (keys containing "mb" or "memory"): Displayed as "X.XX MB"
//   - Percentages ("gc_cpu_fraction", "hit_rate_percent"): Displayed as "X.XX%"
//   - Cache sizes ("size", "max_size"): Displayed as "X entries"
//   - GC pause times ("pause_total_ns"): Displayed as milliseconds
//   - Last GC time ("last_gc_ns"): Displayed as formatted timestamp or "Never"
//   - Boolean values: Displayed as "true"/"false"
//   - Default: Uses fmt.Sprintf("%v", v) for unsupported types
func formatValueForMarkdown(value any, key string) string {
	switch v := value.(type) {
	case string:
		return formatStringValue(v)
	case int:
		return formatIntValue(v)
	case int64:
		return formatInt64Value(key, v)
	case uint32:
		return formatUint32Value(v)
	case uint64:
		return formatUint64Value(key, v)
	case float64:
		return formatFloat64Value(key, v)
	case bool:
		return formatBoolValue(v)
	default:
		return formatDefaultValue(v)
	}
}

// calculateHitRate calculates the cache hit rate as a percentage.
//
// calculateHitRate computes the hit rate percentage for cache operations
// based on the number of hits and misses. It handles edge cases like zero
// total operations to avoid division by zero.
//
// Parameters:
//   - hits: Number of successful cache hits
//   - misses: Number of cache misses
//
// Returns:
//   - float64: Hit rate as a percentage (0.0 to 100.0)
//
// Formula: (hits / (hits + misses)) * 100
// Edge case: Returns 0.0 if total operations (hits + misses) is 0
func calculateHitRate(hits, misses int64) float64 {
	total := hits + misses
	if total == 0 {
		return 0.0
	}
	return float64(hits) / float64(total) * 100.0
}
