# Resource Monitoring Prompt Template

This template defines the workflow messages for resource monitoring and performance analysis.

## Messages
{{if eq .MonitoringContext "debugging"}}
##### Assistant: Introduction
Debugging resource usage issues for certificate operations. We'll systematically identify and resolve performance bottlenecks.

##### Assistant: Debugging Methodology
Follow this step-by-step debugging process:

1. **Baseline Measurement**: Establish current resource usage patterns
2. **Load Testing**: Identify resource consumption under different loads
3. **Memory Analysis**: Check for leaks and excessive allocations
4. **Cache Performance**: Analyze CRL cache efficiency and bottlenecks
5. **Bottleneck Identification**: Pinpoint specific performance issues

##### Assistant: Common Issues & Solutions
Common debugging scenarios and their solutions:

• **High Memory Usage During Certificate Processing**
  - Check buffer pooling efficiency (should reuse buffers)
  - Monitor certificate chain sizes (large chains consume more memory)
  - Verify CRL cache isn't growing unbounded

• **Slow Performance with Large Certificate Chains**
  - Check network timeouts and connection pooling
  - Monitor CRL validation overhead
  - Verify concurrent processing limits aren't exceeded

• **Memory Leaks in Batch Operations**
  - Ensure buffers are returned to pools after use
  - Check for goroutine leaks in concurrent processing
  - Monitor CRL cache cleanup

• **CRL Cache Inefficiencies**
  - Check cache hit rates (< 80% indicates tuning needed)
  - Monitor eviction rates and memory usage
  - Verify cleanup of expired CRLs

##### User: Detailed Analysis
Let's start with detailed resource usage information to identify specific performance bottlenecks and memory issues.
{{else if eq .MonitoringContext "optimization"}}
##### Assistant: Introduction
Optimizing resource usage for certificate operations. We'll identify and implement performance improvements.

##### Assistant: Optimization Strategy
Systematic optimization approach:

1. **Resource Profiling**: Identify current usage patterns and bottlenecks
2. **Configuration Tuning**: Adjust cache sizes, timeouts, and limits
3. **Memory Optimization**: Improve buffer usage and reduce allocations
4. **Concurrent Processing**: Optimize goroutine usage and limits
5. **Performance Validation**: Verify improvements under load

##### Assistant: Optimization Opportunities
Specific optimization recommendations:

• **CRL Cache Size Tuning**
  - Monitor hit rates and adjust cache size accordingly
  - Consider cache size vs memory usage trade-offs
  - Implement LRU eviction for optimal performance

• **Memory Allocation Patterns**
  - Use buffer pooling for certificate data processing
  - Minimize string concatenations in favor of efficient builders
  - Monitor GC pressure and heap allocations

• **Buffer Pooling Efficiency**
  - Ensure all buffers are returned to pools after use
  - Monitor pool utilization and adjust sizes if needed
  - Check for buffer leaks in error paths

• **Concurrent Processing Limits**
  - Adjust semaphore limits based on system capacity
  - Monitor goroutine counts and context switching overhead
  - Balance throughput with resource consumption

##### User: Performance Analysis
Let's analyze current resource usage patterns to identify specific optimization opportunities and configuration improvements.
{{else if eq .MonitoringContext "troubleshooting"}}
##### Assistant: Introduction
Troubleshooting resource-related issues in certificate operations. We'll diagnose and resolve specific problems.

##### Assistant: Troubleshooting Process
Structured diagnostic approach:

1. **Symptom Identification**: Clearly define the observed issue
2. **Resource Monitoring**: Gather comprehensive usage data
3. **Pattern Analysis**: Identify trends and anomalies
4. **Root Cause Analysis**: Determine underlying causes
5. **Solution Implementation**: Apply targeted fixes

##### Assistant: Diagnostic Scenarios
Common troubleshooting scenarios with specific steps:

• **Unexpected Memory Growth**
  - Check for buffer leaks in certificate processing
  - Monitor CRL cache growth over time
  - Verify proper cleanup of temporary allocations
  - Look for goroutine accumulation

• **Performance Degradation Over Time**
  - Monitor CRL cache hit rates for decline
  - Check for memory fragmentation
  - Verify consistent garbage collection performance
  - Look for resource exhaustion patterns

• **Cache Hit Rate Problems**
  - Analyze cache size vs working set size
  - Check for cache key collisions or inefficiencies
  - Monitor eviction patterns and cleanup effectiveness
  - Verify CRL freshness requirements

• **Resource Exhaustion During Peak Loads**
  - Check concurrent processing limits
  - Monitor memory usage spikes
  - Verify timeout configurations
  - Analyze request queuing and backpressure

##### User: Diagnostic Check
Let's systematically check resource usage to diagnose the specific issue and identify the root cause.
{{else}}
##### Assistant: Introduction
Routine resource monitoring for certificate operations. We'll establish baseline metrics and monitor for anomalies.

##### Assistant: Monitoring Checklist
Comprehensive monitoring checklist:

• **Memory Usage Trends**
  - Track heap allocation patterns over time
  - Monitor garbage collection frequency and pause times
  - Check for memory leaks in long-running processes
  - Verify buffer pool utilization

• **CRL Cache Performance**
  - Monitor hit rates (target: >90%)
  - Track cache size and memory usage
  - Check eviction rates and cleanup effectiveness
  - Verify CRL freshness and expiration handling

• **Garbage Collection Statistics**
  - Monitor GC pause times and frequency
  - Check for excessive allocations
  - Verify memory fragmentation levels
  - Track heap size trends

• **System Resource Utilization**
  - Monitor CPU usage patterns
  - Check goroutine counts and growth
  - Verify network connection pooling
  - Monitor disk I/O for CRL operations

##### User: Resource Check
Let's perform a comprehensive check of current resource usage and establish baseline performance metrics.
{{end}}

##### Assistant: Tool Usage Guide
Use the get_resource_usage tool with these parameters:

{{if eq .FormatPreference "markdown"}}
• For human-readable reports: get_resource_usage(detailed=false, format="markdown")
• For detailed analysis: get_resource_usage(detailed=true, format="markdown")
{{else}}
• For programmatic analysis: get_resource_usage(detailed=false, format="json")
• For comprehensive data: get_resource_usage(detailed=true, format="json")
{{end}}

##### Assistant: Interpretation Guide
Understanding the metrics:

• **Memory Metrics**
  - HeapAlloc: Current heap memory usage
  - HeapSys: Total heap memory obtained from OS
  - GCCycles: Number of garbage collection cycles
  - GCPause: Average GC pause time (should be < 10ms)

• **CRL Cache Metrics**
  - Hit Rate: Percentage of cache hits (>90% ideal)
  - Size: Current number of cached CRLs
  - Memory: Memory used by cache
  - Evictions: Number of cache evictions (should be low)

• **System Metrics**
  - Goroutines: Current number of goroutines (should be stable)
  - CPU: CPU usage percentage
  - Memory: Total system memory usage

• **Performance Indicators**
  - Look for memory growth without corresponding workload increase
  - Monitor cache hit rates for degradation
  - Check for increasing GC pause times
  - Watch for goroutine leaks

##### User: Next Steps
{{if eq .MonitoringContext "debugging"}}
Based on the detailed resource data, let's identify specific bottlenecks and implement targeted fixes for the performance issues.
{{else if eq .MonitoringContext "optimization"}}
Based on the performance analysis, let's implement the identified optimizations and measure their impact on resource usage.
{{else if eq .MonitoringContext "troubleshooting"}}
Based on the diagnostic data, let's implement the specific fixes needed to resolve the resource-related issue.
{{else}}
Based on the monitoring data, let's establish alerting thresholds and continue regular monitoring for any anomalies.
{{end}}