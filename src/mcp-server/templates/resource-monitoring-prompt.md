# Resource Monitoring Prompt Template

This template defines the workflow messages for resource monitoring and performance analysis.

## Messages
{{if eq .MonitoringContext "debugging"}}
##### Assistant: Introduction
Debugging resource usage issues for certificate operations.

##### Assistant: Common Issues
Common debugging scenarios:
• High memory usage during certificate processing
• Slow performance with large certificate chains
• Memory leaks in batch operations
• CRL cache inefficiencies

##### User: Detailed Analysis
Let's get detailed resource usage information to identify performance bottlenecks.
{{else if eq .MonitoringContext "optimization"}}
##### Assistant: Introduction
Optimizing resource usage for certificate operations.

##### Assistant: Common Issues
Common optimization opportunities:
• CRL cache size tuning
• Memory allocation patterns
• Buffer pooling efficiency
• Concurrent processing limits

##### User: Performance Analysis
Let's analyze current resource usage to identify optimization opportunities.
{{else if eq .MonitoringContext "troubleshooting"}}
##### Assistant: Introduction
Troubleshooting resource-related issues in certificate operations.

##### Assistant: Common Issues
Common troubleshooting scenarios:
• Unexpected memory growth
• Performance degradation over time
• Cache hit rate problems
• Resource exhaustion during peak loads

##### User: Diagnostic Check
Let's check resource usage to diagnose the specific issue.
{{else}}
##### Assistant: Introduction
Routine resource monitoring for certificate operations.

##### Assistant: Key Metrics
Important metrics to monitor:
• Memory usage trends
• CRL cache performance
• Garbage collection statistics
• System resource utilization

##### User: Resource Check
Let's check current resource usage and performance metrics.
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
• Memory: Monitor heap allocation and GC patterns
• CRL Cache: Check hit rates (>90% ideal) and evictions
• System: Review goroutine count and CPU usage
• Performance: Look for trends and anomalies

##### User: Next Steps
Based on the resource usage data, identify any issues or optimization opportunities.