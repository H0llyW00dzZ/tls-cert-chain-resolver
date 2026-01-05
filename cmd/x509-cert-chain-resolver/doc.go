// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

// x509-cert-chain-resolver is a Model Context Protocol (MCP) server that exposes
// X.509 certificate operations to AI assistants and automation clients over stdio.
//
// # Installation
//
// Install with Go 1.25.5 or later:
//
//	go install github.com/H0llyW00dzZ/tls-cert-chain-resolver/cmd/x509-cert-chain-resolver@latest
//
// # Usage
//
//	x509-cert-chain-resolver [FLAGS]
//
// # Flags
//
//	--config        Path to MCP server configuration file (JSON or YAML)
//	--instructions  Display certificate operation workflows and MCP server usage
//	--help          Show help information
//	--version       Show version information
//
// # Environment Variables
//
//	X509_AI_APIKEY        API key for AI-backed certificate analysis (optional)
//	MCP_X509_CONFIG_FILE  Path to configuration file (alternative to --config flag)
//
// # MCP Tools
//
// The server provides the following certificate operations:
//
//   - resolve_cert_chain: Build a full chain from a certificate file or base64 payload
//   - validate_cert_chain: Verify trust relationships and highlight validation issues
//   - check_cert_expiry: Report upcoming expirations with configurable warning windows
//   - batch_resolve_cert_chain: Resolve multiple certificates in a single call
//   - fetch_remote_cert: Retrieve chains directly from TLS endpoints
//   - visualize_cert_chain: Visualize certificate chains in ASCII tree, table, or JSON formats
//   - analyze_certificate_with_ai: Delegate structured certificate analysis to a configured LLM
//   - get_resource_usage: Monitor server resource usage (memory, GC, system info)
//
// # MCP Resources
//
//   - config://template: Server configuration template
//   - info://version: Version and capabilities info
//   - docs://certificate-formats: Certificate format documentation
//   - status://server-status: Current server health status
//
// # MCP Prompts
//
//   - certificate-analysis: Comprehensive certificate chain analysis workflow
//   - expiry-monitoring: Monitor certificate expiration dates and generate renewal alerts
//   - security-audit: Perform comprehensive SSL/TLS security audit on a server
//   - troubleshooting: Troubleshoot common certificate and TLS issues
//   - resource-monitoring: Monitor server resource usage and performance metrics
//
// # Examples
//
// Start MCP server with default configuration:
//
//	x509-cert-chain-resolver
//
// Load custom configuration:
//
//	x509-cert-chain-resolver --config /path/to/config.json
//
// Show certificate operation workflows:
//
//	x509-cert-chain-resolver --instructions
//
// # AI-Assisted Analysis
//
// Set X509_AI_APIKEY or configure the ai section of the MCP config to allow
// the server to request completions from xAI Grok (default), OpenAI, or any
// OpenAI-compatible API.
package main
