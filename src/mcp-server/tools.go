// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"github.com/mark3labs/mcp-go/mcp"
)

// createTools creates and returns all MCP tool definitions with their handlers.
// It organizes tools into two categories: those that don't require configuration
// and those that need access to the server configuration (e.g., for AI integration or timeouts).
//
// Returns:
//   - A slice of ToolDefinition for tools without config dependencies
//   - A slice of ToolDefinitionWithConfig for tools that require server configuration
//
// The function defines the following tools:
//   - resolve_cert_chain: Resolves certificate chains from files or base64 data
//   - validate_cert_chain: Validates certificate chains for correctness and trust
//   - batch_resolve_cert_chain: Processes multiple certificate chains in batch
//   - check_cert_expiry: Checks certificate expiry dates with configurable warnings
//   - fetch_remote_cert: Fetches certificate chains from remote hostnames
//   - analyze_certificate_with_ai: Performs AI-powered certificate analysis
//   - get_resource_usage: Provides server resource usage statistics
//
// Each tool includes proper parameter definitions, descriptions, and default values
// as required by the MCP specification.
func createTools() ([]ToolDefinition, []ToolDefinitionWithConfig) {
	// Tools that don't need config
	tools := []ToolDefinition{
		{
			Tool: mcp.NewTool("resolve_cert_chain",
				mcp.WithDescription("Resolve X509 certificate chain from a certificate file or base64-encoded certificate data"),
				mcp.WithString("certificate",
					mcp.Required(),
					mcp.Description("Certificate file path or base64-encoded certificate data"),
				),
				mcp.WithString("format",
					mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
					mcp.DefaultString("pem"),
				),
				mcp.WithBoolean("include_system_root",
					mcp.Description("Include system root CA in output (default: false)"),
					mcp.DefaultBool(false),
				),
				mcp.WithBoolean("intermediate_only",
					mcp.Description("Output only intermediate certificates (default: false)"),
					mcp.DefaultBool(false),
				),
			),
			Handler: handleResolveCertChain,
			Role:    "chainResolver",
		},
		{
			Tool: mcp.NewTool("validate_cert_chain",
				mcp.WithDescription("Validate a X509 certificate chain for correctness and trust"),
				mcp.WithString("certificate",
					mcp.Required(),
					mcp.Description("Certificate file path or base64-encoded certificate data"),
				),
				mcp.WithBoolean("include_system_root",
					mcp.Description("Include system root CA for validation (default: true)"),
					mcp.DefaultBool(true),
				),
			),
			Handler: handleValidateCertChain,
			Role:    "chainValidator",
		},
		{
			Tool: mcp.NewTool("batch_resolve_cert_chain",
				mcp.WithDescription("Resolve X509 certificate chains for multiple certificates in batch"),
				mcp.WithString("certificates",
					mcp.Required(),
					mcp.Description("Comma-separated list of certificate file paths or base64-encoded certificate data"),
				),
				mcp.WithString("format",
					mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
					mcp.DefaultString("pem"),
				),
				mcp.WithBoolean("include_system_root",
					mcp.Description("Include system root CA in output (default: false)"),
					mcp.DefaultBool(false),
				),
				mcp.WithBoolean("intermediate_only",
					mcp.Description("Output only intermediate certificates (default: false)"),
					mcp.DefaultBool(false),
				),
			),
			Handler: handleBatchResolveCertChain,
			Role:    "batchResolver",
		},
		{
			Tool: mcp.NewTool("get_resource_usage",
				mcp.WithDescription("Get current resource usage statistics including memory, GC, and CPU information"),
				mcp.WithBoolean("detailed",
					mcp.Description("Include detailed memory breakdown (default: false)"),
					mcp.DefaultBool(false),
				),
				mcp.WithString("format",
					mcp.Description("Output format: 'json' or 'markdown' (default: 'json')"),
					mcp.DefaultString("json"),
				),
			),
			Handler: handleGetResourceUsage,
			Role:    "resourceMonitor",
		},
	}

	// Tools that need config
	toolsWithConfig := []ToolDefinitionWithConfig{
		{
			Tool: mcp.NewTool("check_cert_expiry",
				mcp.WithDescription("Check certificate expiry dates and warn about upcoming expirations"),
				mcp.WithString("certificate",
					mcp.Required(),
					mcp.Description("Certificate file path or base64-encoded certificate data"),
				),
				mcp.WithNumber("warn_days",
					mcp.Description("Number of days before expiry to show warning (default: 30)"),
					mcp.DefaultNumber(30),
				),
			),
			Handler: handleCheckCertExpiry,
			Role:    "expiryChecker",
		},
		{
			Tool: mcp.NewTool("fetch_remote_cert",
				mcp.WithDescription("Fetch X509 certificate chain from a remote hostname/port"),
				mcp.WithString("hostname",
					mcp.Required(),
					mcp.Description("Remote hostname to connect to"),
				),
				mcp.WithNumber("port",
					mcp.Description("Port number (default: 443)"),
					mcp.DefaultNumber(443),
				),
				mcp.WithString("format",
					mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
					mcp.DefaultString("pem"),
				),
				mcp.WithBoolean("include_system_root",
					mcp.Description("Include system root CA in output (default: false)"),
					mcp.DefaultBool(false),
				),
				mcp.WithBoolean("intermediate_only",
					mcp.Description("Output only intermediate certificates (default: false)"),
					mcp.DefaultBool(false),
				),
			),
			Handler: handleFetchRemoteCert,
			Role:    "remoteFetcher",
		},
		{
			Tool: mcp.NewTool("analyze_certificate_with_ai",
				mcp.WithDescription("Analyze certificate data using AI collaboration (requires bidirectional communication)"),
				mcp.WithString("certificate",
					mcp.Required(),
					mcp.Description("Certificate file path or base64-encoded certificate data to analyze"),
				),
				mcp.WithString("analysis_type",
					mcp.Required(),
					mcp.Description("Type of analysis (required): 'security', 'compliance', 'general'"),
				),
			),
			Handler: handleAnalyzeCertificateWithAI,
			Role:    "aiAnalyzer",
		},
	}

	return tools, toolsWithConfig
}
