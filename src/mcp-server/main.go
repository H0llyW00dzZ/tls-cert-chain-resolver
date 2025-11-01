// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package mcpserver provides MCP server implementation for TLS/SSL certificate chain resolution
package mcpserver

import (
	"context"
	"fmt"
	"os"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var serverName = "TLS/SSL Certificate Chain Resolver" // MCP server name
var appVersion = version.Version                      // default version

// Run starts the MCP server with TLS/SSL certificate chain resolution tools.
// It loads configuration from the MCP_CONFIG_FILE environment variable.
func Run() error {
	// Load configuration
	config, err := loadConfig(os.Getenv("MCP_CONFIG_FILE"))
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// Create MCP server
	s := server.NewMCPServer(
		serverName,
		appVersion,
		server.WithToolCapabilities(true),
	)

	// Define certificate chain resolution tool
	resolveCertChainTool := mcp.NewTool("resolve_cert_chain",
		mcp.WithDescription("Resolve TLS/SSL certificate chain from a certificate file or base64-encoded certificate data"),
		mcp.WithString("certificate",
			mcp.Required(),
			mcp.Description("Certificate file path or base64-encoded certificate data"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'pem', 'der', or 'json' (default: "+config.Defaults.Format+")"),
			mcp.DefaultString(config.Defaults.Format),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA in output (default: "+fmt.Sprintf("%v", config.Defaults.IncludeSystemRoot)+")"),
			mcp.DefaultBool(config.Defaults.IncludeSystemRoot),
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates (default: "+fmt.Sprintf("%v", config.Defaults.IntermediateOnly)+")"),
			mcp.DefaultBool(config.Defaults.IntermediateOnly),
		),
	)

	// Define batch certificate chain resolution tool
	batchResolveCertChainTool := mcp.NewTool("batch_resolve_cert_chain",
		mcp.WithDescription("Resolve TLS/SSL certificate chains for multiple certificates in batch"),
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
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates (default: false)"),
		),
	)

	// Define certificate validation tool
	validateCertChainTool := mcp.NewTool("validate_cert_chain",
		mcp.WithDescription("Validate a TLS/SSL certificate chain for correctness and trust"),
		mcp.WithString("certificate",
			mcp.Required(),
			mcp.Description("Certificate file path or base64-encoded certificate data"),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA for validation (default: true)"),
			mcp.DefaultBool(true),
		),
	)

	// Define certificate expiry checking tool
	checkCertExpiryTool := mcp.NewTool("check_cert_expiry",
		mcp.WithDescription("Check certificate expiry dates and warn about upcoming expirations"),
		mcp.WithString("certificate",
			mcp.Required(),
			mcp.Description("Certificate file path or base64-encoded certificate data"),
		),
		mcp.WithNumber("warn_days",
			mcp.Description("Number of days before expiry to show warning (default: "+fmt.Sprintf("%d", config.Defaults.WarnDays)+")"),
			mcp.DefaultNumber(float64(config.Defaults.WarnDays)),
		),
	)

	// Define remote certificate fetching tool
	fetchRemoteCertTool := mcp.NewTool("fetch_remote_cert",
		mcp.WithDescription("Fetch TLS/SSL certificate chain from a remote hostname/port"),
		mcp.WithString("hostname",
			mcp.Required(),
			mcp.Description("Remote hostname to connect to"),
		),
		mcp.WithNumber("port",
			mcp.Description("Port number (default: "+fmt.Sprintf("%d", config.Defaults.Port)+")"),
			mcp.DefaultNumber(float64(config.Defaults.Port)),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'pem', 'der', or 'json' (default: "+config.Defaults.Format+")"),
			mcp.DefaultString(config.Defaults.Format),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA in output (default: "+fmt.Sprintf("%v", config.Defaults.IncludeSystemRoot)+")"),
			mcp.DefaultBool(config.Defaults.IncludeSystemRoot),
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates (default: "+fmt.Sprintf("%v", config.Defaults.IntermediateOnly)+")"),
			mcp.DefaultBool(config.Defaults.IntermediateOnly),
		),
	)

	// Register tool handler
	s.AddTool(resolveCertChainTool, handleResolveCertChain)
	s.AddTool(batchResolveCertChainTool, handleBatchResolveCertChain)
	s.AddTool(validateCertChainTool, handleValidateCertChain)
	s.AddTool(checkCertExpiryTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleCheckCertExpiry(request, config)
	})
	s.AddTool(fetchRemoteCertTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleFetchRemoteCert(ctx, request, config)
	})

	// Start server
	return server.ServeStdio(s)
}
