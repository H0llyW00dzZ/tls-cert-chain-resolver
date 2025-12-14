// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/mcp"
)

// handleConfigResource handles requests for the configuration template resource.
// It provides a JSON template showing the expected configuration structure for the MCP server.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for the config template
//
// Returns:
//   - A slice containing the configuration template as JSON content
//   - An error if JSON marshaling fails
//
// The resource provides default values for format, includeSystemRoot, intermediateOnly, warnDays, and timeoutSeconds.
func handleConfigResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	exampleConfig := map[string]any{
		"defaults": map[string]any{
			"format":            "pem",
			"includeSystemRoot": false,
			"intermediateOnly":  false,
			"warnDays":          30,
			"timeoutSeconds":    30,
		},
	}

	jsonData, err := json.MarshalIndent(exampleConfig, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config template: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "config://template",
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// handleVersionResource handles requests for version information resource.
// It provides server metadata including version, capabilities, and supported features.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for version information
//
// Returns:
//   - A slice containing version and capability information as JSON content
//   - An error if JSON marshaling fails
//
// The resource includes server name, version, supported tools, resources, prompts with full metadata from config, and certificate formats.
// All capabilities (tools, resources, prompts) are loaded dynamically from codegen config files with their meta information.
func handleVersionResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	// Load configurations dynamically
	prompts, err := loadPromptsConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load prompts config: %w", err)
	}

	tools, err := loadToolsConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load tools config: %w", err)
	}

	resources, err := loadResourcesConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load resources config: %w", err)
	}

	versionInfo := map[string]any{
		"name":    "X509 Certificate Chain Resolver",
		"version": version.Version,
		"type":    "MCP Server",
		"capabilities": map[string]any{
			"tools":     tools,     // Loaded from config with meta
			"resources": resources, // Loaded from config with meta
			"prompts":   prompts,   // Loaded from config with meta
		},
		"supportedFormats": []string{"pem", "der", "json"},
	}

	jsonData, err := json.MarshalIndent(versionInfo, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal version info: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "info://version",
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// handleCertificateFormatsResource handles requests for certificate formats documentation resource.
// It serves embedded documentation about supported certificate formats (PEM, DER, etc.).
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for certificate format documentation
//
// Returns:
//   - A slice containing the certificate formats documentation as markdown content
//   - An error if the embedded file cannot be read
//
// The documentation is stored in templates/certificate-formats.md and provides
// detailed information about certificate encoding formats and usage.
func handleCertificateFormatsResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	content, err := templates.MagicEmbed.ReadFile("certificate-formats.md")
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate formats template: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "docs://certificate-formats",
			MIMEType: "text/markdown",
			Text:     string(content),
		},
	}, nil
}

// handleStatusResource handles requests for server status information resource.
// It provides current server health, version, and operational status.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: MCP resource read request for server status
//
// Returns:
//   - A slice containing server status information as JSON content
//   - An error if JSON marshaling fails
//
// The status includes server health, timestamp, version, and available capabilities
// (tools, resources, prompts with full metadata from config, supported formats).
// All capabilities are loaded dynamically from codegen config files with their meta information.
func handleStatusResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	// Load configurations dynamically
	prompts, err := loadPromptsConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load prompts config: %w", err)
	}

	tools, err := loadToolsConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load tools config: %w", err)
	}

	resources, err := loadResourcesConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load resources config: %w", err)
	}

	statusInfo := map[string]any{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"server":    "X.509 Certificate Chain Resolver MCP Server",
		"version":   version.Version,
		"capabilities": map[string]any{
			"tools":     tools,     // Loaded from config with meta
			"resources": resources, // Loaded from config with meta
			"prompts":   prompts,   // Loaded from config with meta
		},
		"supportedFormats": []string{"pem", "der", "json"},
	}

	jsonData, err := json.MarshalIndent(statusInfo, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal status info: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "status://server-status",
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}
