// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"fmt"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	verpkg "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
)

var appVersion = verpkg.Version // default version

// GetVersion returns the current version of the MCP server.
//
// GetVersion provides access to the server's version string, which is set
// during server initialization via the Run function. This allows other
// components to access the version information for logging, user-agent
// strings, or API responses.
//
// Returns:
//   - string: The current server version (e.g., "0.4.9")
//
// The version is initially set to the default from the version package,
// but can be overridden when calling Run() with a specific version string.
func GetVersion() string {
	return appVersion
}

// Run starts the MCP server with X509 certificate chain resolution tools.
//
// Run initializes and starts the MCP server with all certificate chain resolution
// capabilities, including AI-powered analysis, remote certificate fetching,
// batch processing, and resource monitoring. The server supports graceful shutdown
// and integrates with the CRL cache cleanup system.
//
// Parameters:
//   - version: Version string to set for the server (e.g., "0.4.9")
//   - configFile: Path to the configuration file (overrides environment variable)
//
// Returns:
//   - error: Server startup or runtime error, or graceful shutdown signal
//
// Configuration:
//   - Loads config from configFile parameter if provided, otherwise from MCP_X509_CONFIG_FILE environment variable
//   - Falls back to default config if no configuration file is specified
//
// Features:
//   - Certificate chain resolution and validation
//   - Expiry checking with configurable warning thresholds
//   - Batch processing for multiple certificates
//   - Remote certificate fetching from hostnames
//   - AI-powered security analysis with revocation checking
//   - Resource usage monitoring and reporting
//   - Static resources (config template, version, formats, status)
//   - Guided prompts for certificate workflows
//
// Server Lifecycle:
//  1. Load configuration from file or defaults
//  2. Initialize CRL cache cleanup with context
//  3. Set up signal handling for graceful shutdown
//  4. Build MCP server using ServerBuilder pattern
//  5. Start stdio server with context cancellation support
//  6. Wait for either server error or shutdown signal
//
// Graceful Shutdown:
//   - Responds to SIGINT (Ctrl+C) and SIGTERM signals
//   - Cancels context to stop CRL cache cleanup
//   - Waits for server to stop cleanly
//   - Returns context.Canceled error on signal-based shutdown
//
// Error Handling:
//   - Configuration errors: Wrapped with "config error" prefix
//   - Server build errors: Wrapped with "failed to build server" prefix
//   - Shutdown errors: Wrapped with "server shutdown" prefix
func Run(version string, configFile string) error {
	// Set the version for GetVersion
	appVersion = version

	// Load default configuration for CLI framework initialization
	config, err := loadConfig("")
	if err != nil {
		return fmt.Errorf("failed to load default config: %w", err)
	}

	// Create tools for CLI framework
	tools, toolsWithConfig := createTools()
	resources, resourcesWithEmbed := createResources()
	prompts, promptsWithEmbed := createPrompts()

	// Generate instructions dynamically
	instructions, err := loadInstructions(tools, toolsWithConfig)
	if err != nil {
		return fmt.Errorf("failed to load instructions: %w", err)
	}

	// Create server dependencies with tools
	deps := ServerDependencies{
		Version: version,
		// Currently unused; will be implemented later. It's fine to keep as-is due to the framework's dependency injection design.
		CertManager: x509certs.New(),
		Config:      config,
		Embed:       templates.MagicEmbed,
		// Currently unused; will be implemented later. It's fine to keep as-is due to the framework's dependency injection design.
		ChainResolver:      DefaultChainResolver{},
		Tools:              tools,
		ToolsWithConfig:    toolsWithConfig,
		Resources:          resources,
		ResourcesWithEmbed: resourcesWithEmbed,
		Prompts:            prompts,
		PromptsWithEmbed:   promptsWithEmbed,
		SamplingHandler:    NewDefaultSamplingHandler(config, version),
		Instructions:       instructions,
		PopulateCache:      true,
	}

	// Create CLI framework with all dependencies
	cliFramework := NewCLIFramework("", deps)

	// Get the root command from CLI framework
	rootCmd := cliFramework.BuildRootCommand()

	// Execute the command
	return rootCmd.Execute()
}
