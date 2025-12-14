// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/server"
)

var appVersion = version.Version // default version

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
//
// Returns:
//   - error: Server startup or runtime error, or graceful shutdown signal
//
// Configuration:
//   - Loads config from MCP_X509_CONFIG_FILE environment variable
//   - Falls back to default config if environment variable not set
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
//  1. Load configuration from environment
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
func Run(version string) error {
	// Set the version for GetVersion
	appVersion = version

	// Load configuration
	config, err := loadConfig(os.Getenv("MCP_X509_CONFIG_FILE"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create tools (called once and reused)
	tools, toolsWithConfig := createTools()

	// Load server instructions with tool information
	//
	// This approach is better as it uses dynamic content generation based on tools,
	// instead of hardcoded values
	instructions, err := loadInstructions(tools, toolsWithConfig)
	if err != nil {
		return fmt.Errorf("failed to load instructions: %w", err)
	}

	// Create cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start CRL cache cleanup with cancellable context
	x509chain.StartCRLCacheCleanup(ctx)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Create MCP server using ServerBuilder for better testability
	s, err := NewServerBuilder().
		WithConfig(config).
		WithEmbed(templates.MagicEmbed).
		WithVersion(version).
		WithCertManager(x509certs.New()).
		WithChainResolver(DefaultChainResolver{}).
		WithSampling(NewDefaultSamplingHandler(config, version)).
		WithTools(tools...).
		WithToolsWithConfig(toolsWithConfig...).
		WithResources(createResources()...).
		WithPrompts(createPrompts()...).
		WithInstructions(instructions).
		WithPopulate().
		Build()
	if err != nil {
		return fmt.Errorf("failed to build server: %w", err)
	}

	// Create stdio server to connect with our context
	stdioServer := server.NewStdioServer(s)

	// Start server with graceful shutdown support
	errChan := make(chan error, 1)
	go func() {
		errChan <- stdioServer.Listen(ctx, os.Stdin, os.Stdout)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		// Graceful shutdown triggered by signal
		return fmt.Errorf("server shutdown: %w", ctx.Err())
	}
}
