// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package mcpserver provides [MCP] server implementation for [X509] certificate chain resolution
//
// [X509]: https://grokipedia.com/page/X.509
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
package mcpserver

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/mark3labs/mcp-go/server"
)

var appVersion = version.Version // default version

// GetVersion returns the current version of the MCP server
func GetVersion() string {
	return appVersion
}

// Run starts the MCP server with X509 certificate chain resolution tools.
// It loads configuration from the MCP_X509_CONFIG_FILE environment variable.
func Run(version string) error {
	// Set the version for GetVersion
	appVersion = version

	// Load configuration
	config, err := loadConfig(os.Getenv("MCP_X509_CONFIG_FILE"))
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// Create cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		WithEmbed(MagicEmbed).
		WithVersion(version).
		WithCertManager(x509certs.New()).
		WithChainResolver(DefaultChainResolver{}).
		WithSampling(NewDefaultSamplingHandler(config, version)).
		WithDefaultTools().
		WithResources(createResources()...).
		WithPrompts(createPrompts()...).
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
