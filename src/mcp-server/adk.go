// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"os"

	mcptransport "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ADKTransportConfig holds configuration for creating MCP transports for ADK integration
//
// NOTE: This provides transport creation utilities for [Google ADK] integration.
// These transports can be used with ADK mcptoolset.
//
// Example usage with ADK:
//
//	transport, err := NewADKTransportBuilder().WithInMemoryTransport().BuildTransport(ctx)
//	mcpToolSet, err := mcptoolset.New(mcptoolset.Config{Transport: transport})
//
// [Google ADK]: https://pkg.go.dev/google.golang.org/adk
//
// [google.golang.org/adk/*]: https://pkg.go.dev/google.golang.org/adk
type ADKTransportConfig struct {
	// MCP server configuration
	MCPConfigFile string
	Version       string

	// Transport type: "inmemory"
	TransportType string
}

// ADKTransportBuilder helps construct MCP transports for ADK integration
type ADKTransportBuilder struct{ config ADKTransportConfig }

// NewADKTransportBuilder creates a new ADK transport builder with default configuration
func NewADKTransportBuilder() *ADKTransportBuilder {
	return &ADKTransportBuilder{
		config: ADKTransportConfig{
			MCPConfigFile: os.Getenv("MCP_X509_CONFIG_FILE"),
			Version:       version.Version,
			TransportType: "inmemory",
		},
	}
}

// WithMCPConfig sets the MCP server configuration file path
func (b *ADKTransportBuilder) WithMCPConfig(configFile string) *ADKTransportBuilder {
	b.config.MCPConfigFile = configFile
	return b
}

// WithVersion sets the MCP server version
func (b *ADKTransportBuilder) WithVersion(version string) *ADKTransportBuilder {
	b.config.Version = version
	return b
}

// WithInMemoryTransport configures in-memory transport (connects directly to handlers)
func (b *ADKTransportBuilder) WithInMemoryTransport() *ADKTransportBuilder {
	b.config.TransportType = "inmemory"
	return b
}

// ValidateConfig validates the transport builder configuration
func (b *ADKTransportBuilder) ValidateConfig() error {
	if b.config.TransportType == "inmemory" {
		// No additional validation needed for in-memory transport
		return nil
	}

	return fmt.Errorf("unsupported transport type: %s", b.config.TransportType)
}

// BuildTransport creates an MCP server for ADK integration
//
// This returns an [mcp.Transport] interface that can be used directly with
// ADK's [mcptoolset]. The implementation bridges between [mark3labs/mcp-go]
// server and [Official MCP SDK] transport expectations.
//
// Example usage:
//
//	transport, err := NewADKTransportBuilder().WithInMemoryTransport().BuildTransport(ctx)
//	if err != nil {
//		// handle error
//	}
//	// Use transport with ADK mcptoolset
//	// mcpToolSet, err := mcptoolset.New(mcptoolset.Config{Transport: transport})
//
// [mark3labs/mcp-go]: https://pkg.go.dev/github.com/mark3labs/mcp-go
// [Official MCP SDK]: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk
func (b *ADKTransportBuilder) BuildTransport(ctx context.Context) (mcptransport.Transport, error) {
	// Validate configuration first
	if err := b.ValidateConfig(); err != nil {
		return nil, err
	}

	switch b.config.TransportType {
	case "inmemory":
		return b.buildInMemoryTransport(ctx)
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", b.config.TransportType)
	}
}

// buildInMemoryTransport creates an in-memory MCP server using TransportBuilder
//
// This uses the TransportBuilder from framework.go to create an MCP server
// with all certificate tools, providing a clean separation between server building
// and transport creation while avoiding test dependencies.
func (b *ADKTransportBuilder) buildInMemoryTransport(ctx context.Context) (mcptransport.Transport, error) {
	// Load configuration
	config, err := loadConfig(b.config.MCPConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load MCP config: %w", err)
	}

	// Use TransportBuilder to create the transport
	transportBuilder := NewTransportBuilder().
		WithConfig(config).
		WithVersion(b.config.Version).
		WithDefaultTools()

	// Build the server
	srv, err := transportBuilder.serverBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build server: %w", err)
	}

	// Create transport and connect server with sampling handler support
	transport := NewInMemoryTransport(ctx)

	// Create DefaultSamplingHandler with streaming support
	// This handler is attached to the client side (transport) to process sampling requests from the server
	samplingHandler := NewDefaultSamplingHandler(config, b.config.Version)
	samplingHandler.TokenCallback = func(token string) {
		// Stream token via custom notification to the ADK receive channel
		// We use "notifications/sampling/progress" which is a custom method for this bridge
		transport.SendJSONRPCNotification("notifications/sampling/progress", map[string]string{
			"content": token,
		})
	}
	transport.SetSamplingHandler(samplingHandler)

	if err := transport.ConnectServer(ctx, srv); err != nil {
		return nil, fmt.Errorf("failed to connect server to transport: %w", err)
	}

	return transport, nil
}
