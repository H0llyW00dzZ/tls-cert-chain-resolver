// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"
	"os"
)

// ADKTransportConfig holds configuration for creating MCP transports for ADK integration
//
// NOTE: This provides transport creation utilities for [Google ADK] integration.
// The [Google ADK] packages ([google.golang.org/adk/*]) are not yet publicly available.
// When they become available, these transports can be used with ADK mcptoolset.
//
// Example usage with ADK (when packages are available):
//
//	transport := NewADKTransportBuilder().WithInMemoryTransport().BuildTransport(ctx)
//	mcpToolSet, err := mcptoolset.New(mcptoolset.Config{Transport: transport})
//
// [google.golang.org/adk/*]: https://pkg.go.dev/google.golang.org/adk
// [Google ADK]: https://pkg.go.dev/google.golang.org/adk
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
			Version:       "1.0.0",
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
// NOTE: This returns an [any] because the actual MCP server types
// depend on the [mark3labs/mcp-go] library. When used with ADK, you would
// create an in-process client using client.NewInProcessClient(server).
//
// Example usage when ADK packages are available:
//
//	transport := NewADKTransportBuilder().WithInMemoryTransport().BuildTransport(ctx)
//	server := transport.(*server.MCPServer)  // Cast to actual type
//	mcpClient, err := client.NewInProcessClient(server)
//	// Use mcpClient for ADK integration
//
// [mark3labs/mcp-go]: https://github.com/mark3labs/mcp-go
func (b *ADKTransportBuilder) BuildTransport(ctx context.Context) (any, error) {
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
func (b *ADKTransportBuilder) buildInMemoryTransport(ctx context.Context) (any, error) {
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

	return transportBuilder.BuildInMemoryTransport(ctx)
}
