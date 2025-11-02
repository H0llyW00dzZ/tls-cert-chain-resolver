// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"embed"

	"crypto/x509"

	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ServerConfig holds configuration for the [MCP] server
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type ServerConfig struct {
	Version string
	Config  *Config
	Embed   embed.FS
}

// CertificateManager defines the interface for certificate operations
type CertificateManager interface {
	Decode(data []byte) (*x509.Certificate, error)
	DecodeMultiple(data []byte) ([]*x509.Certificate, error)
	EncodePEM(cert *x509.Certificate) []byte
	EncodeMultiplePEM(certs []*x509.Certificate) []byte
	EncodeDER(cert *x509.Certificate) []byte
	EncodeMultipleDER(certs []*x509.Certificate) []byte
}

// ChainResolver defines the interface for certificate chain operations
type ChainResolver interface {
	New(cert *x509.Certificate, version string) *x509chain.Chain
}

// DefaultChainResolver implements ChainResolver using the [x509chain.New] function
type DefaultChainResolver struct{}

// New creates a new certificate chain using the [x509chain.New] function
func (d DefaultChainResolver) New(cert *x509.Certificate, version string) *x509chain.Chain {
	return x509chain.New(cert, version)
}

// ToolHandler defines the signature for tool handlers (matches [MCP] server expectation)
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type ToolHandler = func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)

// ToolHandlerWithConfig defines tool handlers that need config
type ToolHandlerWithConfig func(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error)

// ResourceHandler defines the signature for resource handlers
type ResourceHandler = func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error)

// PromptHandler defines the signature for prompt handlers
type PromptHandler = func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error)

// ToolDefinition holds a tool definition and its handler
type ToolDefinition struct {
	Tool    mcp.Tool
	Handler ToolHandler
}

// ToolDefinitionWithConfig holds a tool that needs config
type ToolDefinitionWithConfig struct {
	Tool    mcp.Tool
	Handler ToolHandlerWithConfig
}

// ServerDependencies holds all dependencies needed to create the server
type ServerDependencies struct {
	Config          *Config
	Embed           embed.FS
	Version         string
	CertManager     CertificateManager
	ChainResolver   ChainResolver
	Tools           []ToolDefinition
	ToolsWithConfig []ToolDefinitionWithConfig
	Resources       []server.ServerResource
	Prompts         []server.ServerPrompt
}

// ServerBuilder helps construct the [MCP] server with proper dependencies
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type ServerBuilder struct{ deps ServerDependencies }

// NewServerBuilder creates a new server builder
func NewServerBuilder() *ServerBuilder { return &ServerBuilder{} }

// WithConfig sets the server configuration
func (b *ServerBuilder) WithConfig(config *Config) *ServerBuilder {
	b.deps.Config = config
	return b
}

// WithEmbed sets the embedded filesystem
func (b *ServerBuilder) WithEmbed(embed embed.FS) *ServerBuilder {
	b.deps.Embed = embed
	return b
}

// WithVersion sets the server version
func (b *ServerBuilder) WithVersion(version string) *ServerBuilder {
	b.deps.Version = version
	return b
}

// WithCertManager sets the certificate manager
func (b *ServerBuilder) WithCertManager(cm CertificateManager) *ServerBuilder {
	b.deps.CertManager = cm
	return b
}

// WithChainResolver sets the chain resolver
func (b *ServerBuilder) WithChainResolver(cr ChainResolver) *ServerBuilder {
	b.deps.ChainResolver = cr
	return b
}

// WithTools adds tools to the server
func (b *ServerBuilder) WithTools(tools ...ToolDefinition) *ServerBuilder {
	b.deps.Tools = append(b.deps.Tools, tools...)
	return b
}

// WithToolsWithConfig adds tools that need config
func (b *ServerBuilder) WithToolsWithConfig(tools ...ToolDefinitionWithConfig) *ServerBuilder {
	b.deps.ToolsWithConfig = append(b.deps.ToolsWithConfig, tools...)
	return b
}

// WithResources adds resources to the server
func (b *ServerBuilder) WithResources(resources ...server.ServerResource) *ServerBuilder {
	b.deps.Resources = append(b.deps.Resources, resources...)
	return b
}

// WithPrompts adds prompts to the server
func (b *ServerBuilder) WithPrompts(prompts ...server.ServerPrompt) *ServerBuilder {
	b.deps.Prompts = append(b.deps.Prompts, prompts...)
	return b
}

// WithDefaultTools adds the default X509 certificate tools using createTools
func (b *ServerBuilder) WithDefaultTools() *ServerBuilder {
	tools, toolsWithConfig := createTools()
	b.deps.Tools = append(b.deps.Tools, tools...)
	b.deps.ToolsWithConfig = append(b.deps.ToolsWithConfig, toolsWithConfig...)
	return b
}

// Build creates the [MCP] server with all configured dependencies
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
func (b *ServerBuilder) Build() (*server.MCPServer, error) {
	s := server.NewMCPServer(
		"X509 Certificate Chain Resolver",
		b.deps.Version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
	)

	// Add tools
	for _, tool := range b.deps.Tools {
		s.AddTool(tool.Tool, tool.Handler)
	}

	// Add tools that need config (wrap the handler)
	for _, tool := range b.deps.ToolsWithConfig {
		handler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return tool.Handler(ctx, request, b.deps.Config)
		}
		s.AddTool(tool.Tool, handler)
	}

	// Add resources
	for _, resource := range b.deps.Resources {
		s.AddResource(resource.Resource, resource.Handler)
	}

	// Add prompts
	for _, prompt := range b.deps.Prompts {
		s.AddPrompt(prompt.Prompt, prompt.Handler)
	}

	return s, nil
}
