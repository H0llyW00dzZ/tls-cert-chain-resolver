// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"crypto/x509"

	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/mark3labs/mcp-go/client"
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
	SamplingHandler client.SamplingHandler // Added for bidirectional AI communication
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

// WithSampling adds a sampling handler for bidirectional AI communication
func (b *ServerBuilder) WithSampling(handler client.SamplingHandler) *ServerBuilder {
	// Note: Sampling handler is stored but not in ServerDependencies
	// It's used during Build() to enable sampling on the server
	b.deps.SamplingHandler = handler
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

	// Enable sampling for bidirectional AI communication if handler provided
	if b.deps.SamplingHandler != nil {
		s.EnableSampling()
		// Note: The sampling handler is managed internally by the server
		// when clients connect and request sampling
	}

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

// DefaultSamplingHandler provides configurable AI API integration for bidirectional communication
type DefaultSamplingHandler struct {
	apiKey   string
	endpoint string
	model    string
	timeout  time.Duration
	client   *http.Client
}

// NewDefaultSamplingHandler creates a new sampling handler with configurable AI settings
func NewDefaultSamplingHandler(config *Config) client.SamplingHandler {
	return &DefaultSamplingHandler{
		apiKey:   config.AI.APIKey,
		endpoint: config.AI.Endpoint,
		model:    config.AI.Model,
		timeout:  time.Duration(config.AI.Timeout) * time.Second,
		client:   &http.Client{Timeout: time.Duration(config.AI.Timeout) * time.Second},
	}
}

// CreateMessage handles sampling requests by calling the configured AI API
func (h *DefaultSamplingHandler) CreateMessage(ctx context.Context, request mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
	// If no API key, return placeholder response
	if h.apiKey == "" {
		response := "AI API key not configured. Please set X509_AI_APIKEY environment variable or configure in config.json. " +
			"This is a placeholder response for demonstration purposes."

		return &mcp.CreateMessageResult{
			SamplingMessage: mcp.SamplingMessage{
				Role:    mcp.RoleAssistant,
				Content: mcp.NewTextContent(response),
			},
			Model:      "placeholder",
			StopReason: "end",
		}, nil
	}

	// Convert MCP messages to OpenAI-compatible format
	var messages []map[string]any
	for _, msg := range request.Messages {
		message := map[string]any{
			"role": string(msg.Role),
		}

		// Handle different content types
		if textContent, ok := msg.Content.(mcp.TextContent); ok {
			message["content"] = textContent.Text
		} else {
			// For other content types, convert to string representation
			message["content"] = fmt.Sprintf("%v", msg.Content)
		}

		messages = append(messages, message)
	}

	// Prepare API request
	model := h.model // Use configured default model
	if request.ModelPreferences != nil && len(request.ModelPreferences.Hints) > 0 {
		// Use the first model hint if available
		model = request.ModelPreferences.Hints[0].Name
	}

	// Build messages array
	requestMessages := messages

	// Add system prompt if provided
	if request.SystemPrompt != "" {
		systemMessage := map[string]any{
			"role":    "system",
			"content": request.SystemPrompt,
		}
		requestMessages = append([]map[string]any{systemMessage}, messages...)
	}

	apiRequest := map[string]any{
		"model":       model,
		"messages":    requestMessages,
		"max_tokens":  request.MaxTokens,
		"temperature": request.Temperature,
		"stream":      false,
	}

	// Add stop sequences if provided
	if len(request.StopSequences) > 0 {
		apiRequest["stop"] = request.StopSequences
	}

	// Marshal request to JSON
	reqBody, err := json.Marshal(apiRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal API request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", h.endpoint+"/v1/chat/completions", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.apiKey)

	// Make the request
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call AI API: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AI API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResponse map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse AI API response: %w", err)
	}

	// Extract the response content (OpenAI-compatible format)
	choices, ok := apiResponse["choices"].([]any)
	if !ok || len(choices) == 0 {
		return nil, fmt.Errorf("invalid API response format: missing or empty choices")
	}

	choice, ok := choices[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid API response format: invalid choice structure")
	}

	message, ok := choice["message"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid API response format: missing message")
	}

	content, ok := message["content"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid API response format: missing content")
	}

	// Extract model name
	modelName := model
	if modelFromResponse, ok := apiResponse["model"].(string); ok {
		modelName = modelFromResponse
	}

	// Determine stop reason
	stopReason := "stop"
	if finishReason, ok := choice["finish_reason"].(string); ok {
		stopReason = finishReason
	}

	return &mcp.CreateMessageResult{
		SamplingMessage: mcp.SamplingMessage{
			Role:    mcp.RoleAssistant,
			Content: mcp.NewTextContent(content),
		},
		Model:      modelName,
		StopReason: stopReason,
	}, nil
}
