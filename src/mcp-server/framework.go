// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"crypto/x509"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
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
	version  string
}

// NewDefaultSamplingHandler creates a new sampling handler with configurable AI settings
func NewDefaultSamplingHandler(config *Config, version string) client.SamplingHandler {
	return &DefaultSamplingHandler{
		apiKey:   config.AI.APIKey,
		endpoint: config.AI.Endpoint,
		model:    config.AI.Model,
		version:  version,
		timeout:  time.Duration(config.AI.Timeout) * time.Second,
		client:   &http.Client{Timeout: time.Duration(config.AI.Timeout) * time.Second},
	}
}

// CreateMessage handles sampling requests by calling the configured AI API
func (h *DefaultSamplingHandler) CreateMessage(ctx context.Context, request mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
	// Get buffer from pool for efficient memory usage
	buf := gc.Default.Get()
	defer func() {
		buf.Reset()         // Reset buffer to prevent data leaks
		gc.Default.Put(buf) // Return buffer to pool for reuse
	}()

	// If no API key, return guidance for enabling AI integration
	if h.apiKey == "" {
		return h.handleNoAPIKey()
	}

	// Convert MCP messages to OpenAI-compatible format
	messages := h.convertMessages(request.Messages)

	// Prepare API request
	model := h.selectModel(request.ModelPreferences)
	requestMessages := h.prepareMessages(messages, request.SystemPrompt)
	apiRequest := h.buildAPIRequest(model, requestMessages, request)

	// Create and send HTTP request
	resp, err := h.sendAPIRequest(ctx, apiRequest, buf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, h.handleAPIError(resp, buf)
	}

	// Handle streaming response
	content, modelName, stopReason, err := h.parseStreamingResponse(resp.Body, model)
	if err != nil {
		return nil, fmt.Errorf("error reading streaming response: %w", err)
	}

	return h.buildSamplingResult(content, modelName, stopReason), nil
}

// handleNoAPIKey returns a helpful message when no API key is configured
func (h *DefaultSamplingHandler) handleNoAPIKey() (*mcp.CreateMessageResult, error) {
	response := "AI API key not configured. Set X509_AI_APIKEY or configure the ai.apiKey field in config.json to enable certificate analysis. " +
		"Until then, the server will return static information only."

	return &mcp.CreateMessageResult{
		SamplingMessage: mcp.SamplingMessage{
			Role:    mcp.RoleAssistant,
			Content: mcp.NewTextContent(response),
		},
		Model:      "not-configured",
		StopReason: "end",
	}, nil
}

// convertMessages converts MCP messages to OpenAI-compatible format
func (h *DefaultSamplingHandler) convertMessages(mcpMessages []mcp.SamplingMessage) []map[string]any {
	var messages []map[string]any
	for _, msg := range mcpMessages {
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
	return messages
}

// selectModel chooses the appropriate model based on preferences
func (h *DefaultSamplingHandler) selectModel(preferences *mcp.ModelPreferences) string {
	model := h.model // Use configured default model
	if preferences != nil && len(preferences.Hints) > 0 {
		// Use the first model hint if available
		model = preferences.Hints[0].Name
	}
	return model
}

// prepareMessages adds system prompt if provided
func (h *DefaultSamplingHandler) prepareMessages(messages []map[string]any, systemPrompt string) []map[string]any {
	if systemPrompt == "" {
		return messages
	}

	systemMessage := map[string]any{
		"role":    "system",
		"content": systemPrompt,
	}
	return append([]map[string]any{systemMessage}, messages...)
}

// buildAPIRequest creates the API request payload
func (h *DefaultSamplingHandler) buildAPIRequest(model string, messages []map[string]any, request mcp.CreateMessageRequest) map[string]any {
	apiRequest := map[string]any{
		"model":       model,
		"messages":    messages,
		"max_tokens":  request.MaxTokens,
		"temperature": request.Temperature,
		"stream":      true, // Enable streaming for better performance and real-time responses
	}

	// Add stop sequences if provided
	if len(request.StopSequences) > 0 {
		apiRequest["stop"] = request.StopSequences
	}

	return apiRequest
}

// sendAPIRequest creates and sends the HTTP request
func (h *DefaultSamplingHandler) sendAPIRequest(ctx context.Context, apiRequest map[string]any, buf gc.Buffer) (*http.Response, error) {
	// Marshal request to JSON
	reqBody, err := json.Marshal(apiRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal API request: %w", err)
	}

	// Create HTTP request using bytes.Reader for request body
	req, err := http.NewRequestWithContext(ctx, "POST", h.endpoint+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.apiKey)
	req.Header.Set("User-Agent", "X.509-Certificate-Chain-Resolver-MCP/"+h.version+" (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)")

	// Make the request
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call AI API: %w", err)
	}

	return resp, nil
}

// handleAPIError processes API error responses
func (h *DefaultSamplingHandler) handleAPIError(resp *http.Response, buf gc.Buffer) error {
	// Read error response body using buffer pool
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return fmt.Errorf("AI API error (status %d): failed to read error response: %w", resp.StatusCode, err)
	}
	return fmt.Errorf("AI API error (status %d): %s", resp.StatusCode, string(buf.Bytes()))
}

// parseStreamingResponse handles the streaming response parsing
func (h *DefaultSamplingHandler) parseStreamingResponse(body io.Reader, defaultModel string) (string, string, string, error) {
	var fullContent strings.Builder
	modelName := defaultModel
	stopReason := "stop"

	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}

		// Parse Server-Sent Events format
		if data, found := strings.CutPrefix(line, "data: "); found {
			// Handle end of stream
			if data == "[DONE]" {
				break
			}

			// Parse JSON chunk
			var chunk map[string]any
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				continue // Skip malformed chunks
			}

			// Extract model name if available
			if modelFromChunk, ok := chunk["model"].(string); ok && modelName == defaultModel {
				modelName = modelFromChunk
			}

			// Process choices
			if choices, ok := chunk["choices"].([]any); ok && len(choices) > 0 {
				if choice, ok := choices[0].(map[string]any); ok {
					// Extract delta content
					if delta, ok := choice["delta"].(map[string]any); ok {
						if content, ok := delta["content"].(string); ok {
							fullContent.WriteString(content)
						}
					}

					// Check for finish reason
					if finishReason, ok := choice["finish_reason"].(string); ok && finishReason != "" {
						stopReason = finishReason
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}

	return fullContent.String(), modelName, stopReason, nil
}

// buildSamplingResult creates the final sampling result
func (h *DefaultSamplingHandler) buildSamplingResult(content, modelName, stopReason string) *mcp.CreateMessageResult {
	return &mcp.CreateMessageResult{
		SamplingMessage: mcp.SamplingMessage{
			Role:    mcp.RoleAssistant,
			Content: mcp.NewTextContent(content),
		},
		Model:      modelName,
		StopReason: stopReason,
	}
}

// SamplingRequestMarker is a special result that indicates a sampling request should be made
type SamplingRequestMarker struct {
	Request SamplingRequest
}

// SamplingRequest represents a request for AI sampling from a handler
type SamplingRequest struct {
	Messages     []mcp.SamplingMessage
	SystemPrompt string
	MaxTokens    int
	Temperature  float64
}
