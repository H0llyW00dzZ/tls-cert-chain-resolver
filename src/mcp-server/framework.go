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

// ServerConfig holds configuration for the [MCP] server, including version, config, and embedded filesystem.
// It is used to initialize the server with necessary dependencies and settings.
//
// Fields:
//   - Version: The server version string (e.g., "1.0.0")
//   - Config: Pointer to the server configuration containing AI and other settings
//   - Embed: Embedded filesystem for static resources like templates and documentation
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type ServerConfig struct {
	Version string
	Config  *Config
	Embed   embed.FS
}

// CertificateManager defines the interface for certificate operations.
// It provides methods for encoding and decoding certificates in various formats.
//
// Methods:
//   - Decode: Parses a single certificate from PEM or DER data
//   - DecodeMultiple: Parses multiple certificates from concatenated PEM data
//   - EncodePEM: Encodes a certificate to PEM format
//   - EncodeMultiplePEM: Encodes multiple certificates to concatenated PEM format
//   - EncodeDER: Encodes a certificate to DER format
//   - EncodeMultipleDER: Encodes multiple certificates to concatenated DER format
//
// Example usage:
//
//	cert, err := manager.Decode(pemData)
//	if err != nil {
//	    return err
//	}
//	pemBytes := manager.EncodePEM(cert)
type CertificateManager interface {
	Decode(data []byte) (*x509.Certificate, error)
	DecodeMultiple(data []byte) ([]*x509.Certificate, error)
	EncodePEM(cert *x509.Certificate) []byte
	EncodeMultiplePEM(certs []*x509.Certificate) []byte
	EncodeDER(cert *x509.Certificate) []byte
	EncodeMultipleDER(certs []*x509.Certificate) []byte
}

// ChainResolver defines the interface for certificate chain operations.
// It provides methods to create and manage certificate chains for validation.
//
// Methods:
//   - New: Creates a new certificate chain from a leaf certificate and version string
//
// Example usage:
//
//	resolver := &DefaultChainResolver{}
//	chain := resolver.New(leafCert, "1.0.0")
type ChainResolver interface {
	New(cert *x509.Certificate, version string) *x509chain.Chain
}

// DefaultChainResolver implements ChainResolver using the x509chain.New function.
// It provides a default implementation that creates certificate chains using the internal chain package.
//
// This implementation is used when no custom chain resolver is provided to the server builder.
type DefaultChainResolver struct{}

// New creates a new certificate chain using the [x509chain.New] function.
// It takes a leaf certificate and version string to initialize the chain.
//
// Parameters:
//   - cert: The leaf certificate to start the chain from
//   - version: Version string for the chain (used for User-Agent headers)
//
// Returns:
//   - A pointer to the newly created certificate chain
//
// The returned chain can be used for fetching additional certificates,
// validating the chain, and checking revocation status.
func (d DefaultChainResolver) New(cert *x509.Certificate, version string) *x509chain.Chain {
	return x509chain.New(cert, version)
}

// ToolHandler defines the signature for tool handlers that matches [MCP] server expectations.
// It processes tool calls and returns results.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: The MCP tool call request containing arguments and metadata
//
// Returns:
//   - The tool execution result or an error if the tool failed
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type ToolHandler = func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)

// ToolHandlerWithConfig defines tool handlers that require access to server configuration.
// It extends ToolHandler to include a Config parameter for tools that need configuration data.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: The MCP tool call request containing arguments and metadata
//   - config: Pointer to the server configuration containing AI settings and other options
//
// Returns:
//   - The tool execution result or an error if the tool failed
//
// This type is used for tools that need access to configuration like AI API keys or timeouts.
type ToolHandlerWithConfig func(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error)

// ResourceHandler defines the signature for resource handlers that provide static or dynamic resources.
// It processes resource read requests and returns the resource contents.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: The MCP resource read request containing the resource URI
//
// Returns:
//   - A slice of resource contents or an error if the resource cannot be read
//
// Resource handlers can return multiple content items for complex resources.
type ResourceHandler = func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error)

// PromptHandler defines the signature for prompt handlers that provide predefined prompts.
// It processes prompt requests and returns prompt content with optional arguments.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - request: The MCP prompt request containing the prompt name and arguments
//
// Returns:
//   - The prompt result containing messages and description, or an error if the prompt is not found
//
// Prompt handlers are used for guided workflows like certificate analysis or security audits.
type PromptHandler = func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error)

// ToolDefinition holds a tool definition and its handler.
// It pairs an MCP tool specification with its implementation function.
//
// Fields:
//   - Tool: The MCP tool definition containing name, description, and input schema
//   - Handler: The function that implements the tool's logic
//
// This struct is used when registering tools that don't require configuration access.
type ToolDefinition struct {
	Tool    mcp.Tool
	Handler ToolHandler
}

// ToolDefinitionWithConfig holds a tool definition that requires configuration access.
// It pairs an MCP tool specification with a handler that receives server configuration.
//
// Fields:
//   - Tool: The MCP tool definition containing name, description, and input schema
//   - Handler: The function that implements the tool's logic with config access
//
// This struct is used for tools that need configuration like AI API keys or timeouts.
// The handler receives a Config parameter in addition to the standard context and request.
type ToolDefinitionWithConfig struct {
	Tool    mcp.Tool
	Handler ToolHandlerWithConfig
}

// ServerDependencies holds all dependencies needed to create the MCP server.
// It consolidates all required components for server initialization using the builder pattern.
//
// Fields:
//   - Config: Server configuration containing AI settings and other options
//   - Embed: Embedded filesystem for static resources and templates
//   - Version: Server version string for User-Agent headers and identification
//   - CertManager: Interface for certificate encoding/decoding operations
//   - ChainResolver: Interface for creating certificate chains
//   - Tools: List of tool definitions without configuration requirements
//   - ToolsWithConfig: List of tool definitions that need configuration access
//   - Resources: List of static and dynamic resources provided by the server
//   - Prompts: List of predefined prompts for guided workflows
//   - SamplingHandler: Handler for bidirectional AI communication and streaming responses
//
// This struct is used internally by ServerBuilder and should not be instantiated directly.
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

// ServerBuilder helps construct the [MCP] server with proper dependencies using a fluent interface.
// It implements the builder pattern to configure and create MCP servers with all required components.
//
// The builder allows chaining configuration methods and provides default implementations
// for common dependencies. Use NewServerBuilder() to create an instance, chain configuration
// methods, and call Build() to create the server.
//
// Example:
//
//	builder := NewServerBuilder().
//	    WithConfig(config).
//	    WithVersion("1.0.0").
//	    WithDefaultTools().
//	    WithSampling(samplingHandler)
//	server, err := builder.Build()
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type ServerBuilder struct{ deps ServerDependencies }

// NewServerBuilder creates a new server builder with default empty dependencies.
// It initializes a ServerBuilder instance that can be configured using the fluent interface methods.
//
// Returns:
//   - A pointer to a new ServerBuilder instance ready for configuration
//
// The returned builder has no dependencies configured and should be chained with
// configuration methods before calling Build().
func NewServerBuilder() *ServerBuilder { return &ServerBuilder{} }

// WithConfig sets the server configuration containing AI settings and other options.
// It configures the server with the provided Config struct.
//
// Parameters:
//   - config: Pointer to the server configuration (can be nil for basic functionality)
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// The configuration includes AI API settings, timeouts, and other server options.
// If config is nil, some features like AI analysis may not be available.
func (b *ServerBuilder) WithConfig(config *Config) *ServerBuilder {
	b.deps.Config = config
	return b
}

// WithEmbed sets the embedded filesystem for static resources and templates.
// It configures the server with an embedded filesystem containing templates and documentation.
//
// Parameters:
//   - embed: The embedded filesystem (typically from //go:embed directives)
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// The embedded filesystem is used to serve static resources like certificate format documentation
// and analysis templates. If not set, some resources may not be available.
func (b *ServerBuilder) WithEmbed(embed embed.FS) *ServerBuilder {
	b.deps.Embed = embed
	return b
}

// WithVersion sets the server version string used for identification and User-Agent headers.
// It configures the server with a version string that appears in logs and HTTP requests.
//
// Parameters:
//   - version: The server version string (e.g., "1.0.0" or "v1.2.3")
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// The version is used in User-Agent headers for HTTP requests and server identification.
func (b *ServerBuilder) WithVersion(version string) *ServerBuilder {
	b.deps.Version = version
	return b
}

// WithCertManager sets the certificate manager for encoding and decoding operations.
// It configures the server with a CertificateManager implementation for PEM/DER operations.
//
// Parameters:
//   - cm: The certificate manager implementation (must implement CertificateManager interface)
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// If not set, certificate encoding/decoding operations may not be available.
// The default implementation uses the internal certs package.
func (b *ServerBuilder) WithCertManager(cm CertificateManager) *ServerBuilder {
	b.deps.CertManager = cm
	return b
}

// WithChainResolver sets the chain resolver for creating certificate chains.
// It configures the server with a ChainResolver implementation for chain operations.
//
// Parameters:
//   - cr: The chain resolver implementation (must implement ChainResolver interface)
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// If not set, certificate chain resolution operations may not be available.
// The default implementation uses the internal chain package.
func (b *ServerBuilder) WithChainResolver(cr ChainResolver) *ServerBuilder {
	b.deps.ChainResolver = cr
	return b
}

// WithTools adds tool definitions to the server that don't require configuration access.
// It registers multiple tools that can be called by MCP clients.
//
// Parameters:
//   - tools: Variable number of ToolDefinition structs containing tool specs and handlers
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// Tools added with this method do not receive the server Config parameter.
// Use WithToolsWithConfig for tools that need configuration access.
func (b *ServerBuilder) WithTools(tools ...ToolDefinition) *ServerBuilder {
	b.deps.Tools = append(b.deps.Tools, tools...)
	return b
}

// WithToolsWithConfig adds tool definitions that require configuration access to the server.
// It registers multiple tools that receive the server Config parameter in their handlers.
//
// Parameters:
//   - tools: Variable number of ToolDefinitionWithConfig structs containing tool specs and handlers
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// Tools added with this method receive access to server configuration like AI API keys.
// Use WithTools for tools that don't need configuration access.
func (b *ServerBuilder) WithToolsWithConfig(tools ...ToolDefinitionWithConfig) *ServerBuilder {
	b.deps.ToolsWithConfig = append(b.deps.ToolsWithConfig, tools...)
	return b
}

// WithResources adds static and dynamic resources to the MCP server.
// It registers resources that can be read by MCP clients using resource URIs.
//
// Parameters:
//   - resources: Variable number of server.ServerResource structs containing resource specs and handlers
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// Resources can provide static content (like documentation) or dynamic content
// (like server status). Clients access resources using URIs like "info://version".
func (b *ServerBuilder) WithResources(resources ...server.ServerResource) *ServerBuilder {
	b.deps.Resources = append(b.deps.Resources, resources...)
	return b
}

// WithPrompts adds predefined prompts to the MCP server for guided workflows.
// It registers prompts that provide structured interactions for common tasks.
//
// Parameters:
//   - prompts: Variable number of server.ServerPrompt structs containing prompt specs and handlers
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// Prompts are used for workflows like certificate analysis or security audits,
// providing clients with predefined conversation starters and argument schemas.
func (b *ServerBuilder) WithPrompts(prompts ...server.ServerPrompt) *ServerBuilder {
	b.deps.Prompts = append(b.deps.Prompts, prompts...)
	return b
}

// WithSampling adds a sampling handler for bidirectional AI communication.
// It configures the server to support AI-powered features like certificate analysis.
//
// Parameters:
//   - handler: The sampling handler implementation for AI API integration
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// The sampling handler enables real-time AI analysis of certificates with streaming responses.
// If not set, AI-powered features will return static guidance messages.
func (b *ServerBuilder) WithSampling(handler client.SamplingHandler) *ServerBuilder {
	// Note: Sampling handler is stored but not in ServerDependencies
	// It's used during Build() to enable sampling on the server
	b.deps.SamplingHandler = handler
	return b
}

// WithDefaultTools adds the default X509 certificate tools to the server.
// It automatically registers all standard certificate-related tools using createTools.
//
// Returns:
//   - The ServerBuilder instance for method chaining
//
// This includes tools for certificate chain resolution, validation, expiry checking,
// remote certificate fetching, and AI-powered analysis. The tools are added to both
// the regular tools list and tools-with-config list as appropriate.
func (b *ServerBuilder) WithDefaultTools() *ServerBuilder {
	tools, toolsWithConfig := createTools()
	b.deps.Tools = append(b.deps.Tools, tools...)
	b.deps.ToolsWithConfig = append(b.deps.ToolsWithConfig, toolsWithConfig...)
	return b
}

// Build creates the [MCP] server with all configured dependencies.
// It validates the configuration and constructs a fully configured MCP server instance.
//
// Returns:
//   - A pointer to the configured MCPServer instance
//   - An error if the configuration is invalid or server creation fails
//
// The method enables sampling if a sampling handler was provided, registers all tools,
// resources, and prompts, and returns a ready-to-use server. The server will handle
// MCP protocol communication and route requests to the appropriate handlers.
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
	apiKey        string
	endpoint      string
	model         string
	timeout       time.Duration
	client        *http.Client
	version       string
	TokenCallback func(string) // Callback for streaming tokens
}

// NewDefaultSamplingHandler creates a new sampling handler with configurable AI settings
func NewDefaultSamplingHandler(config *Config, version string) *DefaultSamplingHandler {
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
	// Note: Buffer is primarily used for error response reading.
	// During successful streaming, it remains allocated but unused until the function returns.
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
func (h *DefaultSamplingHandler) sendAPIRequest(ctx context.Context, apiRequest map[string]any, _ gc.Buffer) (*http.Response, error) {
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
							// Stream token via callback if configured
							if h.TokenCallback != nil {
								h.TokenCallback(content)
							}
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
