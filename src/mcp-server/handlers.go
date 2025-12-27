// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"fmt"
	"maps"
	"strings"
	"sync"
	"text/template"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
)

// instructionData holds the data used to populate the MCP server instructions template.
//
// It is used internally by loadInstructions to prepare data for the
// embedded X509_instructions.md template. It contains processed tool information,
// role mappings, binary name, and version that help generate comprehensive server capability descriptions.
//
// Fields:
//   - Tools: Processed list of tool information extracted from tool definitions
//   - ToolRoles: Mapping of semantic tool roles to their actual tool names for template rendering
//   - BinaryName: The name of the binary executable for dynamic command examples
//   - Version: The server version for template rendering
type instructionData struct {
	// Tools: Processed list of tool information for template rendering
	Tools []toolInfo
	// ToolRoles: Mapping of tool roles to tool names for template use
	ToolRoles map[string]string
	// BinaryName: Dynamic binary name for command examples in instructions
	BinaryName string
	// Version: Server version for template rendering
	Version string
}

// toolInfo represents information about an MCP tool for template rendering.
//
// It is a lightweight struct used to pass tool metadata to the instructions template.
// It contains only the essential information needed for generating human-readable
// server capability descriptions.
//
// Fields:
//   - Name: The human-readable tool name for display in instructions
//   - Description: Brief description of what the tool does for user guidance
type toolInfo struct {
	// Name: Human-readable tool name for template rendering
	Name string
	// Description: Tool description for user guidance in instructions
	Description string
}

// loadInstructions parses the embedded instructions template with dynamic tool data.
//
// It is critical for MCP server initialization as it generates the
// instructions that clients receive during the handshake. It processes tool
// definitions, extracts metadata, and renders a comprehensive capability guide.
//
// The process involves:
//  1. Loading the embedded X509_instructions.md template
//  2. Processing tool definitions to extract names, descriptions, and roles
//  3. Building role mappings for template rendering
//  4. Executing the template with structured data including dynamic binary name and version
//
// Parameters:
//   - tools: Tool definitions without configuration requirements
//   - toolsWithConfig: Tool definitions that need configuration access
//   - binaryName: The name of the binary executable for dynamic command examples
//   - version: The server version for template rendering
//
// Returns:
//   - string: Rendered instructions describing all server capabilities
//   - error: Template loading, parsing, or execution failures
//
// The generated instructions help MCP clients understand available tools,
// their purposes, and how to interact with the certificate analysis server.
func loadInstructions(tools []ToolDefinition, toolsWithConfig []ToolDefinitionWithConfig, binaryName, version string) (string, error) {
	// Read the template file
	templateBytes, err := templates.MagicEmbed.ReadFile("X509_instructions.md")
	if err != nil {
		return "", fmt.Errorf("failed to load MCP server instructions template: %w", err)
	}

	// Extract tool info and build role mappings for template
	var toolInfos []toolInfo
	toolRoles := make(map[string]string)

	for _, tool := range tools {
		toolName := string(tool.Tool.Name)
		toolInfos = append(toolInfos, toolInfo{
			Name:        toolName,
			Description: tool.Tool.Description,
		})

		// Use the Role defined in the tool definition
		if tool.Role != "" {
			toolRoles[tool.Role] = toolName
		}
	}

	for _, tool := range toolsWithConfig {
		toolName := string(tool.Tool.Name)
		toolInfos = append(toolInfos, toolInfo{
			Name:        toolName,
			Description: tool.Tool.Description,
		})

		// Use the Role defined in the tool definition
		if tool.Role != "" {
			toolRoles[tool.Role] = toolName
		}
	}

	// Prepare data for template
	data := instructionData{
		Tools:      toolInfos,
		ToolRoles:  toolRoles,
		BinaryName: binaryName,
		Version:    version,
	}

	// Parse the template
	//
	// TODO: Separate template and make it package level to generate dynamic content in the templates/ directory for reusability
	tmpl, err := template.New("instructions").Parse(string(templateBytes))
	if err != nil {
		return "", fmt.Errorf("failed to parse instructions template: %w", err)
	}

	// Execute the template
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute instructions template: %w", err)
	}

	return buf.String(), nil
}

// serverCache provides thread-safe metadata caching for MCP server capabilities.
//
// It caches processed metadata for tools, prompts, and resources to avoid
// repeated computation during resource handler requests. It is populated once during
// server initialization and accessed read-only thereafter.
//
// The cache improves performance for resource handlers that need to expose server
// capabilities metadata, reducing computation overhead on each request.
//
// Fields:
//   - prompts: Cached prompt metadata with names, descriptions, and argument schemas
//   - tools: Cached metadata for regular tools (no config requirements)
//   - toolsWithConfig: Cached metadata for tools requiring configuration access
//   - resources: Cached resource metadata with URIs, names, and descriptions
type serverCache struct {
	// prompts: Cached metadata for MCP prompts with argument schemas
	prompts []map[string]any
	// tools: Cached metadata for regular tools (without config requirements)
	tools []map[string]any
	// toolsWithConfig: Cached metadata for tools requiring configuration access
	toolsWithConfig []map[string]any
	// resources: Cached metadata for MCP resources with URIs and descriptions
	resources []map[string]any
}

// Global cache instance with sync.Once for thread-safe lazy initialization
var (
	cache     *serverCache
	cacheOnce sync.Once
)

// getServerCache returns the lazily initialized server cache singleton.
//
// It implements the singleton pattern using sync.Once to ensure
// thread-safe initialization of the server cache. The cache is populated
// during server initialization via the populate*MetadataCache functions.
//
// The lazy initialization ensures the cache is only created when first accessed,
// which happens during resource handler requests when WithPopulate() is used.
//
// Returns:
//   - *serverCache: The initialized server cache instance
//
// Thread Safety: Safe for concurrent access from multiple goroutines.
func getServerCache() *serverCache {
	cacheOnce.Do(func() {
		cache = &serverCache{
			// Cache is populated dynamically through populate*MetadataCache functions
			// called from the ServerBuilder's Build() method when WithPopulate() is used
		}
	})
	return cache
}

// loadPromptsConfig loads the prompts configuration from the server cache.
//
// It provides access to cached prompt metadata for resource handlers.
// The returned data includes prompt names, descriptions, arguments, and metadata
// that resource handlers can expose to clients.
//
// The prompts configuration is populated once during server initialization
// and remains static throughout the server lifecycle.
//
// Returns:
//   - []map[string]any: Array of prompt metadata for resource handlers
//   - error: Always nil (cache access doesn't fail)
//
// The metadata includes:
// - Prompt names and descriptions
// - Argument schemas with names, descriptions, and required flags
// - Additional metadata fields from the prompt definitions
func loadPromptsConfig() ([]map[string]any, error) {
	cache := getServerCache()
	return cache.prompts, nil
}

// toolsConfig holds the structured configuration for tools and tools with config.
//
// It provides organized access to different categories of tools for resource
// handlers. It separates regular tools from those requiring configuration, while
// also providing a merged view for backward compatibility.
//
// Fields:
//   - Tools: Regular tools that don't require configuration access
//   - ToolsWithConfig: Tools that receive server configuration parameters
//   - AllTools: Merged list of all tools for unified access when needed
type toolsConfig struct {
	// Tools: Regular tools not requiring configuration access
	Tools []map[string]any
	// ToolsWithConfig: Tools that require configuration access
	ToolsWithConfig []map[string]any
	// AllTools: Merged list of all tools for backward compatibility
	AllTools []map[string]any
}

// loadToolsConfig loads the tools configuration from the server cache.
//
// This function creates a structured toolsConfig instance that separates regular
// tools from those requiring configuration access. It provides multiple access
// patterns for different use cases in resource handlers.
//
// The function splits the cached tools array to separate regular tools from
// tools-with-config based on the original registration order during server build.
//
// Returns:
//   - *toolsConfig: Structured tool configuration with categorized access
//   - error: Always nil (cache access doesn't fail)
//
// The returned config provides:
// - Tools: Regular tools (first N items from cache)
// - ToolsWithConfig: Tools requiring config (remaining items)
// - AllTools: Complete merged list for unified access
func loadToolsConfig() (*toolsConfig, error) {
	cache := getServerCache()
	return &toolsConfig{
		Tools:           cache.tools[:len(cache.tools)-len(cache.toolsWithConfig)], // Regular tools
		ToolsWithConfig: cache.toolsWithConfig,                                     // Tools with config
		AllTools:        cache.tools,                                               // Merged list
	}, nil
}

// loadResourcesConfig loads the resources configuration from the server cache.
//
// It provides access to cached resource metadata for resource handlers.
// The returned data includes resource URIs, names, descriptions, MIME types,
// and metadata that resource handlers can expose to clients.
//
// The resources configuration is populated once during server initialization
// and remains static throughout the server lifecycle.
//
// Returns:
//   - []map[string]any: Array of resource metadata for resource handlers
//   - error: Always nil (cache access doesn't fail)
//
// The metadata includes:
// - Resource URIs for client access
// - Human-readable names and descriptions
// - MIME types for content type indication
// - Additional metadata fields from resource definitions
func loadResourcesConfig() ([]map[string]any, error) {
	cache := getServerCache()
	return cache.resources, nil
}

// populateToolMetadataCache extracts metadata from created tools and caches it for resource handlers.
//
// It is called once during server initialization when WithPopulate() is used
// on the ServerBuilder. It processes all registered tools and creates a flattened
// metadata representation suitable for resource handlers to expose server capabilities.
//
// The function separates regular tools from tools-with-config to maintain the
// distinction needed by loadToolsConfig() for proper categorization.
//
// Parameters:
//   - serverCache: The server cache instance to populate with tool metadata
//   - tools: Regular tool definitions without configuration requirements
//   - toolsWithConfig: Tool definitions that require configuration access
//
// Processing:
//  1. Extract metadata from regular tools (name, description)
//  2. Extract metadata from config-requiring tools
//  3. Merge both lists into a single AllTools array
//
// The resulting cache enables resource handlers to dynamically expose tool
// capabilities without hardcoding tool lists.
func populateToolMetadataCache(serverCache *serverCache, tools []ToolDefinition, toolsWithConfig []ToolDefinitionWithConfig) {
	serverCache.tools = make([]map[string]any, 0, len(tools))
	serverCache.toolsWithConfig = make([]map[string]any, 0, len(toolsWithConfig))

	// Extract metadata from regular tools
	for _, toolDef := range tools {
		tool := toolDef.Tool
		metadata := map[string]any{
			"name":        tool.Name,
			"description": tool.Description,
		}
		serverCache.tools = append(serverCache.tools, metadata)
	}

	// Extract metadata from tools with config
	for _, toolDef := range toolsWithConfig {
		tool := toolDef.Tool
		metadata := map[string]any{
			"name":        tool.Name,
			"description": tool.Description,
		}
		serverCache.toolsWithConfig = append(serverCache.toolsWithConfig, metadata)
	}

	// Merge tools and toolsWithConfig for the loadToolsConfig function
	// This provides the AllTools field in toolsConfig for resource handlers
	allTools := make([]map[string]any, 0, len(serverCache.tools)+len(serverCache.toolsWithConfig))
	allTools = append(allTools, serverCache.tools...)
	allTools = append(allTools, serverCache.toolsWithConfig...)
	serverCache.tools = allTools
}

// populatePromptMetadataCache extracts metadata from created prompts and caches it for resource handlers.
//
// It processes MCP prompt definitions during server initialization
// to create a cache of prompt metadata. It extracts names, descriptions,
// argument schemas, and additional metadata for resource handler access.
//
// The function handles complex prompt structures including:
// - Basic prompt information (name, description)
// - Argument definitions with names, descriptions, and required flags
// - Additional metadata fields from the prompt definitions
// - Proper handling of optional meta fields and progress tokens
//
// Parameters:
//   - serverCache: The server cache instance to populate with prompt metadata
//   - prompts: Array of MCP prompt definitions from server registration
//
// The cached metadata enables resource handlers to expose prompt capabilities
// dynamically, supporting discovery and documentation of available prompts.
func populatePromptMetadataCache(serverCache *serverCache, prompts []ServerPrompt) {
	serverCache.prompts = make([]map[string]any, 0, len(prompts))

	for _, promptDef := range prompts {
		prompt := promptDef.Prompt
		metadata := map[string]any{
			"name":        prompt.Name,
			"description": prompt.Description,
		}

		// Extract arguments
		if len(prompt.Arguments) > 0 {
			args := make([]map[string]any, 0, len(prompt.Arguments))
			for _, arg := range prompt.Arguments {
				argMap := map[string]any{
					"name":        arg.Name,
					"description": arg.Description,
					"required":    arg.Required,
				}
				args = append(args, argMap)
			}
			metadata["arguments"] = args
		}

		// Extract meta information
		if prompt.Meta != nil {
			// Convert Meta struct to map for JSON serialization
			metaMap := make(map[string]any)
			maps.Copy(metaMap, prompt.Meta.AdditionalFields)
			// Remove any null/empty progressToken that might be set by MCP library
			if progressToken, exists := metaMap["progressToken"]; exists {
				if progressToken == nil || progressToken == "" || progressToken == "null" {
					delete(metaMap, "progressToken")
				}
			}
			if len(metaMap) > 0 {
				metadata["meta"] = metaMap
			}
		}

		serverCache.prompts = append(serverCache.prompts, metadata)
	}
}

// populateResourceMetadataCache extracts metadata from created resources and caches it for resource handlers.
//
// It processes MCP resource definitions during server initialization
// to create a cache of resource metadata. It extracts URIs, names, descriptions,
// MIME types, and additional metadata for resource handler access.
//
// The function handles resource meta fields carefully, filtering out
// implementation-specific fields like progress tokens that shouldn't be
// exposed to clients.
//
// Parameters:
//   - serverCache: The server cache instance to populate with resource metadata
//   - resources: Array of MCP resource definitions from server registration
//
// The cached metadata enables resource handlers to expose resource capabilities
// dynamically, supporting discovery and documentation of available resources.
//
// Processed metadata includes:
// - Resource URIs for client access
// - Human-readable names and descriptions
// - MIME types for content negotiation
// - Filtered metadata fields (excluding internal fields)
func populateResourceMetadataCache(serverCache *serverCache, resources []ServerResource) {
	serverCache.resources = make([]map[string]any, 0, len(resources))

	for _, resourceDef := range resources {
		resource := resourceDef.Resource
		metadata := map[string]any{
			"uri":         resource.URI,
			"name":        resource.Name,
			"description": resource.Description,
			"mimeType":    resource.MIMEType,
		}

		// Extract meta information
		if resource.Meta != nil {
			// Convert Meta struct to map for JSON serialization
			metaMap := make(map[string]any)
			maps.Copy(metaMap, resource.Meta.AdditionalFields)
			// Remove any null/empty progressToken that might be set by MCP library
			if progressToken, exists := metaMap["progressToken"]; exists {
				if progressToken == nil || progressToken == "" || progressToken == "null" {
					delete(metaMap, "progressToken")
				}
			}
			if len(metaMap) > 0 {
				metadata["meta"] = metaMap
			}
		}

		serverCache.resources = append(serverCache.resources, metadata)
	}
}
