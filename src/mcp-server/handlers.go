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
	"github.com/mark3labs/mcp-go/server"
)

// instructionData holds the data used to populate the MCP server instructions template.
type instructionData struct {
	Tools     []toolInfo
	ToolRoles map[string]string // Maps tool roles to tool names for template use
}

// toolInfo represents information about an MCP tool for template rendering.
type toolInfo struct {
	Name        string
	Description string
}

// loadInstructions parses the template with dynamic data from the provided tools and returns the rendered instructions as a string for MCP client initialization.
//
// Parameters:
//   - tools: Slice of tool definitions without config requirements
//   - toolsWithConfig: Slice of tool definitions that require configuration access
//
// Returns:
//   - string: The rendered instruction text describing server capabilities and tool usage
//   - error: If the embedded file cannot be read or template parsing fails
//
// The instructions provide MCP clients with comprehensive guidance on using
// all available certificate analysis tools and workflows.
func loadInstructions(tools []ToolDefinition, toolsWithConfig []ToolDefinitionWithConfig) (string, error) {
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
		Tools:     toolInfos,
		ToolRoles: toolRoles,
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

// Cache structure for server capabilities
type serverCache struct {
	prompts         []map[string]any
	tools           []map[string]any
	toolsWithConfig []map[string]any
	resources       []map[string]any
}

// Global cache instance with sync.Once for thread-safe lazy initialization
var (
	cache     *serverCache
	cacheOnce sync.Once
)

// getServerCache returns the lazily initialized server cache.
// Uses sync.Once to ensure initialization happens exactly once, even with concurrent access.
func getServerCache() *serverCache {
	cacheOnce.Do(func() {
		cache = &serverCache{
			// Cache is populated dynamically through populate*MetadataCache functions
			// called from the ServerBuilder's Build() method when WithPopulate() is used
		}
	})
	return cache
}

// loadPromptsConfig loads the prompts configuration from the cache.
// Returns the prompts array with user-facing information only (filters out internal fields).
func loadPromptsConfig() ([]map[string]any, error) {
	cache := getServerCache()
	return cache.prompts, nil
}

// toolsConfig holds the structured configuration for tools and tools with config.
// This provides separate access to regular tools and tools requiring configuration.
type toolsConfig struct {
	Tools           []map[string]any // Regular tools not requiring config
	ToolsWithConfig []map[string]any // Tools that require configuration access
	AllTools        []map[string]any // Merged list for backward compatibility
}

// loadToolsConfig loads the tools configuration from the cache.
// Returns structured tool configuration with separate access to regular tools,
// tools with config, and merged list for backward compatibility.
func loadToolsConfig() (*toolsConfig, error) {
	cache := getServerCache()
	return &toolsConfig{
		Tools:           cache.tools[:len(cache.tools)-len(cache.toolsWithConfig)], // Regular tools
		ToolsWithConfig: cache.toolsWithConfig,                                     // Tools with config
		AllTools:        cache.tools,                                               // Merged list
	}, nil
}

// loadResourcesConfig loads the resources configuration from the cache.
// Returns the resources with user-facing information only (filters out internal fields).
func loadResourcesConfig() ([]map[string]any, error) {
	cache := getServerCache()
	return cache.resources, nil
}

// populateToolMetadataCache extracts metadata from created tools and caches it for resource handlers.
// This function is called once during server initialization via the ServerBuilder's Build() method
// when WithPopulate() is used. It processes tools created by the builder's tool registration methods.
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
// This function is called once during server initialization via the ServerBuilder's Build() method
// when WithPopulate() is used. It processes prompts created by the builder's prompt registration methods.
func populatePromptMetadataCache(serverCache *serverCache, prompts []server.ServerPrompt) {
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
// This function is called once during server initialization via the ServerBuilder's Build() method
// when WithPopulate() is used. It processes resources created by the builder's resource registration methods.
func populateResourceMetadataCache(serverCache *serverCache, resources []server.ServerResource) {
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
