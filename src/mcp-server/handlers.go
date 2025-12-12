// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
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

// It parses the template with dynamic data from the provided tools and returns the rendered instructions as a string for MCP client initialization.
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
