// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package codegen

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
)

// Config holds the loaded configuration
type Config struct {
	Resources []ResourceDefinition `json:"resources"`
	Tools     []ToolDefinition     `json:"tools"`
}

// ResourceDefinition represents a resource to be generated
type ResourceDefinition struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MIMEType    string `json:"mimeType"`
	Handler     string `json:"handler"`
}

// ToolDefinition represents a tool to be generated
type ToolDefinition struct {
	ConstName   string      `json:"constName"`
	Name        string      `json:"name"`
	Comment     string      `json:"comment"`
	Description string      `json:"description"`
	Handler     string      `json:"handler"`
	RoleConst   string      `json:"roleConst"`
	RoleName    string      `json:"roleName"`
	RoleComment string      `json:"roleComment"`
	WithConfig  bool        `json:"withConfig"`
	Params      []ToolParam `json:"params"`
}

// ToolParam represents a parameter for a tool
type ToolParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // string, number, boolean
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"` // For documentation or default value
}

// getCodegenDir returns the absolute path to the codegen directory
func getCodegenDir() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(currentFile)) // Go up from internal/ to codegen/
}

// getTemplatePath returns the path to a template file
func getTemplatePath(templateName string) string {
	return filepath.Join(getCodegenDir(), "templates", templateName)
}

// getOutputPath returns the path to an output file
func getOutputPath(outputName string) string {
	return filepath.Join(getCodegenDir(), "..", "..", "src", "mcp-server", outputName)
}

// loadConfig loads the configuration from JSON files
func loadConfig() (*Config, error) {
	config := &Config{}

	codegenDir := getCodegenDir()

	// Load resources
	resourcesPath := filepath.Join(codegenDir, "config", "resources.json")
	resourcesData, err := os.ReadFile(resourcesPath)
	if err != nil {
		return nil, fmt.Errorf("reading resources config from %s: %w", resourcesPath, err)
	}

	var resourcesWrapper struct {
		Resources []ResourceDefinition `json:"resources"`
	}
	if err := json.Unmarshal(resourcesData, &resourcesWrapper); err != nil {
		return nil, fmt.Errorf("parsing resources config: %w", err)
	}
	config.Resources = resourcesWrapper.Resources

	// Load tools
	toolsPath := filepath.Join(codegenDir, "config", "tools.json")
	toolsData, err := os.ReadFile(toolsPath)
	if err != nil {
		return nil, fmt.Errorf("reading tools config from %s: %w", toolsPath, err)
	}

	var toolsWrapper struct {
		Tools []ToolDefinition `json:"tools"`
	}
	if err := json.Unmarshal(toolsData, &toolsWrapper); err != nil {
		return nil, fmt.Errorf("parsing tools config: %w", err)
	}
	config.Tools = toolsWrapper.Tools

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return config, nil
}

// validateConfig validates the loaded configuration
func validateConfig(config *Config) error {
	if err := validateResources(config.Resources); err != nil {
		return err
	}
	if err := validateTools(config.Tools); err != nil {
		return err
	}
	return nil
}

// validateResources validates resource definitions
func validateResources(resources []ResourceDefinition) error {
	resourceURIs := make(map[string]bool)
	for i, res := range resources {
		if res.URI == "" {
			return fmt.Errorf("resource %d: URI is required", i)
		}
		if res.Name == "" {
			return fmt.Errorf("resource %d: Name is required", i)
		}
		if res.Handler == "" {
			return fmt.Errorf("resource %d: Handler is required", i)
		}
		if resourceURIs[res.URI] {
			return fmt.Errorf("resource %d: duplicate URI '%s'", i, res.URI)
		}
		resourceURIs[res.URI] = true
	}
	return nil
}

// validateTools validates tool definitions
func validateTools(tools []ToolDefinition) error {
	toolNames := make(map[string]bool)
	roleNames := make(map[string]bool)
	for i, tool := range tools {
		if err := validateTool(&tool, i, toolNames, roleNames); err != nil {
			return err
		}
	}
	return nil
}

// validateTool validates a single tool definition
func validateTool(tool *ToolDefinition, index int, toolNames, roleNames map[string]bool) error {
	if tool.Name == "" {
		return fmt.Errorf("tool %d: Name is required", index)
	}
	if tool.ConstName == "" {
		return fmt.Errorf("tool %d: ConstName is required", index)
	}
	if tool.Handler == "" {
		return fmt.Errorf("tool %d: Handler is required", index)
	}
	if tool.RoleConst == "" {
		return fmt.Errorf("tool %d: RoleConst is required", index)
	}
	if toolNames[tool.Name] {
		return fmt.Errorf("tool %d: duplicate name '%s'", index, tool.Name)
	}
	if roleNames[tool.RoleName] {
		return fmt.Errorf("tool %d: duplicate role name '%s'", index, tool.RoleName)
	}
	toolNames[tool.Name] = true
	roleNames[tool.RoleName] = true

	return validateToolParams(tool.Params, index)
}

// validateToolParams validates tool parameters
func validateToolParams(params []ToolParam, toolIndex int) error {
	paramNames := make(map[string]bool)
	for j, param := range params {
		if param.Name == "" {
			return fmt.Errorf("tool %d param %d: Name is required", toolIndex, j)
		}
		if param.Type == "" {
			return fmt.Errorf("tool %d param %d: Type is required", toolIndex, j)
		}
		if param.Type != "string" && param.Type != "number" && param.Type != "boolean" {
			return fmt.Errorf("tool %d param %d: invalid type '%s', must be string, number, or boolean", toolIndex, j, param.Type)
		}
		if paramNames[param.Name] {
			return fmt.Errorf("tool %d param %d: duplicate parameter name '%s'", toolIndex, j, param.Name)
		}
		paramNames[param.Name] = true
	}
	return nil
}

// GenerateResources generates the resources.go file for the MCP server
func GenerateResources() error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	templatePath := getTemplatePath("resources.go.tmpl")
	outputPath := getOutputPath("resources.go")

	return generateFile(templatePath, outputPath, config, "resources")
}

// generateFile generates a file using a template
func generateFile(templatePath, outputPath string, config *Config, fileType string) error {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("parsing template from %s: %w", templatePath, err)
	}

	var code bytes.Buffer

	// Header
	writeHeader(&code)

	// Package and imports
	code.WriteString("package mcpserver\n\n")
	code.WriteString("import (\n")
	if fileType == "resources" {
		code.WriteString("\t\"github.com/mark3labs/mcp-go/mcp\"\n")
		code.WriteString("\t\"github.com/mark3labs/mcp-go/server\"\n")
	} else {
		code.WriteString("\t\"github.com/mark3labs/mcp-go/mcp\"\n")
	}
	code.WriteString(")\n\n")

	// Execute template
	if err := tmpl.Execute(&code, config); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return writeGeneratedFile(outputPath, code.Bytes())
}

// GenerateTools generates the tools.go file for the MCP server
func GenerateTools() error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	templatePath := getTemplatePath("tools.go.tmpl")
	outputPath := getOutputPath("tools.go")

	return generateFile(templatePath, outputPath, config, "tools")
}

func writeHeader(code *bytes.Buffer) {
	code.WriteString("// Copyright (c) 2025 H0llyW00dzZ All rights reserved.\n")
	code.WriteString("//\n")
	code.WriteString("// By accessing or using this software, you agree to be bound by the terms\n")
	code.WriteString("// of the License Agreement, which you can find at LICENSE files.\n\n")
	code.WriteString("// Code generated by go generate; DO NOT EDIT.\n")
	code.WriteString("// This file is generated from tools/codegen/internal/codegen.go\n\n")
}

func writeGeneratedFile(filename string, content []byte) error {
	// Format the generated code
	formatted, err := format.Source(content)
	if err != nil {
		return fmt.Errorf("formatting code: %w", err)
	}

	// Write to the generated file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	_, err = writer.Write(formatted)
	if err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flushing file: %w", err)
	}

	fmt.Printf("Generated %s successfully\n", filename)
	return nil
}
