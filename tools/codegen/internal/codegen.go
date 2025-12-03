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
	Prompts   []PromptDefinition   `json:"prompts"`
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

// PromptDefinition represents a prompt to be generated
type PromptDefinition struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Handler     string           `json:"handler"`
	Arguments   []PromptArgument `json:"arguments"`
}

// PromptArgument represents an argument for a prompt
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
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

	// Load resources
	var resourcesWrapper struct {
		Resources []ResourceDefinition `json:"resources"`
	}
	if err := loadJSON("resources.json", &resourcesWrapper); err != nil {
		return nil, err
	}
	config.Resources = resourcesWrapper.Resources

	// Load tools
	var toolsWrapper struct {
		Tools []ToolDefinition `json:"tools"`
	}
	if err := loadJSON("tools.json", &toolsWrapper); err != nil {
		return nil, err
	}
	config.Tools = toolsWrapper.Tools

	// Load prompts
	var promptsWrapper struct {
		Prompts []PromptDefinition `json:"prompts"`
	}
	if err := loadJSON("prompts.json", &promptsWrapper); err != nil {
		return nil, err
	}
	config.Prompts = promptsWrapper.Prompts

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return config, nil
}

// loadJSON helper to reduce duplication in loading config files
func loadJSON(filename string, target any) error {
	path := filepath.Join(getCodegenDir(), "config", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config from %s: %w", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parsing config from %s: %w", path, err)
	}
	return nil
}

// validateConfig validates the loaded configuration
func validateConfig(config *Config) error {
	if err := validateResources(config.Resources); err != nil {
		return err
	}
	if err := validateTools(config.Tools); err != nil {
		return err
	}
	if err := validatePrompts(config.Prompts); err != nil {
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

// validatePrompts validates prompt definitions
func validatePrompts(prompts []PromptDefinition) error {
	promptNames := make(map[string]bool)
	for i, prompt := range prompts {
		if prompt.Name == "" {
			return fmt.Errorf("prompt %d: Name is required", i)
		}
		if prompt.Handler == "" {
			return fmt.Errorf("prompt %d: Handler is required", i)
		}
		if promptNames[prompt.Name] {
			return fmt.Errorf("prompt %d: duplicate name '%s'", i, prompt.Name)
		}
		promptNames[prompt.Name] = true

		if err := validatePromptArguments(prompt.Arguments, i); err != nil {
			return err
		}
	}
	return nil
}

// validatePromptArguments validates prompt arguments
func validatePromptArguments(args []PromptArgument, promptIndex int) error {
	argNames := make(map[string]bool)
	for j, arg := range args {
		if arg.Name == "" {
			return fmt.Errorf("prompt %d arg %d: Name is required", promptIndex, j)
		}
		if argNames[arg.Name] {
			return fmt.Errorf("prompt %d arg %d: duplicate argument name '%s'", promptIndex, j, arg.Name)
		}
		argNames[arg.Name] = true
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
	if fileType == "resources" || fileType == "prompts" {
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

// GeneratePrompts generates the prompts.go file for the MCP server
func GeneratePrompts() error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	templatePath := getTemplatePath("prompts.go.tmpl")
	outputPath := getOutputPath("prompts.go")

	return generateFile(templatePath, outputPath, config, "prompts")
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
