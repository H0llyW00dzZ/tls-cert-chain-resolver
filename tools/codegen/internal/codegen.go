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
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Config holds the loaded configuration for code generation.
//
// It contains definitions for MCP server resources, tools, and prompts
// that will be used to generate Go code.
type Config struct {
	Resources []ResourceDefinition `json:"resources"`
	Tools     []ToolDefinition     `json:"tools"`
	Prompts   []PromptDefinition   `json:"prompts"`
}

// ResourceDefinition represents a resource to be generated
type ResourceDefinition struct {
	URI         string         `json:"uri"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	MIMEType    string         `json:"mimeType"`
	Handler     string         `json:"handler"`
	WithEmbed   bool           `json:"withEmbed,omitempty"` // Whether resource needs embed access
	Audience    []string       `json:"audience,omitempty"`  // MCP annotation audience roles
	Priority    *float64       `json:"priority,omitempty"`  // MCP annotation priority
	Meta        map[string]any `json:"meta,omitempty"`      // Additional metadata fields
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
	// MCP annotations for LLM hints
	TitleAnnotation           string `json:"titleAnnotation,omitempty"`
	ReadOnlyHintAnnotation    bool   `json:"readOnlyHintAnnotation,omitempty"`
	DestructiveHintAnnotation bool   `json:"destructiveHintAnnotation,omitempty"`
	IdempotentHintAnnotation  bool   `json:"idempotentHintAnnotation,omitempty"`
	OpenWorldHintAnnotation   bool   `json:"openWorldHintAnnotation,omitempty"`
	// Additional metadata
	Meta map[string]any `json:"meta,omitempty"`
}

// ToolParam represents a parameter for a tool
type ToolParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // string, number, boolean, array, object
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"` // For documentation or default value
	// Parameter constraints
	Enum       []string       `json:"enum,omitempty"`       // Allowed values
	MinLength  *int           `json:"minLength,omitempty"`  // Minimum string length
	MaxLength  *int           `json:"maxLength,omitempty"`  // Maximum string length
	Minimum    *float64       `json:"minimum,omitempty"`    // Minimum number value
	Maximum    *float64       `json:"maximum,omitempty"`    // Maximum number value
	Pattern    string         `json:"pattern,omitempty"`    // Regex pattern for strings
	Items      map[string]any `json:"items,omitempty"`      // Schema for array items
	Properties map[string]any `json:"properties,omitempty"` // Schema for object properties
}

// PromptDefinition represents a prompt to be generated
type PromptDefinition struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Handler     string           `json:"handler"`
	WithEmbed   bool             `json:"withEmbed,omitempty"` // Whether prompt needs embed access
	Arguments   []PromptArgument `json:"arguments"`
	Audience    []string         `json:"audience,omitempty"` // MCP annotation audience roles
	Priority    *float64         `json:"priority,omitempty"` // MCP annotation priority
	Meta        map[string]any   `json:"meta,omitempty"`     // Additional metadata fields
}

// PromptArgument represents an argument for a prompt
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required,omitempty"` // Whether the argument is required
}

// getCodegenDir returns the path to the codegen directory.
// It uses runtime.Caller to determine the current file's location
// and navigates up two directory levels from internal/ to codegen/.
func getCodegenDir() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(currentFile)) // Go up from internal/ to codegen/
}

// getTemplatePath returns the path to a template file.
// It constructs the full path to the templates directory
// for the specified template file name.
func getTemplatePath(templateName string) string {
	return filepath.Join(getCodegenDir(), "templates", templateName)
}

// getOutputPath returns the path to an output file.
// It constructs the full path relative to the codegen directory
// for the specified output file name.
func getOutputPath(outputName string) string {
	return filepath.Join(getCodegenDir(), "..", "..", "src", "mcp-server", outputName)
}

// loadConfig loads the configuration from JSON files.
// It reads resources.json, tools.json, and prompts.json to build
// the complete configuration for code generation.
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

	// Validate against JSON schema
	schemaPath := filepath.Join(getCodegenDir(), "config", strings.TrimSuffix(filename, ".json")+".schema.json")
	if err := validateJSONSchema(data, schemaPath); err != nil {
		return fmt.Errorf("validating config from %s: %w", path, err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parsing config from %s: %w", path, err)
	}
	return nil
}

// validateJSONSchema validates JSON data against a JSON schema.
// It reads the schema file and uses gojsonschema to validate
// the provided JSON data against the schema.
func validateJSONSchema(jsonData []byte, schemaPath string) error {
	// Read schema file
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("reading schema file %s: %w", schemaPath, err)
	}

	schemaLoader := gojsonschema.NewBytesLoader(schemaData)
	documentLoader := gojsonschema.NewBytesLoader(jsonData)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("schema validation error: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, desc.String())
		}
		return fmt.Errorf("JSON schema validation failed:\n%s", strings.Join(errors, "\n"))
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
	validRoles := map[string]bool{
		"user":      true,
		"assistant": true,
	}
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

		// Validate audience roles
		for _, role := range res.Audience {
			if !validRoles[role] {
				return fmt.Errorf("resource %d: invalid audience role '%s', must be one of: user, assistant", i, role)
			}
		}

		// Validate priority
		if res.Priority != nil && (*res.Priority < 0.0 || *res.Priority > 10.0) {
			return fmt.Errorf("resource %d: priority must be between 0.0 and 10.0, got %f", i, *res.Priority)
		}
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
		if param.Type != "string" && param.Type != "number" && param.Type != "boolean" && param.Type != "array" && param.Type != "object" {
			return fmt.Errorf("tool %d param %d: invalid type '%s', must be string, number, boolean, array, or object", toolIndex, j, param.Type)
		}
		if paramNames[param.Name] {
			return fmt.Errorf("tool %d param %d: duplicate parameter name '%s'", toolIndex, j, param.Name)
		}
		paramNames[param.Name] = true

		// Validate parameter constraints
		if err := validateParamConstraints(&param, toolIndex, j); err != nil {
			return err
		}
	}
	return nil
}

// validateEnumConstraints validates enum values based on parameter type
func validateEnumConstraints(param *ToolParam, toolIndex, paramIndex int) error {
	if len(param.Enum) == 0 {
		return nil
	}

	switch param.Type {
	case "string":
		// String enums are always valid
		return nil
	case "number":
		// Number enums should be numeric strings that can be parsed
		for _, val := range param.Enum {
			if _, err := strconv.ParseFloat(val, 64); err != nil {
				return fmt.Errorf("tool %d param %d: enum value '%s' is not a valid number", toolIndex, paramIndex, val)
			}
		}
		return nil
	case "boolean":
		// Boolean enums should be "true" or "false"
		for _, val := range param.Enum {
			if val != "true" && val != "false" {
				return fmt.Errorf("tool %d param %d: enum value '%s' is not a valid boolean", toolIndex, paramIndex, val)
			}
		}
		return nil
	default:
		return fmt.Errorf("tool %d param %d: enum is not supported for type '%s'", toolIndex, paramIndex, param.Type)
	}
}

// validateLengthConstraints validates minLength/maxLength constraints for strings
func validateLengthConstraints(param *ToolParam, toolIndex, paramIndex int) error {
	if param.Type == "string" {
		if param.MinLength != nil && param.MaxLength != nil && *param.MinLength > *param.MaxLength {
			return fmt.Errorf("tool %d param %d: minLength (%d) cannot be greater than maxLength (%d)", toolIndex, paramIndex, *param.MinLength, *param.MaxLength)
		}
	} else if param.MinLength != nil || param.MaxLength != nil {
		return fmt.Errorf("tool %d param %d: minLength/maxLength constraints are only valid for string type", toolIndex, paramIndex)
	}
	return nil
}

// validateNumericConstraints validates minimum/maximum constraints for numbers
func validateNumericConstraints(param *ToolParam, toolIndex, paramIndex int) error {
	if param.Type == "number" {
		if param.Minimum != nil && param.Maximum != nil && *param.Minimum > *param.Maximum {
			return fmt.Errorf("tool %d param %d: minimum (%f) cannot be greater than maximum (%f)", toolIndex, paramIndex, *param.Minimum, *param.Maximum)
		}
	} else if param.Minimum != nil || param.Maximum != nil {
		return fmt.Errorf("tool %d param %d: minimum/maximum constraints are only valid for number type", toolIndex, paramIndex)
	}
	return nil
}

// validatePatternConstraints validates pattern constraints for strings
func validatePatternConstraints(param *ToolParam, toolIndex, paramIndex int) error {
	if param.Type != "string" && param.Pattern != "" {
		return fmt.Errorf("tool %d param %d: pattern constraint is only valid for string type", toolIndex, paramIndex)
	}
	return nil
}

// validateItemsConstraints validates items constraints for arrays
func validateItemsConstraints(param *ToolParam, toolIndex, paramIndex int) error {
	if param.Type != "array" && len(param.Items) > 0 {
		return fmt.Errorf("tool %d param %d: items constraint is only valid for array type", toolIndex, paramIndex)
	}
	return nil
}

// validatePropertiesConstraints validates properties constraints for objects
func validatePropertiesConstraints(param *ToolParam, toolIndex, paramIndex int) error {
	if param.Type != "object" && len(param.Properties) > 0 {
		return fmt.Errorf("tool %d param %d: properties constraint is only valid for object type", toolIndex, paramIndex)
	}
	return nil
}

// validateParamConstraints validates parameter-specific constraints
func validateParamConstraints(param *ToolParam, toolIndex, paramIndex int) error {
	if err := validateEnumConstraints(param, toolIndex, paramIndex); err != nil {
		return err
	}
	if err := validateLengthConstraints(param, toolIndex, paramIndex); err != nil {
		return err
	}
	if err := validateNumericConstraints(param, toolIndex, paramIndex); err != nil {
		return err
	}
	if err := validatePatternConstraints(param, toolIndex, paramIndex); err != nil {
		return err
	}
	if err := validateItemsConstraints(param, toolIndex, paramIndex); err != nil {
		return err
	}
	if err := validatePropertiesConstraints(param, toolIndex, paramIndex); err != nil {
		return err
	}
	return nil
}

// validatePrompts validates prompt definitions
func validatePrompts(prompts []PromptDefinition) error {
	promptNames := make(map[string]bool)
	validRoles := map[string]bool{
		"user":      true,
		"assistant": true,
	}
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

		// Validate audience roles
		for _, role := range prompt.Audience {
			if !validRoles[role] {
				return fmt.Errorf("prompt %d: invalid audience role '%s', must be one of: user, assistant", i, role)
			}
		}

		// Validate priority
		if prompt.Priority != nil && (*prompt.Priority < 0.0 || *prompt.Priority > 10.0) {
			return fmt.Errorf("prompt %d: priority must be between 0.0 and 10.0, got %f", i, *prompt.Priority)
		}

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

// GenerateResources generates the resources.go file for the MCP server.
//
// It loads the configuration, processes resource definitions, and generates
// Go code that implements MCP server resources with their handlers.
//
// Returns:
//   - error: Error if configuration loading or file generation fails
func GenerateResources() error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	templatePath := getTemplatePath("resources.go.tmpl")
	outputPath := getOutputPath("resources.go")

	return generateFile(templatePath, outputPath, config, "resources")
}

// toGoMap converts a map[string]any to Go map literal syntax
func toGoMap(m map[string]any) string {
	if len(m) == 0 {
		return "nil"
	}

	// Sort keys for deterministic output
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%q: %s", k, formatGoValue(m[k])))
	}

	return fmt.Sprintf("map[string]any{%s}", strings.Join(parts, ", "))
}

// formatGoValue formats a value as Go literal syntax
func formatGoValue(v any) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", val)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val)
	case float32, float64:
		return fmt.Sprintf("%g", val)
	case bool:
		return fmt.Sprintf("%t", val)
	case map[string]any:
		return toGoMap(val)
	case []any:
		var elements []string
		for _, elem := range val {
			elements = append(elements, formatGoValue(elem))
		}
		return fmt.Sprintf("[]any{%s}", strings.Join(elements, ", "))
	case nil:
		return "nil"
	default:
		// For complex types, fall back to string representation
		return fmt.Sprintf("%q", fmt.Sprintf("%v", val))
	}
}

// getTemplateFuncMap returns the template functions used for code generation
func getTemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"toJSON": func(v any) string {
			data, _ := json.Marshal(v)
			return string(data)
		},
		"title": func(s string) string {
			return cases.Title(language.Und).String(s)
		},
		"toGoMap": toGoMap,
		// TODO: Consider removing this later as it is no longer used
		"countTools": func(tools []ToolDefinition, withConfig bool) int {
			count := 0
			for _, tool := range tools {
				if tool.WithConfig == withConfig {
					count++
				}
			}
			return count
		},
		"joinTools": func(tools []ToolDefinition, withConfig bool) string {
			var names []string
			for _, tool := range tools {
				if tool.WithConfig == withConfig {
					names = append(names, tool.Name)
				}
			}
			if len(names) == 0 {
				return ""
			}
			return strings.Join(names, ", ")
		},
		"formatToolList": formatToolListForTemplate,
	}
}

// formatToolListForTemplate formats a comma-separated tool list with line breaks for readability
func formatToolListForTemplate(toolList string) string {
	if toolList == "" {
		return ""
	}

	tools := strings.Split(toolList, ", ")
	if len(tools) < 4 {
		return toolList
	}

	// Format with line breaks for readability when 4+ tools
	var result strings.Builder
	for i, tool := range tools {
		if i > 0 {
			if i%3 == 0 { // Break line every 3 tools
				result.WriteString(",\n//      ")
			} else {
				result.WriteString(", ")
			}
		}
		result.WriteString(tool)
	}
	return result.String()
}

// generateFile generates a file using a template
func generateFile(templatePath, outputPath string, config *Config, _ string) error {
	tmpl, err := template.New(filepath.Base(templatePath)).Funcs(getTemplateFuncMap()).ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("parsing template from %s: %w", templatePath, err)
	}

	var code bytes.Buffer

	// Header
	writeHeader(&code)

	// Package and imports
	code.WriteString("package mcpserver\n\n")
	code.WriteString("import (\n")
	code.WriteString("\t\"github.com/mark3labs/mcp-go/mcp\"\n")
	code.WriteString(")\n\n")

	// Execute template
	if err := tmpl.Execute(&code, config); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return writeGeneratedFile(outputPath, code.Bytes())
}

// GenerateTools generates the tools.go file for the MCP server.
//
// It loads the configuration, processes tool definitions, and generates
// Go code that implements MCP server tools with their handlers and parameters.
//
// Returns:
//   - error: Error if configuration loading or file generation fails
func GenerateTools() error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	templatePath := getTemplatePath("tools.go.tmpl")
	outputPath := getOutputPath("tools.go")

	return generateFile(templatePath, outputPath, config, "tools")
}

// GeneratePrompts generates the prompts.go file for the MCP server.
//
// It loads the configuration, processes prompt definitions, and generates
// Go code that implements MCP server prompts with their handlers and arguments.
//
// Returns:
//   - error: Error if configuration loading or file generation fails
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
	fmt.Fprintf(code, "// Copyright (c) %d H0llyW00dzZ All rights reserved.\n", time.Now().Year())
	code.WriteString("//\n")
	code.WriteString("// By accessing or using this software, you agree to be bound by the terms\n")
	code.WriteString("// of the License Agreement, which you can find at LICENSE files.\n\n")
	code.WriteString("// Code generated by go generate; DO NOT EDIT.\n")
	code.WriteString("// This file is generated from tools/codegen/internal/codegen.go\n\n")
}

// writeGeneratedFile writes formatted Go code to a file.
// It formats the code using go/format.Source and writes it to the specified file.
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
	if _, err = writer.Write(formatted); err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flushing file: %w", err)
	}

	fmt.Printf("Generated %s successfully\n", filename)
	return nil
}
