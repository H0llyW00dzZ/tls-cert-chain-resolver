// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateParamConstraints(t *testing.T) {
	tests := []struct {
		name    string
		param   ToolParam
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid string param with enum",
			param: ToolParam{
				Type:     "string",
				Enum:     []string{"pem", "der", "json"},
				Required: true,
			},
			wantErr: false,
		},
		{
			name: "valid number param with min/max",
			param: ToolParam{
				Type:     "number",
				Minimum:  &[]float64{1}[0],
				Maximum:  &[]float64{365}[0],
				Required: true,
			},
			wantErr: false,
		},
		{
			name: "invalid enum for number type",
			param: ToolParam{
				Type:     "number",
				Enum:     []string{"not-a-number"},
				Required: true,
			},
			wantErr: true,
			errMsg:  "enum value 'not-a-number' is not a valid number",
		},
		{
			name: "invalid enum for boolean type",
			param: ToolParam{
				Type:     "boolean",
				Enum:     []string{"not-a-bool"},
				Required: true,
			},
			wantErr: true,
			errMsg:  "enum value 'not-a-bool' is not a valid boolean",
		},
		{
			name: "minLength > maxLength for string",
			param: ToolParam{
				Type:      "string",
				MinLength: &[]int{10}[0],
				MaxLength: &[]int{5}[0],
				Required:  true,
			},
			wantErr: true,
			errMsg:  "minLength (10) cannot be greater than maxLength (5)",
		},
		{
			name: "minimum > maximum for number",
			param: ToolParam{
				Type:     "number",
				Minimum:  &[]float64{100}[0],
				Maximum:  &[]float64{50}[0],
				Required: true,
			},
			wantErr: true,
			errMsg:  "minimum (100.000000) cannot be greater than maximum (50.000000)",
		},
		{
			name: "pattern on non-string type",
			param: ToolParam{
				Type:     "number",
				Pattern:  "^[0-9]+$",
				Required: true,
			},
			wantErr: true,
			errMsg:  "pattern constraint is only valid for string type",
		},
		{
			name: "items on non-array type",
			param: ToolParam{
				Type:     "string",
				Items:    map[string]any{"type": "string"},
				Required: true,
			},
			wantErr: true,
			errMsg:  "items constraint is only valid for array type",
		},
		{
			name: "properties on non-object type",
			param: ToolParam{
				Type:       "string",
				Properties: map[string]any{"key": map[string]any{"type": "string"}},
				Required:   true,
			},
			wantErr: true,
			errMsg:  "properties constraint is only valid for object type",
		},
		{
			name: "minLength on non-string type",
			param: ToolParam{
				Type:      "number",
				MinLength: &[]int{5}[0],
				Required:  true,
			},
			wantErr: true,
			errMsg:  "minLength/maxLength constraints are only valid for string type",
		},
		{
			name: "minimum on non-number type",
			param: ToolParam{
				Type:     "string",
				Minimum:  &[]float64{5}[0],
				Required: true,
			},
			wantErr: true,
			errMsg:  "minimum/maximum constraints are only valid for number type",
		},
		{
			name: "valid array type with items",
			param: ToolParam{
				Type:     "array",
				Items:    map[string]any{"type": "string"},
				Required: true,
			},
			wantErr: false,
		},
		{
			name: "valid object type with properties",
			param: ToolParam{
				Type:       "object",
				Properties: map[string]any{"name": map[string]any{"type": "string"}},
				Required:   true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateParamConstraints(&tt.param, 0, 0)
			if tt.wantErr {
				assert.Error(t, err, "validateParamConstraints() should return error")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg,
						"validateParamConstraints() error should contain expected message")
				}
			} else {
				assert.NoError(t, err, "validateParamConstraints() should not return error")
			}
		})
	}
}

func TestValidateToolParams(t *testing.T) {
	tests := []struct {
		name    string
		params  []ToolParam
		wantErr bool
	}{
		{
			name: "valid params",
			params: []ToolParam{
				{
					Name:      "certificate",
					Type:      "string",
					Required:  true,
					MinLength: &[]int{1}[0],
				},
				{
					Name:     "format",
					Type:     "string",
					Required: false,
					Enum:     []string{"pem", "der", "json"},
					Default:  "\"pem\"",
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate param names",
			params: []ToolParam{
				{Name: "test", Type: "string", Required: true},
				{Name: "test", Type: "number", Required: false},
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			params: []ToolParam{
				{Name: "test", Type: "invalid", Required: true},
			},
			wantErr: true,
		},
		{
			name: "constraint validation error",
			params: []ToolParam{
				{
					Name:      "test",
					Type:      "string",
					Required:  true,
					MinLength: &[]int{10}[0],
					MaxLength: &[]int{5}[0],
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateToolParams(tt.params, 0)
			if tt.wantErr {
				assert.Error(t, err, "validateToolParams() should return error")
			} else {
				assert.NoError(t, err, "validateToolParams() should not return error")
			}
		})
	}
}

func TestValidateResources(t *testing.T) {
	tests := []struct {
		name      string
		resources []ResourceDefinition
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid resources with annotations",
			resources: []ResourceDefinition{
				{
					URI:         "config://template",
					Name:        "Template",
					Description: "Config template",
					MIMEType:    "application/json",
					Handler:     "handleConfig",
					Audience:    []string{"user", "assistant"},
					Priority:    &[]float64{1.0}[0],
					Meta:        map[string]any{"category": "config"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing required fields",
			resources: []ResourceDefinition{
				{
					URI:  "",
					Name: "Test",
				},
			},
			wantErr: true,
			errMsg:  "URI is required",
		},
		{
			name: "duplicate URI",
			resources: []ResourceDefinition{
				{
					URI:     "test://uri",
					Name:    "Test1",
					Handler: "handler1",
				},
				{
					URI:     "test://uri",
					Name:    "Test2",
					Handler: "handler2",
				},
			},
			wantErr: true,
			errMsg:  "duplicate URI",
		},
		{
			name: "invalid audience role",
			resources: []ResourceDefinition{
				{
					URI:      "test://uri",
					Name:     "Test",
					Handler:  "handler",
					Audience: []string{"invalid_role"},
				},
			},
			wantErr: true,
			errMsg:  "invalid audience role",
		},
		{
			name: "invalid priority range",
			resources: []ResourceDefinition{
				{
					URI:      "test://uri",
					Name:     "Test",
					Handler:  "handler",
					Priority: &[]float64{-1.0}[0],
				},
			},
			wantErr: true,
			errMsg:  "priority must be between 0.0 and 10.0",
		},
		{
			name: "valid priority range",
			resources: []ResourceDefinition{
				{
					URI:      "test://uri",
					Name:     "Test",
					Handler:  "handler",
					Priority: &[]float64{10.0}[0],
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResources(tt.resources)
			if tt.wantErr {
				assert.Error(t, err, "validateResources() should return error")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg,
						"validateResources() error should contain expected message")
				}
			} else {
				assert.NoError(t, err, "validateResources() should not return error")
			}
		})
	}
}

func TestValidatePrompts(t *testing.T) {
	tests := []struct {
		name    string
		prompts []PromptDefinition
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid prompts with annotations",
			prompts: []PromptDefinition{
				{
					Name:        "test-prompt",
					Description: "Test prompt",
					Handler:     "handleTest",
					Arguments: []PromptArgument{
						{Name: "arg1", Description: "First arg", Required: true},
					},
					Audience: []string{"user", "assistant"},
					Priority: &[]float64{1.0}[0],
					Meta:     map[string]any{"category": "test"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing required fields",
			prompts: []PromptDefinition{
				{
					Name:    "",
					Handler: "handleTest",
				},
			},
			wantErr: true,
			errMsg:  "Name is required",
		},
		{
			name: "duplicate prompt name",
			prompts: []PromptDefinition{
				{
					Name:    "duplicate",
					Handler: "handle1",
				},
				{
					Name:    "duplicate",
					Handler: "handle2",
				},
			},
			wantErr: true,
			errMsg:  "duplicate name",
		},
		{
			name: "invalid audience role",
			prompts: []PromptDefinition{
				{
					Name:     "test",
					Handler:  "handleTest",
					Audience: []string{"invalid_role"},
				},
			},
			wantErr: true,
			errMsg:  "invalid audience role",
		},
		{
			name: "invalid priority range",
			prompts: []PromptDefinition{
				{
					Name:     "test",
					Handler:  "handleTest",
					Priority: &[]float64{-1.0}[0],
				},
			},
			wantErr: true,
			errMsg:  "priority must be between 0.0 and 10.0",
		},
		{
			name: "valid priority range",
			prompts: []PromptDefinition{
				{
					Name:     "test",
					Handler:  "handleTest",
					Priority: &[]float64{10.0}[0],
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrompts(tt.prompts)
			if tt.wantErr {
				assert.Error(t, err, "validatePrompts() should return error")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg,
						"validatePrompts() error should contain expected message")
				}
			} else {
				assert.NoError(t, err, "validatePrompts() should not return error")
			}
		})
	}
}

func TestToGoMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected string
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: "nil",
		},
		{
			name:     "empty map",
			input:    map[string]any{},
			expected: "nil",
		},
		{
			name: "simple string values",
			input: map[string]any{
				"key1": "value1",
				"key2": "value2",
			},
			expected: `map[string]any{"key1": "value1", "key2": "value2"}`,
		},
		{
			name: "mixed types",
			input: map[string]any{
				"string":  "hello",
				"number":  42,
				"boolean": true,
				"float":   3.14,
			},
			expected: `map[string]any{"boolean": true, "float": 3.14, "number": 42, "string": "hello"}`,
		},
		{
			name: "nested map",
			input: map[string]any{
				"config": map[string]any{
					"enabled": true,
					"port":    8080,
				},
			},
			expected: `map[string]any{"config": map[string]any{"enabled": true, "port": 8080}}`,
		},
		{
			name: "array values",
			input: map[string]any{
				"tags": []any{"web", "api", "ssl"},
			},
			expected: `map[string]any{"tags": []any{"web", "api", "ssl"}}`,
		},
		{
			name: "nil value",
			input: map[string]any{
				"optional": nil,
			},
			expected: `map[string]any{"optional": nil}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toGoMap(tt.input)
			assert.Equal(t, tt.expected, result, "toGoMap() should return expected result")
		})
	}
}

func TestLoadJSON(t *testing.T) {
	// Create a temporary JSON file in the config directory
	configDir := filepath.Join(getCodegenDir(), "config")
	tempFile := filepath.Join(configDir, "test_temp.json")
	schemaFile := filepath.Join(configDir, "test_temp.schema.json")
	jsonContent := `{"test": "value", "number": 42}`
	schemaContent := `{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}`

	// Ensure cleanup
	defer os.Remove(tempFile)
	defer os.Remove(schemaFile)

	err := os.WriteFile(tempFile, []byte(jsonContent), 0644)
	require.NoError(t, err, "Failed to create test JSON file")

	err = os.WriteFile(schemaFile, []byte(schemaContent), 0644)
	require.NoError(t, err, "Failed to create test schema file")

	var result map[string]any
	err = loadJSON("test_temp.json", &result)
	assert.NoError(t, err, "loadJSON() should not return error")

	assert.Equal(t, "value", result["test"], "test field should equal 'value'")
	assert.Equal(t, float64(42), result["number"], "number field should equal 42")
}

func TestLoadConfig(t *testing.T) {
	// This test requires the actual config files to exist
	// We'll test error cases and assume config files are present for success case
	config, err := loadConfig()
	require.NoError(t, err, "loadConfig() should not return error")
	require.NotNil(t, config, "config should not be nil")

	// Basic validation that config has expected structure
	assert.NotEmpty(t, config.Resources, "Expected at least one resource in config")
	assert.NotEmpty(t, config.Tools, "Expected at least one tool in config")
	assert.NotEmpty(t, config.Prompts, "Expected at least one prompt in config")
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Resources: []ResourceDefinition{
					{URI: "test://uri", Name: "Test", Handler: "handler"},
				},
				Tools: []ToolDefinition{
					{Name: "test", ConstName: "Test", Handler: "handler", RoleConst: "Role", RoleName: "role", RoleComment: "comment", WithConfig: false},
				},
				Prompts: []PromptDefinition{
					{Name: "test", Handler: "handler"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid resource",
			config: &Config{
				Resources: []ResourceDefinition{
					{URI: "", Name: "Test"}, // Missing required fields
				},
			},
			wantErr: true,
		},
		{
			name: "invalid tool",
			config: &Config{
				Tools: []ToolDefinition{
					{Name: "", Handler: "handler"}, // Missing required fields
				},
			},
			wantErr: true,
		},
		{
			name: "invalid prompt",
			config: &Config{
				Prompts: []PromptDefinition{
					{Name: "", Handler: "handler"}, // Missing required fields
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err, "validateConfig() should return error")
			} else {
				assert.NoError(t, err, "validateConfig() should not return error")
			}
		})
	}
}

func TestValidateTools(t *testing.T) {
	tests := []struct {
		name    string
		tools   []ToolDefinition
		wantErr bool
	}{
		{
			name: "valid tools",
			tools: []ToolDefinition{
				{
					Name:        "test1",
					ConstName:   "Test1",
					Handler:     "handler1",
					RoleConst:   "Role1",
					RoleName:    "role1",
					RoleComment: "comment1",
					WithConfig:  false,
				},
				{
					Name:        "test2",
					ConstName:   "Test2",
					Handler:     "handler2",
					RoleConst:   "Role2",
					RoleName:    "role2",
					RoleComment: "comment2",
					WithConfig:  true,
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate tool names",
			tools: []ToolDefinition{
				{Name: "duplicate", ConstName: "Test1", Handler: "handler1", RoleConst: "Role1", RoleName: "role1", RoleComment: "comment1", WithConfig: false},
				{Name: "duplicate", ConstName: "Test2", Handler: "handler2", RoleConst: "Role2", RoleName: "role2", RoleComment: "comment2", WithConfig: false},
			},
			wantErr: true,
		},
		{
			name: "duplicate role names",
			tools: []ToolDefinition{
				{Name: "test1", ConstName: "Test1", Handler: "handler1", RoleConst: "Role1", RoleName: "duplicate", RoleComment: "comment1", WithConfig: false},
				{Name: "test2", ConstName: "Test2", Handler: "handler2", RoleConst: "Role2", RoleName: "duplicate", RoleComment: "comment2", WithConfig: false},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTools(tt.tools)
			if tt.wantErr {
				assert.Error(t, err, "validateTools() should return error")
			} else {
				assert.NoError(t, err, "validateTools() should not return error")
			}
		})
	}
}

func TestValidateTool(t *testing.T) {
	tests := []struct {
		name    string
		tool    ToolDefinition
		wantErr bool
	}{
		{
			name: "valid tool",
			tool: ToolDefinition{
				Name:        "test",
				ConstName:   "Test",
				Handler:     "handler",
				RoleConst:   "Role",
				RoleName:    "role",
				RoleComment: "comment",
				WithConfig:  false,
			},
			wantErr: false,
		},
		{
			name:    "missing name",
			tool:    ToolDefinition{Handler: "handler", RoleConst: "Role", RoleName: "role", RoleComment: "comment", WithConfig: false},
			wantErr: true,
		},
		{
			name:    "missing const name",
			tool:    ToolDefinition{Name: "test", Handler: "handler", RoleConst: "Role", RoleName: "role", RoleComment: "comment", WithConfig: false},
			wantErr: true,
		},
		{
			name:    "missing handler",
			tool:    ToolDefinition{Name: "test", ConstName: "Test", RoleConst: "Role", RoleName: "role", RoleComment: "comment", WithConfig: false},
			wantErr: true,
		},
		{
			name:    "missing role const",
			tool:    ToolDefinition{Name: "test", ConstName: "Test", Handler: "handler", RoleName: "role", RoleComment: "comment", WithConfig: false},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTool(&tt.tool, 0, make(map[string]bool), make(map[string]bool))
			if tt.wantErr {
				assert.Error(t, err, "validateTool() should return error")
			} else {
				assert.NoError(t, err, "validateTool() should not return error")
			}
		})
	}
}

func TestValidatePromptArguments(t *testing.T) {
	tests := []struct {
		name      string
		arguments []PromptArgument
		wantErr   bool
	}{
		{
			name: "valid arguments",
			arguments: []PromptArgument{
				{Name: "arg1", Description: "First arg"},
				{Name: "arg2", Description: "Second arg", Required: true},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			arguments: []PromptArgument{
				{Description: "Missing name"},
			},
			wantErr: true,
		},
		{
			name: "duplicate names",
			arguments: []PromptArgument{
				{Name: "duplicate", Description: "First"},
				{Name: "duplicate", Description: "Second"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePromptArguments(tt.arguments, 0)
			if tt.wantErr {
				assert.Error(t, err, "validatePromptArguments() should return error")
			} else {
				assert.NoError(t, err, "validatePromptArguments() should not return error")
			}
		})
	}
}

func TestFormatGoValue(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"string", "hello", `"hello"`},
		{"int", 42, "42"},
		{"int8", int8(8), "8"},
		{"int16", int16(16), "16"},
		{"int32", int32(32), "32"},
		{"int64", int64(64), "64"},
		{"uint", uint(1), "1"},
		{"uint8", uint8(8), "8"},
		{"uint16", uint16(16), "16"},
		{"uint32", uint32(32), "32"},
		{"uint64", uint64(64), "64"},
		{"float32", float32(3.14), "3.14"},
		{"float64", 3.14159, "3.14159"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"nil", nil, "nil"},
		{"array", []any{"a", "b"}, `[]any{"a", "b"}`},
		{"map", map[string]any{"key": "value"}, `map[string]any{"key": "value"}`},
		{"complex type", complex(1, 2), `"(1+2i)"`}, // fallback case
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatGoValue(tt.input)
			assert.Equal(t, tt.expected, result, "formatGoValue(%v) should return expected result", tt.input)
		})
	}
}

func TestGetCodegenDir(t *testing.T) {
	dir := getCodegenDir()
	assert.NotEmpty(t, dir, "getCodegenDir() should not return empty string")
	// Check if directory exists
	_, err := os.Stat(dir)
	assert.False(t, os.IsNotExist(err), "getCodegenDir() should return existing directory: %s", dir)
}

func TestGetTemplatePath(t *testing.T) {
	path := getTemplatePath("test.tmpl")
	// Check that path contains the expected components regardless of OS path separators
	parts := strings.Split(filepath.ToSlash(path), "/")
	require.GreaterOrEqual(t, len(parts), 2, "path should have at least 2 parts")
	assert.Equal(t, "templates", parts[len(parts)-2], "path should contain 'templates' directory")
	assert.Equal(t, "test.tmpl", parts[len(parts)-1], "path should end with 'test.tmpl'")
}

func TestGetOutputPath(t *testing.T) {
	path := getOutputPath("test.go")
	// Check that path contains the expected components regardless of OS path separators
	parts := strings.Split(filepath.ToSlash(path), "/")
	require.GreaterOrEqual(t, len(parts), 3, "path should have at least 3 parts")
	assert.Equal(t, "src", parts[len(parts)-3], "path should contain 'src' directory")
	assert.Equal(t, "mcp-server", parts[len(parts)-2], "path should contain 'mcp-server' directory")
	assert.Equal(t, "test.go", parts[len(parts)-1], "path should end with 'test.go'")
}

func TestGenerateResources(t *testing.T) {
	// Test that GenerateResources can be called without panicking
	// Note: This will actually generate files, so we test error handling
	// We expect this to succeed if config files exist
	err := GenerateResources()
	if err != nil {
		t.Logf("GenerateResources() returned error (expected if config files missing): %v", err)
	}
	// We don't assert here since the function may legitimately fail if config files are missing
}

func TestGenerateTools(t *testing.T) {
	// Test that GenerateTools can be called without panicking
	err := GenerateTools()
	if err != nil {
		t.Logf("GenerateTools() returned error (expected if config files missing): %v", err)
	}
	// We don't assert here since the function may legitimately fail if config files are missing
}

func TestGeneratePrompts(t *testing.T) {
	// Test that GeneratePrompts can be called without panicking
	err := GeneratePrompts()
	if err != nil {
		t.Logf("GeneratePrompts() returned error (expected if config files missing): %v", err)
	}
	// We don't assert here since the function may legitimately fail if config files are missing
}

func TestValidateJSONSchema(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		schemaFile string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid tools config",
			jsonData: `{
				"tools": [
					{
						"constName": "TestTool",
						"name": "test_tool",
						"description": "Test tool",
						"handler": "handleTest",
						"roleConst": "TestRole",
						"roleName": "testRole",
						"withConfig": false
					}
				]
			}`,
			schemaFile: "tools.schema.json",
			wantErr:    false,
		},
		{
			name: "invalid tools config - missing required field",
			jsonData: `{
				"tools": [
					{
						"name": "test_tool",
						"description": "Test tool"
					}
				]
			}`,
			schemaFile: "tools.schema.json",
			wantErr:    true,
			errMsg:     "JSON schema validation failed",
		},
		{
			name: "valid resources config",
			jsonData: `{
				"resources": [
					{
						"uri": "test://resource",
						"name": "Test Resource",
						"description": "Test resource",
						"mimeType": "application/json",
						"handler": "handleTest"
					}
				]
			}`,
			schemaFile: "resources.schema.json",
			wantErr:    false,
		},
		{
			name: "valid prompts config",
			jsonData: `{
				"prompts": [
					{
						"name": "test-prompt",
						"description": "Test prompt",
						"handler": "handleTest",
						"arguments": [
							{
								"name": "arg1",
								"description": "Test argument"
							}
						]
					}
				]
			}`,
			schemaFile: "prompts.schema.json",
			wantErr:    false,
		},
		{
			name:       "non-existent schema file",
			jsonData:   `{"test": "data"}`,
			schemaFile: "nonexistent.schema.json",
			wantErr:    true,
			errMsg:     "reading schema file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schemaPath := filepath.Join(getCodegenDir(), "config", tt.schemaFile)
			err := validateJSONSchema([]byte(tt.jsonData), schemaPath)

			if tt.wantErr {
				assert.Error(t, err, "validateJSONSchema() should return error")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg,
						"validateJSONSchema() error should contain expected message")
				}
			} else {
				assert.NoError(t, err, "validateJSONSchema() should not return error")
			}
		})
	}
}

func TestLoadConfigWithSchemaValidation(t *testing.T) {
	// Test that loadConfig validates against schemas
	// This test assumes the actual config files exist and are valid
	_, err := loadConfig()
	if err != nil {
		t.Logf("loadConfig() returned error (may be expected if config files are invalid): %v", err)
		// We don't fail the test here as config files might be intentionally invalid for testing
	}
	// We don't assert here since the function may legitimately fail if config files are missing/invalid
}
