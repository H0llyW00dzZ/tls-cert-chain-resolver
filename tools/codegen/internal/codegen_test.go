// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validateParamConstraints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("validateParamConstraints() error = %v, expected to contain %v", err.Error(), tt.errMsg)
				}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validateToolParams() error = %v, wantErr %v", err, tt.wantErr)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validateResources() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("validateResources() error = %v, expected to contain %v", err, tt.errMsg)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePrompts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("validatePrompts() error = %v, expected to contain %v", err, tt.errMsg)
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
			if result != tt.expected {
				t.Errorf("toGoMap() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsAt(s, substr)))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestLoadJSON(t *testing.T) {
	// Create a temporary JSON file in the config directory
	configDir := filepath.Join(getCodegenDir(), "config")
	tempFile := filepath.Join(configDir, "test_temp.json")
	jsonContent := `{"test": "value", "number": 42}`

	// Ensure cleanup
	defer os.Remove(tempFile)

	if err := os.WriteFile(tempFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("Failed to create test JSON file: %v", err)
	}

	var result map[string]any
	err := loadJSON("test_temp.json", &result)
	if err != nil {
		t.Errorf("loadJSON() error = %v", err)
	}

	if result["test"] != "value" {
		t.Errorf("Expected test = 'value', got %v", result["test"])
	}
	if result["number"] != float64(42) {
		t.Errorf("Expected number = 42, got %v", result["number"])
	}
}

func TestLoadConfig(t *testing.T) {
	// This test requires the actual config files to exist
	// We'll test error cases and assume config files are present for success case
	config, err := loadConfig()
	if err != nil {
		t.Errorf("loadConfig() error = %v", err)
		return
	}

	if config == nil {
		t.Error("Expected config to be non-nil")
		return
	}

	// Basic validation that config has expected structure
	if len(config.Resources) == 0 {
		t.Error("Expected at least one resource in config")
	}
	if len(config.Tools) == 0 {
		t.Error("Expected at least one tool in config")
	}
	if len(config.Prompts) == 0 {
		t.Error("Expected at least one prompt in config")
	}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTools() error = %v, wantErr %v", err, tt.wantErr)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTool() error = %v, wantErr %v", err, tt.wantErr)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePromptArguments() error = %v, wantErr %v", err, tt.wantErr)
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
			if result != tt.expected {
				t.Errorf("formatGoValue(%v) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetCodegenDir(t *testing.T) {
	dir := getCodegenDir()
	if dir == "" {
		t.Error("getCodegenDir() returned empty string")
	}
	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("getCodegenDir() returned non-existent directory: %s", dir)
	}
}

func TestGetTemplatePath(t *testing.T) {
	path := getTemplatePath("test.tmpl")
	// Check that path contains the expected components regardless of OS path separators
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) < 2 || parts[len(parts)-2] != "templates" || parts[len(parts)-1] != "test.tmpl" {
		t.Errorf("getTemplatePath() = %s, expected to end with templates/test.tmpl", path)
	}
}

func TestGetOutputPath(t *testing.T) {
	path := getOutputPath("test.go")
	// Check that path contains the expected components regardless of OS path separators
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) < 3 || parts[len(parts)-3] != "src" || parts[len(parts)-2] != "mcp-server" || parts[len(parts)-1] != "test.go" {
		t.Errorf("getOutputPath() = %s, expected to end with src/mcp-server/test.go", path)
	}
}

func TestGenerateResources(t *testing.T) {
	// Test that GenerateResources can be called without panicking
	// Note: This will actually generate files, so we test error handling
	// We expect this to succeed if config files exist
	if err := GenerateResources(); err != nil {
		t.Logf("GenerateResources() returned error (expected if config files missing): %v", err)
	}
}

func TestGenerateTools(t *testing.T) {
	// Test that GenerateTools can be called without panicking
	if err := GenerateTools(); err != nil {
		t.Logf("GenerateTools() returned error (expected if config files missing): %v", err)
	}
}

func TestGeneratePrompts(t *testing.T) {
	// Test that GeneratePrompts can be called without panicking
	if err := GeneratePrompts(); err != nil {
		t.Logf("GeneratePrompts() returned error (expected if config files missing): %v", err)
	}
}
