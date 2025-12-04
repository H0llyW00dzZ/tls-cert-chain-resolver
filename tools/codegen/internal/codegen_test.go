// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package codegen

import (
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
