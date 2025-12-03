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
