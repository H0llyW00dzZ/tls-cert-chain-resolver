package jsonrpc

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected map[string]any
	}{
		{
			name: "adds jsonrpc version",
			input: map[string]any{
				"id":     1,
				"method": "test",
				"params": map[string]any{"key": "value"},
			},
			expected: map[string]any{
				"id":      1,
				"method":  "test",
				"params":  map[string]any{"key": "value"},
				"jsonrpc": "2.0",
			},
		},
		{
			name: "handles empty id map",
			input: map[string]any{
				"id":     map[string]any{},
				"method": "test",
			},
			expected: map[string]any{
				"id":      nil,
				"method":  "test",
				"jsonrpc": "2.0",
			},
		},
		{
			name: "preserves existing jsonrpc",
			input: map[string]any{
				"id":      1,
				"method":  "test",
				"jsonrpc": "2.0",
			},
			expected: map[string]any{
				"id":      1,
				"method":  "test",
				"jsonrpc": "2.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal input to JSON bytes first
			inputBytes, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			result, err := Marshal(inputBytes)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var actual map[string]any
			if err := json.Unmarshal(result, &actual); err != nil {
				t.Fatalf("Failed to unmarshal result: %v", err)
			}

			if len(actual) != len(tt.expected) {
				t.Errorf("Expected %d fields, got %d", len(tt.expected), len(actual))
			}

			for key, expectedValue := range tt.expected {
				actualValue, ok := actual[key]
				if !ok {
					t.Errorf("Missing key: %s", key)
					continue
				}

				// Handle nil comparison
				if expectedValue == nil && actualValue == nil {
					continue
				}

				// Use DeepEqual for complex types, but handle JSON number conversion
				if !reflect.DeepEqual(expectedValue, actualValue) {
					// Special handling for JSON number types (int vs float64)
					if expectedNum, ok1 := expectedValue.(int); ok1 {
						if actualNum, ok2 := actualValue.(float64); ok2 {
							if expectedNum == int(actualNum) {
								continue
							}
						}
					}
					t.Errorf("Key %s: expected %v (type %T), got %v (type %T)", key, expectedValue, expectedValue, actualValue, actualValue)
				}
			}
		})
	}
}

func TestMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected map[string]any
	}{
		{
			name: "converts to lowercase keys",
			input: map[string]any{
				"ID":     1,
				"METHOD": "test",
				"PARAMS": map[string]any{"key": "value"},
			},
			expected: map[string]any{
				"id":      1,
				"method":  "test",
				"params":  map[string]any{"key": "value"},
				"jsonrpc": "2.0",
			},
		},
		{
			name: "handles mixed case",
			input: map[string]any{
				"Id":     1,
				"Method": "test",
				"Params": map[string]any{"Key": "Value"},
			},
			expected: map[string]any{
				"id":      1,
				"method":  "test",
				"params":  map[string]any{"Key": "Value"},
				"jsonrpc": "2.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Map(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d fields, got %d", len(tt.expected), len(result))
			}

			for key, expectedValue := range tt.expected {
				actualValue, ok := result[key]
				if !ok {
					t.Errorf("Missing key: %s", key)
					continue
				}

				if !reflect.DeepEqual(expectedValue, actualValue) {
					t.Errorf("Key %s: expected %v, got %v", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestNormalizeIDValue(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected any
	}{
		{
			name:     "whole number float64 becomes int64",
			input:    42.0,
			expected: int64(42),
		},
		{
			name:     "fractional float64 stays float64",
			input:    42.5,
			expected: 42.5,
		},
		{
			name:     "negative whole number",
			input:    -1.0,
			expected: int64(-1),
		},
		{
			name:     "zero",
			input:    0.0,
			expected: int64(0),
		},
		{
			name:     "string stays string",
			input:    "test-id",
			expected: "test-id",
		},
		{
			name:     "nil stays nil",
			input:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeIDValue(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("normalizeIDValue(%v) = %v (type %T), expected %v (type %T)",
					tt.input, result, result, tt.expected, tt.expected)
			}
		})
	}
}
