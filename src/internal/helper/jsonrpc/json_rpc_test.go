// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package jsonrpc

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			require.NoError(t, err, "Failed to marshal input")

			result, err := Marshal(inputBytes)
			require.NoError(t, err, "Marshal failed")

			var actual map[string]any
			require.NoError(t, json.Unmarshal(result, &actual), "Failed to unmarshal result")

			assert.Len(t, actual, len(tt.expected), "Expected %d fields, got %d", len(tt.expected), len(actual))

			for key, expectedValue := range tt.expected {
				actualValue, ok := actual[key]
				assert.True(t, ok, "Missing key: %s", key)
				if !ok {
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
					assert.Equal(t, expectedValue, actualValue, "Key %s: expected %v (type %T), got %v (type %T)", key, expectedValue, expectedValue, actualValue, actualValue)
				}
			}
		})
	}
}

func TestMarshal_Error(t *testing.T) {
	// Test case for invalid JSON input
	invalidJSON := []byte(`{"incomplete": json`)
	_, err := Marshal(invalidJSON)
	assert.Error(t, err, "Expected error for invalid JSON, got nil")
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

			assert.Equal(t, len(tt.expected), len(result), "Expected %d fields, got %d", len(tt.expected), len(result))

			for key, expectedValue := range tt.expected {
				actualValue, ok := result[key]
				assert.True(t, ok, "Missing key: %s", key)
				if !ok {
					continue
				}

				assert.Equal(t, expectedValue, actualValue, "Key %s: expected %v, got %v", key, expectedValue, actualValue)
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
			assert.Equal(t, tt.expected, result, "normalizeIDValue(%v) = %v (type %T), expected %v (type %T)",
				tt.input, result, result, tt.expected, tt.expected)
		})
	}
}

func TestUnmarshalFromMap(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	tests := []struct {
		name     string
		input    any
		expected TestStruct
		wantErr  bool
	}{
		{
			name: "valid map",
			input: map[string]any{
				"name":  "test",
				"value": 42,
			},
			expected: TestStruct{
				Name:  "test",
				Value: 42,
			},
			wantErr: false,
		},
		{
			name: "partial map",
			input: map[string]any{
				"name": "partial",
			},
			expected: TestStruct{
				Name:  "partial",
				Value: 0,
			},
			wantErr: false,
		},
		{
			name: "extra fields ignored",
			input: map[string]any{
				"name":  "extra",
				"extra": "ignored",
			},
			expected: TestStruct{
				Name:  "extra",
				Value: 0,
			},
			wantErr: false,
		},
		{
			name:    "unsupported type",
			input:   func() {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result TestStruct
			err := UnmarshalFromMap(tt.input, &result)

			assert.Equal(t, tt.wantErr, err != nil, "UnmarshalFromMap() error = %v, wantErr %v", err, tt.wantErr)

			if !tt.wantErr {
				assert.Equal(t, tt.expected, result, "UnmarshalFromMap() = %v, want %v", result, tt.expected)
			}
		})
	}
}
