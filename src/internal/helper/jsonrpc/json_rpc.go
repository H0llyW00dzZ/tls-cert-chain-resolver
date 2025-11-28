// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package jsonrpc

import (
	"encoding/json"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// Marshal normalizes JSON-RPC payloads to lowercase keys with default version.
//
// It unmarshals the input JSON, normalizes the keys using Map(), and then
// marshals it back to JSON. This ensures that all JSON-RPC messages conform
// to a canonical format with lowercase keys.
//
// Parameters:
//   - data: Raw JSON data to normalize
//
// Returns:
//   - []byte: Normalized JSON data
//   - error: Error if unmarshaling or marshaling fails
func Marshal(data []byte) ([]byte, error) {
	var temp map[string]any
	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, err
	}

	fixed := Map(temp)

	return json.Marshal(fixed)
}

// Map converts a decoded JSON-RPC map to canonical lowercase key form.
//
// It processes a map of arbitrary keys and values, converting all keys to
// lowercase. It handles specific JSON-RPC fields like "id" and "jsonrpc"
// with special logic:
//   - "id": Preserves values, converting whole number floats to int64
//   - "jsonrpc": Adds default version "2.0" if missing
//
// Parameters:
//   - temp: Input map with potentially mixed-case keys
//
// Returns:
//   - map[string]any: Normalized map with lowercase keys
func Map(temp map[string]any) map[string]any {
	fixed := make(map[string]any)
	for k, v := range temp {
		key := strings.ToLower(k)
		switch key {
		case "id":
			if idMap, ok := v.(map[string]any); ok && len(idMap) == 0 {
				fixed["id"] = nil
			} else {
				// Preserve ID value, converting whole number floats to int if possible
				fixed["id"] = normalizeIDValue(v)
			}
		case "jsonrpc":
			fixed["jsonrpc"] = v
		default:
			fixed[key] = v
		}
	}

	if _, ok := fixed["jsonrpc"]; !ok {
		fixed["jsonrpc"] = mcp.JSONRPC_VERSION
	}

	return fixed
}

// normalizeIDValue converts whole number float64 values to int for JSON-RPC ID fields.
//
// JSON unmarshaling often treats numbers as float64. This function checks if
// a float64 value represents a whole number and converts it to int64 if so,
// which is preferred for JSON-RPC IDs.
//
// Parameters:
//   - v: Value to normalize
//
// Returns:
//   - any: Normalized value (int64 if whole number float, else original)
func normalizeIDValue(v any) any {
	if f, ok := v.(float64); ok {
		// Check if it's a whole number
		if f == float64(int64(f)) {
			return int64(f)
		}
	}
	return v
}

// UnmarshalFromMap converts a map/any to a struct via JSON round-trip.
//
// It facilitates converting a generic map (e.g., from JSON-RPC parameters)
// into a strongly-typed struct. This is done by marshaling the map to JSON
// and then unmarshaling it into the destination struct.
//
// Parameters:
//   - src: Source map or value to convert
//   - dest: Pointer to destination struct
//
// Returns:
//   - error: Error if marshaling or unmarshaling fails
func UnmarshalFromMap(src any, dest any) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}
