// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package jsonrpc

import (
	"encoding/json"
	"strings"
)

// Marshal normalizes JSON-RPC payloads to lowercase keys with default version.
func Marshal(data []byte) ([]byte, error) {
	var temp map[string]any
	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, err
	}

	fixed := Map(temp)

	return json.Marshal(fixed)
}

// Map converts a decoded JSON-RPC map to canonical lowercase key form.
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
		fixed["jsonrpc"] = "2.0"
	}

	return fixed
}

// normalizeIDValue converts whole number float64 values to int for JSON-RPC ID fields
func normalizeIDValue(v any) any {
	if f, ok := v.(float64); ok {
		// Check if it's a whole number
		if f == float64(int64(f)) {
			return int64(f)
		}
	}
	return v
}
