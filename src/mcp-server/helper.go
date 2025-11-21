// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import "fmt"

// getParams extracts parameters from a normalized JSON-RPC request.
func getParams(req map[string]any, method string) (map[string]any, error) {
	params, ok := req["params"]
	if !ok {
		return nil, fmt.Errorf("missing params for method %s", method)
	}
	p, ok := params.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid params type for method %s: expected object, got %T", method, params)
	}
	return p, nil
}

// getStringParam extracts a required string parameter from the params map.
func getStringParam(params map[string]any, method, key string) (string, error) {
	val, ok := params[key].(string)
	if !ok {
		return "", fmt.Errorf("invalid params for %s: '%s' must be string", method, key)
	}
	return val, nil
}

// getMapParam extracts a required map[string]any parameter from the params map.
func getMapParam(params map[string]any, method, key string) (map[string]any, error) {
	val, ok := params[key].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid params for %s: '%s' must be object", method, key)
	}
	return val, nil
}
