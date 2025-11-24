// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import "fmt"

// getParams extracts parameters from a normalized [JSON-RPC] request.
//
// This function safely extracts the "params" field from a [JSON-RPC] request map.
// It performs type checking to ensure the params field exists and is a map.
//
// Parameters:
//   - req: The normalized [JSON-RPC] request map
//   - method: The method name for error reporting
//
// Returns:
//   - map[string]any: The extracted parameters map
//   - error: Error if params field is missing or not a map
//
// This function is used by MCP tool handlers to safely access request parameters
// after [JSON-RPC] normalization has been applied.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
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
//
// This function safely extracts a required string parameter from the parameters map.
// It performs type checking to ensure the parameter exists and is a string.
//
// Parameters:
//   - params: The parameters map from getParams()
//   - method: The method name for error reporting
//   - key: The parameter key to extract
//
// Returns:
//   - string: The extracted string value
//   - error: Error if the parameter is missing or not a string
//
// This function is used by MCP tool handlers to safely access required string parameters
// from [JSON-RPC] requests after parameter extraction.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func getStringParam(params map[string]any, method, key string) (string, error) {
	val, ok := params[key].(string)
	if !ok {
		return "", fmt.Errorf("invalid params for %s: '%s' must be string", method, key)
	}
	return val, nil
}

// getOptionalStringParam extracts an optional string parameter from the params map.
// If the key is missing, it returns an empty string and no error.
// If the key exists but is not a string, it returns an error.
//
// This function safely extracts an optional string parameter from the parameters map.
// It allows the parameter to be missing (returning empty string) but validates
// the type if present.
//
// Parameters:
//   - params: The parameters map from getParams()
//   - method: The method name for error reporting
//   - key: The parameter key to extract
//
// Returns:
//   - string: The extracted string value, or empty string if missing
//   - error: Error if the parameter exists but is not a string
//
// This function is used by MCP tool handlers to safely access optional string parameters
// from [JSON-RPC] requests, providing default behavior for missing parameters.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func getOptionalStringParam(params map[string]any, method, key string) (string, error) {
	val, ok := params[key]
	if !ok {
		return "", nil
	}
	strVal, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("invalid params for %s: '%s' must be string", method, key)
	}
	return strVal, nil
}

// getMapParam extracts a required map[string]any parameter from the params map.
//
// This function safely extracts a required map parameter from the parameters map.
// It performs type checking to ensure the parameter exists and is a map[string]any.
//
// Parameters:
//   - params: The parameters map from getParams()
//   - method: The method name for error reporting
//   - key: The parameter key to extract
//
// Returns:
//   - map[string]any: The extracted map value
//   - error: Error if the parameter is missing or not a map
//
// This function is used by MCP tool handlers to safely access required object/map parameters
// from [JSON-RPC] requests, such as certificate data or configuration objects.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func getMapParam(params map[string]any, method, key string) (map[string]any, error) {
	val, ok := params[key].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid params for %s: '%s' must be object", method, key)
	}
	return val, nil
}
