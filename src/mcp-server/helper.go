// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import "fmt"

// getParams extracts parameters from a normalized JSON-RPC request.
func getParams(req map[string]any, method string) (map[string]any, error) {
	p, ok := req["params"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid %s params", method)
	}
	return p, nil
}
