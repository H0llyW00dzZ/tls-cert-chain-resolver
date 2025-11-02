// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"github.com/mark3labs/mcp-go/server"
)

// addResources adds static resources to the MCP server
func addResources(s *server.MCPServer) {
	resources := createResources()
	for _, r := range resources {
		s.AddResource(r.Resource, r.Handler)
	}
}
