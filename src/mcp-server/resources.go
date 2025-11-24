// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"github.com/mark3labs/mcp-go/server"
)

// addResources adds static resources to the MCP server.
//
// This function creates all MCP resources using createResources()
// and registers them with the provided MCP server instance.
// Resources include configuration templates, version information,
// certificate format documentation, and server status.
//
// Parameters:
//   - s: The MCP server instance to add resources to
//
// This function should be called during server initialization
// to make static resources available to MCP clients.
func addResources(s *server.MCPServer) {
	resources := createResources()
	for _, r := range resources {
		s.AddResource(r.Resource, r.Handler)
	}
}
