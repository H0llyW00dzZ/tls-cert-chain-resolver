// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcptransport "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestADKTransportBuilder_WithVersion(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		expectResult string
	}{
		{
			name:         "default version",
			version:      "",
			expectResult: "1.0.0", // Default version
		},
		{
			name:         "custom version",
			version:      "2.0.0",
			expectResult: "2.0.0",
		},
		{
			name:         "patch version",
			version:      "1.2.3",
			expectResult: "1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewADKTransportBuilder()
			if tt.version != "" {
				builder = builder.WithVersion(tt.version)
			}

			if builder.config.Version != tt.expectResult {
				t.Errorf("Expected version '%s', got '%s'", tt.expectResult, builder.config.Version)
			}
		})
	}
}

func TestADKTransportBuilder_WithMCPConfig(t *testing.T) {
	tests := []struct {
		name         string
		configFile   string
		expectResult string
	}{
		{
			name:         "custom config file",
			configFile:   "/custom/config.json",
			expectResult: "/custom/config.json",
		},
		{
			name:         "relative config file",
			configFile:   "config/local.json",
			expectResult: "config/local.json",
		},
		{
			name:         "empty config file",
			configFile:   "",
			expectResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewADKTransportBuilder().
				WithMCPConfig(tt.configFile)

			if builder.config.MCPConfigFile != tt.expectResult {
				t.Errorf("Expected config file '%s', got '%s'", tt.expectResult, builder.config.MCPConfigFile)
			}
		})
	}
}

func TestADKTransportBuilder_WithInMemoryTransport(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(*ADKTransportBuilder) *ADKTransportBuilder
		expectResult string
	}{
		{
			name: "set inmemory transport",
			setup: func(b *ADKTransportBuilder) *ADKTransportBuilder {
				return b.WithInMemoryTransport()
			},
			expectResult: "inmemory",
		},
		{
			name: "default transport type",
			setup: func(b *ADKTransportBuilder) *ADKTransportBuilder {
				return b // No transport set, but default is inmemory
			},
			expectResult: "inmemory", // Default is inmemory
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := tt.setup(NewADKTransportBuilder())

			if builder.config.TransportType != tt.expectResult {
				t.Errorf("Expected transport type '%s', got '%s'", tt.expectResult, builder.config.TransportType)
			}
		})
	}
}

func TestADKTransportBuilder_ValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		transportType string
		expectError   bool
	}{
		{
			name:          "valid inmemory transport",
			transportType: "inmemory",
			expectError:   false,
		},
		{
			name:          "invalid transport type",
			transportType: "invalid",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewADKTransportBuilder()
			builder.config.TransportType = tt.transportType

			err := builder.ValidateConfig()
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestInMemoryTransport_JSONRPC(t *testing.T) {
	tests := []struct {
		name            string
		request         map[string]any
		expectID        float64
		expectHasResult bool
		expectContent   string
	}{
		{
			name: "tools/call request",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name": "test_tool",
					"arguments": map[string]any{
						"message": "Hello World",
					},
				},
				"id": 3,
			},
			expectID:        3,
			expectHasResult: true,
			expectContent:   "Echo: Hello World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create MCP server
			s := server.NewMCPServer(
				"Test Server",
				"1.0.0",
				server.WithToolCapabilities(true),
			)

			// Add a simple tool for testing
			testTool := mcp.NewTool("test_tool",
				mcp.WithDescription("Test tool for transport"),
				mcp.WithString("message",
					mcp.Required(),
					mcp.Description("Message to echo"),
				),
			)

			s.AddTool(testTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				params := request.Params
				args := params.Arguments.(map[string]any)
				msg := args["message"].(string)
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						mcp.NewTextContent("Echo: " + msg),
					},
				}, nil
			})

			// Create transport and connect server
			transport := NewInMemoryTransport()
			err := transport.ConnectServer(t.Context(), s)
			if err != nil {
				t.Fatalf("Failed to connect server: %v", err)
			}
			defer transport.Close()

			// Send JSON-RPC request
			data, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			err = transport.WriteMessage(data)
			if err != nil {
				t.Fatalf("Failed to write message: %v", err)
			}

			// Wait for processing
			time.Sleep(100 * time.Millisecond)

			// Read response
			respData, err := transport.ReadMessage()
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}

			var resp map[string]any
			err = json.Unmarshal(respData, &resp)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			t.Logf("Response: %s", string(respData))

			if resp["id"].(float64) != tt.expectID {
				t.Errorf("Expected id %v, got %v", tt.expectID, resp["id"])
			}

			if tt.expectHasResult && resp["result"] == nil {
				t.Errorf("Expected result in response")
			}

			// For tools/call, check the content
			if tt.expectContent != "" {
				result := resp["result"].(map[string]any)
				content := result["content"].([]any)
				if len(content) == 0 {
					t.Errorf("Expected content in result")
				}

				textContent := content[0].(map[string]any)
				if textContent["text"] != tt.expectContent {
					t.Errorf("Expected '%s', got %v", tt.expectContent, textContent["text"])
				}
			}
		})
	}
}

func TestADKTransportConnection(t *testing.T) {
	// Create MCP server
	s := server.NewMCPServer(
		"Test Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)
	ctx := t.Context()
	// Add a simple tool for testing
	testTool := mcp.NewTool("test_tool",
		mcp.WithDescription("Test tool for connection"),
		mcp.WithString("message",
			mcp.Required(),
			mcp.Description("Message to echo"),
		),
	)

	s.AddTool(testTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := request.Params
		args := params.Arguments.(map[string]any)
		msg := args["message"].(string)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.NewTextContent("Echo: " + msg),
			},
		}, nil
	})

	// Create transport
	transport := NewInMemoryTransport()

	// Connect transport to server (this is what BuildInMemoryTransport does)
	if err := transport.ConnectServer(ctx, s); err != nil {
		t.Fatalf("Failed to connect server: %v", err)
	}

	// Test Connect method returns ADKTransportConnection
	conn, err := transport.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	tests := []struct {
		name     string
		testFunc func(t *testing.T, conn mcptransport.Connection)
	}{
		{
			name: "connection is not nil",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {
				if conn == nil {
					t.Error("Connect returned nil connection")
				}
			},
		},
		{
			name: "session ID is correct",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {
				sessionID := conn.SessionID()
				if sessionID != "in-memory-transport" {
					t.Errorf("Expected session ID 'in-memory-transport', got '%s'", sessionID)
				}
			},
		},
		{
			name: "read returns EOF when no message available",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {

				if _, err := conn.Read(ctx); err != io.EOF {
					t.Errorf("Expected EOF when no message available, got %v", err)
				}
			},
		},
		{
			name: "write method accepts valid message",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {
				// Create a simple JSON-RPC message
				requestData, err := json.Marshal(map[string]any{
					"jsonrpc": "2.0",
					"method":  "tools/list",
					"id":      1,
				})
				if err != nil {
					t.Fatalf("Failed to marshal request: %v", err)
				}

				jsonrpcMsg, err := jsonrpc.DecodeMessage(requestData)
				if err != nil {
					t.Fatalf("Failed to decode message: %v", err)
				}

				// Test that Write doesn't return an error

				if err = conn.Write(ctx, jsonrpcMsg); err != nil {
					t.Errorf("Write returned unexpected error: %v", err)
				}
			},
		},
		{
			name: "close method works",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {

				if err := conn.Close(); err != nil {
					t.Errorf("Failed to close connection: %v", err)
				}
			},
		},
		{
			name: "read fails after close",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {

				if _, err := conn.Read(ctx); err == nil {
					t.Error("Expected error when reading from closed connection")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t, conn)
		})
	}
}
