// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
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
			expectResult: version.Version, // Default version
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

func TestADKTransportBuilder_BuildTransport(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*ADKTransportBuilder) *ADKTransportBuilder
		expectError bool
		description string
	}{
		{
			name: "build inmemory transport with defaults",
			setup: func(b *ADKTransportBuilder) *ADKTransportBuilder {
				return b.WithInMemoryTransport()
			},
			expectError: false,
			description: "Should successfully build in-memory transport with default configuration",
		},
		{
			name: "build inmemory transport with custom config",
			setup: func(b *ADKTransportBuilder) *ADKTransportBuilder {
				return b.WithInMemoryTransport().WithVersion("2.0.0").WithMCPConfig("")
			},
			expectError: false,
			description: "Should successfully build in-memory transport with custom version and config",
		},
		{
			name: "build with invalid transport type",
			setup: func(b *ADKTransportBuilder) *ADKTransportBuilder {
				b.config.TransportType = "invalid"
				return b
			},
			expectError: true,
			description: "Should fail to build transport with invalid transport type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := tt.setup(NewADKTransportBuilder())

			transport, err := builder.BuildTransport(t.Context())

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tt.description)
				}
				if transport != nil {
					t.Errorf("Expected nil transport on error, but got %T", transport)
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
				return
			}

			if transport == nil {
				t.Errorf("Expected valid transport for %s, but got nil", tt.description)
				return
			}

			// Verify it's the expected transport type
			if inmemoryTransport, ok := transport.(*InMemoryTransport); ok {
				// Test basic transport functionality
				if inmemoryTransport.ctx == nil {
					t.Error("Transport context should not be nil")
				}
				if inmemoryTransport.recvCh == nil {
					t.Error("Transport recvCh should not be nil")
				}
				if inmemoryTransport.sendCh == nil {
					t.Error("Transport sendCh should not be nil")
				}

				// Test that sampling handler is set
				if inmemoryTransport.samplingHandler == nil {
					t.Error("Sampling handler should be set on transport")
				}

				// Clean up
				inmemoryTransport.Close()
			} else {
				t.Errorf("Expected *InMemoryTransport, got %T", transport)
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
			transport := NewInMemoryTransport(t.Context())
			err := transport.ConnectServer(t.Context(), s)
			if err != nil {
				t.Fatalf("Failed to connect server: %v", err)
			}
			defer transport.Close()

			// Send initialize request first (required for tools/call)
			initRequest := map[string]any{
				"jsonrpc": "2.0",
				"method":  "initialize",
				"params": map[string]any{
					"protocolVersion": "2024-11-05",
					"capabilities":    map[string]any{},
					"clientInfo": map[string]any{
						"name":    "test-client",
						"version": "1.0.0",
					},
				},
				"id": 0,
			}

			initData, _ := json.Marshal(initRequest)
			if err := transport.WriteMessage(initData); err != nil {
				t.Fatalf("Failed to write init message: %v", err)
			}

			// Wait for processing
			time.Sleep(500 * time.Millisecond)

			// Read init response
			if _, err := transport.ReadMessage(); err != nil {
				t.Fatalf("Failed to read init response: %v", err)
			}

			// Send initialized notification
			notifyRequest := map[string]any{
				"jsonrpc": "2.0",
				"method":  "notifications/initialized",
			}
			notifyData, _ := json.Marshal(notifyRequest)
			if err := transport.WriteMessage(notifyData); err != nil {
				t.Fatalf("Failed to write notify message: %v", err)
			}

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
			time.Sleep(500 * time.Millisecond)

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
	transport := NewInMemoryTransport(ctx)

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
		// read blocks test case removed - moved to TestADKTransportConnection_Blocking
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

				// Consume response to clear channel for next tests
				time.Sleep(50 * time.Millisecond)
				conn.Read(ctx)
			},
		},
		{
			name: "close method works",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {

				if err := conn.Close(); err != nil {
					t.Errorf("Close returned unexpected error: %v", err)
				}
			},
		},
		{
			name: "read fails after close",
			testFunc: func(t *testing.T, conn mcptransport.Connection) {
				if _, err := conn.Read(ctx); err == nil {
					t.Error("Read expected to fail after close, but it succeeded")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.testFunc(t, conn)
		})
	}
}

// TestADKTransportConnection_Blocking tests that Read blocks correctly until message or close
func TestADKTransportConnection_Blocking(t *testing.T) {
	ctx := t.Context() // Background context for manual control
	transport := NewInMemoryTransport(ctx)
	conn, _ := transport.Connect(ctx)

	done := make(chan error)
	go func() {
		_, err := conn.Read(ctx)
		done <- err
	}()

	select {
	case <-done:
		t.Error("Read returned immediately, expected to block")
	case <-time.After(50 * time.Millisecond):
		// Blocked correctly
	}

	// Unblock by closing transport
	transport.Close()

	select {
	case err := <-done:
		if err != io.EOF {
			t.Errorf("Expected EOF on close, got %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Read did not return after close")
	}
}

// TestADKTransportConnection_Advanced tests advanced connection scenarios
func TestADKTransportConnection_Advanced(t *testing.T) {

	// Create MCP server with multiple tools
	s := server.NewMCPServer(
		"Advanced Test Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// Add multiple tools for comprehensive testing
	tools := []struct {
		name        string
		description string
		handler     func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
	}{
		{
			name:        "echo_tool",
			description: "Echoes the input message",
			handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				params := request.Params
				args := params.Arguments.(map[string]any)
				msg := args["message"].(string)
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						mcp.NewTextContent("Echo: " + msg),
					},
				}, nil
			},
		},
		{
			name:        "math_tool",
			description: "Performs basic math operations",
			handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				params := request.Params
				args := params.Arguments.(map[string]any)
				a := args["a"].(float64)
				b := args["b"].(float64)
				op := args["operation"].(string)

				var result float64
				switch op {
				case "add":
					result = a + b
				case "subtract":
					result = a - b
				case "multiply":
					result = a * b
				case "divide":
					if b == 0 {
						return mcp.NewToolResultError("Division by zero"), nil
					}
					result = a / b
				default:
					return mcp.NewToolResultError("Unknown operation: " + op), nil
				}

				return &mcp.CallToolResult{
					Content: []mcp.Content{
						mcp.NewTextContent(fmt.Sprintf("%.2f", result)),
					},
				}, nil
			},
		},
		{
			name:        "error_tool",
			description: "Always returns an error",
			handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return nil, fmt.Errorf("intentional error for testing")
			},
		},
	}

	for _, tool := range tools {
		var mcpTool mcp.Tool
		switch tool.name {
		case "echo_tool":
			mcpTool = mcp.NewTool(tool.name,
				mcp.WithDescription(tool.description),
				mcp.WithString("message", mcp.Required(), mcp.Description("Message to echo")),
			)
		case "math_tool":
			mcpTool = mcp.NewTool(tool.name,
				mcp.WithDescription(tool.description),
				mcp.WithNumber("a", mcp.Required(), mcp.Description("First number")),
				mcp.WithNumber("b", mcp.Required(), mcp.Description("Second number")),
				mcp.WithString("operation", mcp.Required(), mcp.Description("Operation: add, subtract, multiply, divide")),
			)
		case "error_tool":
			mcpTool = mcp.NewTool(tool.name,
				mcp.WithDescription(tool.description),
			)
		}
		s.AddTool(mcpTool, tool.handler)
	}

	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	if err := transport.ConnectServer(ctx, s); err != nil {
		t.Fatalf("Failed to connect server: %v", err)
	}

	// Initialize client
	initRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
		"id": 0,
	}
	initData, _ := json.Marshal(initRequest)
	if err := transport.WriteMessage(initData); err != nil {
		t.Fatalf("Failed to write init message: %v", err)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	if _, err := transport.ReadMessage(); err != nil {
		t.Fatalf("Failed to read init response: %v", err)
	}

	notifyRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifyData, _ := json.Marshal(notifyRequest)
	if err := transport.WriteMessage(notifyData); err != nil {
		t.Fatalf("Failed to write notify message: %v", err)
	}

	// Note: This test uses internal transport methods for comprehensive testing
	// The ADK bridge interface is tested separately in TestADKTransportConnection
	testCases := []struct {
		name            string
		request         map[string]any
		expectError     bool
		expectToolError bool
		expectContains  string
		description     string
	}{
		{
			name: "echo_tool call",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name": "echo_tool",
					"arguments": map[string]any{
						"message": "Hello ADK Transport",
					},
				},
				"id": 1,
			},
			expectError:    false,
			expectContains: "Echo: Hello ADK Transport",
			description:    "Test successful tool call with string parameter",
		},
		{
			name: "math_tool addition",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name": "math_tool",
					"arguments": map[string]any{
						"a":         10.5,
						"b":         5.2,
						"operation": "add",
					},
				},
				"id": 2,
			},
			expectError:    false,
			expectContains: "15.70",
			description:    "Test math tool with floating point numbers",
		},
		{
			name: "math_tool division by zero",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name": "math_tool",
					"arguments": map[string]any{
						"a":         10.0,
						"b":         0.0,
						"operation": "divide",
					},
				},
				"id": 3,
			},
			expectError:     false, // Error in result, not in transport
			expectToolError: true,  // Expect isError: true in result
			expectContains:  "Division by zero",
			description:     "Test error handling in tool results",
		},
		{
			name: "error_tool call",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name":      "error_tool",
					"arguments": map[string]any{},
				},
				"id": 4,
			},
			expectError:    false, // Error in result
			expectContains: "intentional error for testing",
			description:    "Test tool that returns errors",
		},
		{
			name: "tools/list call",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/list",
				"id":      5,
			},
			expectError:    false,
			expectContains: "echo_tool",
			description:    "Test listing available tools",
		},
		{
			name: "invalid method",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "invalid/method",
				"id":      6,
			},
			expectError:    false, // Error in result
			expectContains: "not found",
			description:    "Test handling of unsupported methods",
		},
		{
			name: "malformed JSON",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params":  "not-an-object", // Invalid params
				"id":      7,
			},
			expectError:    false, // Error in result
			expectContains: "unparsable tools/call request",
			description:    "Test handling of malformed parameters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Send request using internal transport (this is what actually works for complex scenarios)
			data, err := json.Marshal(tc.request)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			err = transport.WriteMessage(data)
			if err != nil {
				t.Fatalf("Failed to write message: %v", err)
			}

			// Wait for processing
			time.Sleep(50 * time.Millisecond)

			// Read response using internal transport
			respData, err := transport.ReadMessage()
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}

			var resp map[string]any
			err = json.Unmarshal(respData, &resp)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			t.Logf("Test %s: Response: %s", tc.name, string(respData))

			// Check for expected content
			content := ""
			if result, ok := resp["result"].(map[string]any); ok {
				if resultContent, ok := result["content"].([]any); ok && len(resultContent) > 0 {
					if textContent, ok := resultContent[0].(map[string]any); ok {
						if text, ok := textContent["text"].(string); ok {
							content = text
						}
					}
				}
				// For tools/list, check the tools array
				if tools, ok := result["tools"].([]any); ok && len(tools) > 0 {
					if tool, ok := tools[0].(map[string]any); ok {
						if name, ok := tool["name"].(string); ok {
							content = name
						}
					}
				}
			}

			// Check error field
			if errorField, ok := resp["error"].(map[string]any); ok {
				if message, ok := errorField["message"].(string); ok {
					content = message
				}
			}

			if !strings.Contains(content, tc.expectContains) {
				t.Errorf("Expected response to contain %q, got: %s", tc.expectContains, content)
			}

			// Verify isError field when expectToolError is true
			if tc.expectToolError {
				if result, ok := resp["result"].(map[string]any); ok {
					if isError, ok := result["isError"].(bool); !ok || !isError {
						t.Error("Expected result.isError to be true")
					}
				} else {
					t.Error("Expected result object to be present")
				}
			}
		})
	}
}

// TestInMemoryTransport_SendJSONRPCNotification tests the mechanism used for streaming tokens
func TestInMemoryTransport_SendJSONRPCNotification(t *testing.T) {
	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	// Simulate streaming tokens
	go func() {
		tokens := []string{"Hello", " ", "World"}
		for _, token := range tokens {
			transport.SendJSONRPCNotification("notifications/sampling/progress", map[string]string{
				"content": token,
			})
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Read notifications
	received := ""
	for range 3 {
		msg, err := transport.ReadMessage()
		if err != nil {
			t.Fatalf("Failed to read message: %v", err)
		}

		var notification map[string]any
		if err := json.Unmarshal(msg, &notification); err != nil {
			t.Fatalf("Failed to unmarshal notification: %v", err)
		}

		if notification["method"] != "notifications/sampling/progress" {
			t.Errorf("Expected method 'notifications/sampling/progress', got %v", notification["method"])
		}

		params, ok := notification["params"].(map[string]any)
		if !ok {
			t.Fatalf("Expected params to be map, got %T", notification["params"])
		}

		if content, ok := params["content"].(string); ok {
			received += content
		}
	}

	if received != "Hello World" {
		t.Errorf("Expected 'Hello World', got '%s'", received)
	}
}

// TestADKTransportConnection_Concurrent tests basic transport functionality
func TestADKTransportConnection_Concurrent(t *testing.T) {
	s := server.NewMCPServer(
		"Concurrent Test Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	count := 50 // Test with multiple concurrent sends

	s.AddTool(mcp.NewTool("echo_tool", mcp.WithDescription("Echoes the input message")), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := request.Params
		args := params.Arguments.(map[string]any)
		msg := args["message"].(string)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.NewTextContent("Echo: " + msg),
			},
		}, nil
	})

	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)
	if err := transport.ConnectServer(ctx, s); err != nil {
		t.Fatalf("Failed to connect server: %v", err)
	}
	defer transport.Close()

	// Initialize client
	initRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
		"id": 0,
	}
	initData, _ := json.Marshal(initRequest)
	if err := transport.WriteMessage(initData); err != nil {
		t.Fatalf("Failed to write init message: %v", err)
	}

	// Read init response
	if _, err := transport.ReadMessage(); err != nil {
		t.Fatalf("Failed to read init response: %v", err)
	}

	// Send initialized notification
	notifyRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifyData, _ := json.Marshal(notifyRequest)
	if err := transport.WriteMessage(notifyData); err != nil {
		t.Fatalf("Failed to write notify message: %v", err)
	}

	// Test concurrent sends to transport
	var sendWg sync.WaitGroup
	sendWg.Add(count)

	sendErrors := make(chan error, count)
	for i := range count {
		go func(id int) {
			defer sendWg.Done()
			req := map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name": "echo_tool",
					"arguments": map[string]any{
						"message": fmt.Sprintf("msg-%d", id),
					},
				},
				"id": id,
			}
			data, _ := json.Marshal(req)
			if err := transport.WriteMessage(data); err != nil {
				sendErrors <- err
			}
		}(i)
	}

	// Wait for all sends to complete
	sendWg.Wait()
	close(sendErrors)

	// Check for send errors
	if err := <-sendErrors; err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Verify transport can handle concurrent sends without blocking
	t.Logf("Successfully sent %d messages concurrently to transport", count)

	// Consumer loop to read all responses
	responseIds := make(map[float64]bool)
	var respMu sync.Mutex

	consumeDone := make(chan struct{})
	go func() {
		for range count {
			msg, err := transport.ReadMessage()
			if err != nil {
				break
			}
			var resp map[string]any
			if err := json.Unmarshal(msg, &resp); err == nil {
				if id, ok := resp["id"].(float64); ok {
					respMu.Lock()
					responseIds[id] = true
					respMu.Unlock()
				}
			}
		}
		close(consumeDone)
	}()

	select {
	case <-consumeDone:
	case <-time.After(10 * time.Second): // Allow more time for serial processing
		t.Fatal("Timeout waiting for responses")
	}

	// Verify all responses received
	respMu.Lock()
	receivedCount := len(responseIds)
	respMu.Unlock()

	if receivedCount != count {
		t.Errorf("Expected %d responses, got %d", count, receivedCount)
	} else {
		t.Logf("Successfully received %d responses from transport", receivedCount)
	}
}

// TestADKTransportConnection_ErrorScenarios tests various error scenarios
func TestADKTransportConnection_ErrorScenarios(t *testing.T) {
	ctx := t.Context()

	testCases := []struct {
		name        string
		setupFunc   func() *InMemoryTransport
		expectError bool
		description string
	}{
		{
			name: "connect without server",
			setupFunc: func() *InMemoryTransport {
				transport := NewInMemoryTransport(ctx)
				// Try to write without connecting server - this should work but response will be empty
				return transport
			},
			expectError: false, // Transport allows writing without server, just no response
			description: "Writing without server connected should not fail at transport level",
		},
		{
			name: "double connect server",
			setupFunc: func() *InMemoryTransport {
				s := server.NewMCPServer("Test", "1.0.0")
				transport := NewInMemoryTransport(ctx)
				transport.ConnectServer(ctx, s) // First connect - should work
				transport.ConnectServer(ctx, s) // Second connect - should fail
				return transport
			},
			expectError: false, // The write should still work even if server connect failed
			description: "Double server connect should not prevent transport operation",
		},
		{
			name: "write after close",
			setupFunc: func() *InMemoryTransport {
				s := server.NewMCPServer("Test", "1.0.0")
				transport := NewInMemoryTransport(ctx)
				transport.ConnectServer(ctx, s)
				conn, _ := transport.Connect(ctx)
				conn.Close() // Close connection
				return transport
			},
			expectError: true, // Transport write should fail if context is cancelled
			description: "Writing after connection close should fail at transport level",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			transport := tc.setupFunc()

			// Try to send a request
			request := map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/list",
				"id":      1,
			}

			data, _ := json.Marshal(request)
			err := transport.WriteMessage(data)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tc.description)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tc.description, err)
			}
		})
	}
}

// TestADKTransportBridge tests the ADK transport bridge functionality
func TestADKTransportBridge(t *testing.T) {
	ctx := t.Context()

	// Create transport without server to test bridge conversion
	transport := NewInMemoryTransport(ctx)
	bridge := &ADKTransportConnection{transport: transport}

	// Test SessionID
	t.Run("session_id", func(t *testing.T) {
		sessionID := bridge.SessionID()
		if sessionID != "in-memory-transport" {
			t.Errorf("Expected session ID 'in-memory-transport', got '%s'", sessionID)
		}
	})

	// Test Close
	t.Run("close", func(t *testing.T) {
		err := bridge.Close()
		if err != nil {
			t.Errorf("Close should not fail: %v", err)
		}
	})

	// Test Read when context cancelled
	t.Run("read_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // Cancel immediately

		// Re-create transport with cancelled context
		transport := NewInMemoryTransport(ctx)
		bridge := &ADKTransportConnection{transport: transport}

		_, err := bridge.Read(ctx)
		if err != io.EOF {
			t.Errorf("Expected EOF when context cancelled, got: %v", err)
		}
	})
}

// TestADKTransportBridge_FullJSONRPC tests complete JSON-RPC request-response cycle through the bridge
func TestADKTransportBridge_FullJSONRPC(t *testing.T) {
	// Create MCP server with tools, resources, and prompts
	s := server.NewMCPServer(
		"Bridge Test Server",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
	)

	// Add test tools
	testTool := mcp.NewTool("echo_tool",
		mcp.WithDescription("Echoes the input message"),
		mcp.WithString("message", mcp.Required(), mcp.Description("Message to echo")),
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

	// Add test resource
	testResource := mcp.NewResource("test://resource",
		"Test Resource",
		mcp.WithMIMEType("text/plain"),
	)
	s.AddResource(testResource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "test://resource",
				MIMEType: "text/plain",
				Text:     "This is a test resource",
			},
		}, nil
	})

	// Add test prompt
	testPrompt := mcp.NewPrompt("test_prompt", mcp.WithPromptDescription("Test Prompt"))
	s.AddPrompt(testPrompt, func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "Test Prompt",
			Messages: []mcp.PromptMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent("Test Message"),
				},
			},
		}, nil
	})

	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	// Connect server to transport
	if err := transport.ConnectServer(ctx, s); err != nil {
		t.Fatalf("Failed to connect server: %v", err)
	}
	defer transport.Close()

	// Initialize client via transport methods (since we're using bridge)
	initRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
		"id": 0,
	}
	initData, _ := json.Marshal(initRequest)
	if err := transport.WriteMessage(initData); err != nil {
		t.Fatalf("Failed to write init message: %v", err)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	if _, err := transport.ReadMessage(); err != nil {
		t.Fatalf("Failed to read init response: %v", err)
	}

	notifyRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifyData, _ := json.Marshal(notifyRequest)
	if err := transport.WriteMessage(notifyData); err != nil {
		t.Fatalf("Failed to write notify message: %v", err)
	}

	// Create bridge
	bridge := &ADKTransportConnection{transport: transport}

	testCases := []struct {
		name          string
		request       map[string]any
		expectID      float64
		expectResult  bool
		expectContent string
	}{
		{
			name: "tools/list",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/list",
				"id":      1,
			},
			expectID:      1,
			expectResult:  true,
			expectContent: "echo_tool",
		},
		{
			name: "tools/call",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name": "echo_tool",
					"arguments": map[string]any{
						"message": "Hello Bridge",
					},
				},
				"id": 2,
			},
			expectID:      2,
			expectResult:  true,
			expectContent: "Echo: Hello Bridge",
		},
		{
			name: "resources/list",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "resources/list",
				"id":      3,
			},
			expectID:      3,
			expectResult:  true,
			expectContent: "Test Resource",
		},
		{
			name: "resources/read",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "resources/read",
				"params": map[string]any{
					"uri": "test://resource",
				},
				"id": 4,
			},
			expectID:      4,
			expectResult:  true,
			expectContent: "This is a test resource",
		},
		{
			name: "prompts/list",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "prompts/list",
				"id":      5,
			},
			expectID:      5,
			expectResult:  true,
			expectContent: "test_prompt",
		},
		{
			name: "prompts/get",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "prompts/get",
				"params": map[string]any{
					"name": "test_prompt",
				},
				"id": 6,
			},
			expectID:      6,
			expectResult:  true,
			expectContent: "Test Message",
		},
		{
			name: "ping",
			request: map[string]any{
				"jsonrpc": "2.0",
				"method":  "ping",
				"id":      7,
			},
			expectID:      7,
			expectResult:  true,
			expectContent: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert request to JSON-RPC message
			data, err := json.Marshal(tc.request)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			t.Logf("Sending JSON request: %s", string(data))

			jsonrpcMsg, err := jsonrpc.DecodeMessage(data)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			// Re-encode using MCP SDK for consistent formatting
			encodedData, err := jsonrpc.EncodeMessage(jsonrpcMsg)
			if err != nil {
				t.Fatalf("Failed to encode message: %v", err)
			}

			t.Logf("Sending JSON-RPC request: --> %s", string(encodedData))

			// Write through bridge
			err = bridge.Write(ctx, jsonrpcMsg)
			if err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			// Wait for processing
			time.Sleep(500 * time.Millisecond)

			// Read response through bridge
			respMsg, err := bridge.Read(ctx)
			if err != nil {
				t.Fatalf("Bridge Read failed: %v", err)
			}

			// Use proper wire format encoding
			wireData, err := jsonrpc.EncodeMessage(respMsg)
			if err != nil {
				t.Fatalf("Failed to encode message: %v", err)
			}

			t.Logf("Received JSON-RPC response: <-- %s", string(wireData))

			// Parse the response using proper wire format
			var resp map[string]any
			err = json.Unmarshal(wireData, &resp)

			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			// Validate response - handle jsonrpc.Message format
			if resp["error"] != nil {
				t.Errorf("Response contains error: %v", resp["error"])
			}

			result, ok := resp["result"].(map[string]any)
			if !ok {
				t.Errorf("Expected result field in response")
				return
			}

			// Validate response id
			if idValue, ok := resp["id"].(float64); ok {
				if idValue != tc.expectID {
					t.Errorf("Expected id %v, got %v", tc.expectID, idValue)
				}
			} else {
				t.Errorf("Expected id field to be a number, got %T", resp["id"])
			}

			// Check content based on test case
			if tc.expectContent != "" {
				content := ""

				switch tc.name {
				case "tools/list":
					if tools, ok := result["tools"].([]any); ok && len(tools) > 0 {
						if tool, ok := tools[0].(map[string]any); ok {
							if name, ok := tool["name"].(string); ok {
								content = name
							}
						}
					}
				case "resources/list":
					if resources, ok := result["resources"].([]any); ok && len(resources) > 0 {
						if resource, ok := resources[0].(map[string]any); ok {
							if name, ok := resource["name"].(string); ok {
								content = name
							}
						}
					}
				case "resources/read":
					if contents, ok := result["contents"].([]any); ok && len(contents) > 0 {
						if item, ok := contents[0].(map[string]any); ok {
							if text, ok := item["text"].(string); ok {
								content = text
							}
						}
					}
				case "prompts/list":
					if prompts, ok := result["prompts"].([]any); ok && len(prompts) > 0 {
						if prompt, ok := prompts[0].(map[string]any); ok {
							if name, ok := prompt["name"].(string); ok {
								content = name
							}
						}
					}
				case "prompts/get":
					if messages, ok := result["messages"].([]any); ok && len(messages) > 0 {
						if message, ok := messages[0].(map[string]any); ok {
							if contentMap, ok := message["content"].(map[string]any); ok {
								if text, ok := contentMap["text"].(string); ok {
									content = text
								}
							}
						}
					}
				case "ping":
					// Ping returns empty result, content check is empty string
					content = ""
				default: // tools/call
					if resultContent, ok := result["content"].([]any); ok && len(resultContent) > 0 {
						if textContent, ok := resultContent[0].(map[string]any); ok {
							if text, ok := textContent["text"].(string); ok {
								content = text
							}
						}
					}
				}

				if content != tc.expectContent {
					t.Errorf("Expected content %q, got %q", tc.expectContent, content)
				}
			}
		})
	}
}

// TestADKTransportBridge_WithSDKClient (Robust) tests the bridge using the official SDK client
// This simulates how ADK uses the transport (since ADK wraps the SDK)
func TestADKTransportBridge_WithSDKClient(t *testing.T) {
	// Create MCP server
	s := server.NewMCPServer(
		"SDK Client Test Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// Add a simple tool
	testTool := mcp.NewTool("sdk_echo",
		mcp.WithDescription("Echoes message"),
		mcp.WithString("message", mcp.Required(), mcp.Description("Message to echo")),
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

	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	// Connect server to transport (bridge side)
	if err := transport.ConnectServer(ctx, s); err != nil {
		t.Fatalf("Failed to connect server: %v", err)
	}
	defer transport.Close()

	// Create official SDK client
	client := mcptransport.NewClient(&mcptransport.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}, nil)

	// Connect client to transport (this establishes session and performs handshake)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Failed to connect SDK client: %v", err)
	}
	defer session.Close()

	// List tools
	listParams := mcptransport.ListToolsParams{}
	toolsResult, err := session.ListTools(ctx, &listParams)
	if err != nil {
		t.Fatalf("Failed to list tools: %v", err)
	}

	// Log ListTools response
	toolsJSON, _ := json.MarshalIndent(toolsResult, "", "  ")
	t.Logf("SDK ListTools Response: %s", string(toolsJSON))

	found := false
	for _, tool := range toolsResult.Tools {
		if tool.Name == "sdk_echo" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find 'sdk_echo' tool")
	}

	// Call tool
	callParams := mcptransport.CallToolParams{
		Name: "sdk_echo",
		Arguments: map[string]any{
			"message": "Hello SDK",
		},
	}
	callResult, err := session.CallTool(ctx, &callParams)
	if err != nil {
		t.Fatalf("Failed to call tool: %v", err)
	}

	// Log CallTool response
	callJSON, _ := json.MarshalIndent(callResult, "", "  ")
	t.Logf("SDK CallTool Response: %s", string(callJSON))

	if len(callResult.Content) == 0 {
		t.Fatal("Expected content in tool result")
	}

	// Content is interface{}, need to type assert
	// SDK usually returns []Content interface
	// Check if it's TextContent (pointer receiver)
	if textContent, ok := callResult.Content[0].(*mcptransport.TextContent); ok {
		if textContent.Text != "Echo: Hello SDK" {
			t.Errorf("Expected 'Echo: Hello SDK', got '%s'", textContent.Text)
		}
	} else {
		// It might be a pointer or different structure depending on SDK version
		t.Logf("Content type: %T", callResult.Content[0])
		// Try simplified check via JSON marshalling if type assertion fails
		bytes, _ := json.Marshal(callResult.Content[0])
		if !strings.Contains(string(bytes), "Echo: Hello SDK") {
			t.Errorf("Expected content to contain 'Echo: Hello SDK', got %s", string(bytes))
		}
	}
}

func TestInMemoryTransport_Concurrency(t *testing.T) {
	s := server.NewMCPServer(
		"Concurrent Test Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	count := 50 // Increase count to verify higher concurrency

	// Synchronization primitives
	var mu sync.Mutex
	active := 0
	maxActive := 0

	// readyWg waits for all handlers to start
	var readyWg sync.WaitGroup
	readyWg.Add(count)

	// gate blocks handlers until we release them
	gate := make(chan struct{})

	s.AddTool(mcp.NewTool("barrier_tool", mcp.WithDescription("waits for barrier")), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		// Signal that this handler is active
		readyWg.Done()

		// Wait for the gate to open (or context cancel)
		select {
		case <-gate:
			// Continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		mu.Lock()
		active--
		mu.Unlock()

		return &mcp.CallToolResult{Content: []mcp.Content{mcp.NewTextContent("done")}}, nil
	})

	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)
	// Increase worker pool size to handle concurrent requests
	// Default is 5, which causes timeout when waiting for 50
	if err := transport.ConnectServer(ctx, s, server.WithWorkerPoolSize(count)); err != nil {
		t.Fatalf("Failed to connect server: %v", err)
	}
	defer transport.Close()

	// Initialize client
	initRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
		"id": 0,
	}
	initData, _ := json.Marshal(initRequest)
	if err := transport.WriteMessage(initData); err != nil {
		t.Fatalf("Failed to write init message: %v", err)
	}

	// Read init response
	if _, err := transport.ReadMessage(); err != nil {
		t.Fatalf("Failed to read init response: %v", err)
	}

	// Send initialized notification
	notifyRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifyData, _ := json.Marshal(notifyRequest)
	if err := transport.WriteMessage(notifyData); err != nil {
		t.Fatalf("Failed to write notify message: %v", err)
	}

	// Run multiple requests concurrently
	// Use a separate WaitGroup for the senders to ensure they are all sent
	var sendWg sync.WaitGroup
	sendWg.Add(count)

	for i := range count {
		go func(id int) {
			defer sendWg.Done()
			req := map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params": map[string]any{
					"name":      "barrier_tool",
					"arguments": map[string]any{},
				},
				"id": id,
			}
			data, _ := json.Marshal(req)
			transport.WriteMessage(data)
		}(i)
	}

	// Wait for all requests to be sent
	sendWg.Wait()

	// Wait for all handlers to become active
	// This proves that 'count' requests are processing simultaneously
	// If the server serializes requests, this will deadlock/timeout
	doneCh := make(chan struct{})
	go func() {
		readyWg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// Success: all handlers are active
	case <-time.After(5 * time.Second):
		t.Fatalf("Timeout waiting for concurrent handlers. Active: %d/%d", active, count)
	}

	// Verify peak concurrency
	mu.Lock()
	peak := maxActive
	mu.Unlock()

	if peak != count {
		t.Errorf("Expected max concurrency %d, got %d", count, peak)
	} else {
		t.Logf("Successfully achieved %d concurrent executions", peak)
	}

	// Release all handlers
	close(gate)

	// Consumer loop to drain responses
	responseIds := make(map[float64]bool)
	var respMu sync.Mutex

	consumeDone := make(chan struct{})
	go func() {
		for range count {
			msg, err := transport.ReadMessage()
			if err != nil {
				break
			}
			var resp map[string]any
			if err := json.Unmarshal(msg, &resp); err == nil {
				if id, ok := resp["id"].(float64); ok {
					respMu.Lock()
					responseIds[id] = true
					respMu.Unlock()
				}
			}
		}
		close(consumeDone)
	}()

	select {
	case <-consumeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for responses")
	}

	// Verify all responses received
	respMu.Lock()
	if len(responseIds) != count {
		t.Errorf("Expected %d responses, got %d", count, len(responseIds))
	}
	respMu.Unlock()
}

func TestInMemoryTransport_GracefulShutdown(t *testing.T) {
	// Create a server with a tool that we can signal to finish
	s := server.NewMCPServer("Shutdown Server", "1.0.0", server.WithToolCapabilities(true))

	// Using a channel to control when the tool finishes
	// This allows us to block the tool, call Close(), and ensure Close() waits
	// UNLESS context cancellation aborts the tool immediately.
	// In real world, cancellation happens.
	// We want to verify Close() doesn't race or panic.

	s.AddTool(mcp.NewTool("block_tool", mcp.WithDescription("blocks")), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		select {
		case <-time.After(200 * time.Millisecond):
			return &mcp.CallToolResult{Content: []mcp.Content{mcp.NewTextContent("finished")}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)
	if err := transport.ConnectServer(ctx, s); err != nil {
		t.Fatalf("Failed to connect server: %v", err)
	}

	// Initialize client
	initRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
		"id": 0,
	}
	initData, _ := json.Marshal(initRequest)
	if err := transport.WriteMessage(initData); err != nil {
		t.Fatalf("Failed to write init message: %v", err)
	}

	// Read init response
	if _, err := transport.ReadMessage(); err != nil {
		t.Fatalf("Failed to read init response: %v", err)
	}

	// Send initialized notification
	notifyRequest := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifyData, _ := json.Marshal(notifyRequest)
	if err := transport.WriteMessage(notifyData); err != nil {
		t.Fatalf("Failed to write notify message: %v", err)
	}

	// Send request
	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "block_tool",
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	data, _ := json.Marshal(req)
	if err := transport.WriteMessage(data); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}

	// Give it a moment to start processing
	time.Sleep(10 * time.Millisecond)

	// Close should cancel context, which aborts tool, and then wait for goroutine to exit
	start := time.Now()
	transport.Close()
	duration := time.Since(start)

	t.Logf("Close took %v", duration)

	// Consume response if any (might be dropped due to context cancel)
	// transport.ReadMessage() should return EOF or error now
	_, err := transport.ReadMessage()
	if err == nil {
		t.Log("ReadMessage returned nil error after Close")
	}
}
