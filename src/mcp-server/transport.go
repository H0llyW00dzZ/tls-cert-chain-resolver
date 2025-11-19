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
	"sync"

	jsonrpcInternal "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/jsonrpc"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcptransport "github.com/modelcontextprotocol/go-sdk/mcp"
)

// InMemoryTransport implements ADK SDK mcp.Transport interface
// It bridges between [Official MCP SDK] transport expectations and [mark3labs/mcp-go] client
//
// [mark3labs/mcp-go]: https://pkg.go.dev/github.com/mark3labs/mcp-go
// [Official MCP SDK]: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk
type InMemoryTransport struct {
	client  *client.Client // mark3labs in-process client
	started bool
	mu      sync.Mutex
	recvCh  chan []byte // channel for receiving messages (ReadMessage)
	sendCh  chan []byte // channel for sending messages (WriteMessage)
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewInMemoryTransport creates a new in-memory transport that implements mcp.Transport
// This is designed to work with ADK's [mcptoolset.New] expectations
func NewInMemoryTransport(ctx context.Context) *InMemoryTransport {
	ctx, cancel := context.WithCancel(ctx)
	return &InMemoryTransport{
		recvCh: make(chan []byte, 1),
		sendCh: make(chan []byte, 1),
		ctx:    ctx,
		cancel: cancel,
	}
}

// ReadMessage implements [mcp.Transport.ReadMessage]
// For ADK compatibility, this should return JSON-RPC messages
// Uses channel-based message passing for in-memory communication
func (t *InMemoryTransport) ReadMessage() ([]byte, error) {
	select {
	case msg := <-t.recvCh:
		return msg, nil
	default:
		return nil, io.EOF
	}
}

// WriteMessage implements [mcp.Transport.WriteMessage]
// For ADK compatibility, this should accept JSON-RPC messages
// Uses channel-based message passing for in-memory communication
func (t *InMemoryTransport) WriteMessage(data []byte) error {
	if err := t.ctx.Err(); err != nil {
		return err
	}
	select {
	case t.sendCh <- data:
		return nil
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

// Close implements mcp.Transport.Close()
func (t *InMemoryTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
	}

	// Don't close channels here as they may still be used by goroutines
	// The context cancellation will cause goroutines to exit cleanly
	t.started = false
	return nil
}

// Connect implements ADK SDK mcp.Transport interface
func (t *InMemoryTransport) Connect(ctx context.Context) (mcptransport.Connection, error) {
	// For ADK compatibility, return a connection that wraps this transport
	return &ADKTransportConnection{
		transport: t,
	}, nil
}

// ConnectServer connects a mark3labs MCP server to this transport (public method for testing/docs)
func (t *InMemoryTransport) ConnectServer(ctx context.Context, srv *server.MCPServer) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.started {
		return fmt.Errorf("transport already connected")
	}

	// Create mark3labs in-process client
	var err error
	t.client, err = client.NewInProcessClient(srv)
	if err != nil {
		return fmt.Errorf("failed to create in-process client: %w", err)
	}

	// Start the client
	if err := t.client.Start(t.ctx); err != nil {
		return fmt.Errorf("failed to start client: %w", err)
	}

	// Initialize the client
	initReq := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities:    mcp.ClientCapabilities{},
		},
	}
	if _, err := t.client.Initialize(t.ctx, initReq); err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}

	// Start message processing goroutine
	go t.processMessages()

	t.started = true
	return nil
}

// processMessages handles JSON-RPC message processing between ADK and the MCP client
func (t *InMemoryTransport) processMessages() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case data := <-t.sendCh:
			var req map[string]any
			if err := json.Unmarshal(data, &req); err != nil {
				// Send parse error response
				resp := map[string]any{
					"jsonrpc": "2.0",
					"error": map[string]any{
						"code":    -32700,
						"message": "Parse error",
					},
					"id": nil,
				}
				t.sendResponse(resp)
			} else {
				// Normalize request keys to handle both lowercase and capitalized
				normalizedReq := jsonrpcInternal.Map(req)
				id := normalizedReq["id"]
				var idInt any
				if id != nil {
					// Handle different ID types - preserve as-is
					idInt = id
				} else {
					// For requests without ID (notifications), use null
					idInt = nil
				}

				method, ok := normalizedReq["method"].(string)
				if !ok {
					err := fmt.Errorf("invalid method: expected string, got %T", normalizedReq["method"])
					// Only send error if it's a request (has ID)
					if idInt != nil {
						resp := map[string]any{
							"jsonrpc": "2.0",
							"id":      idInt,
							"error": map[string]any{
								"code":    -32600,
								"message": err.Error(),
							},
						}
						t.sendResponse(resp)
					}
					continue
				}

				// Handle notifications that don't require a response or action in this bridge
				if method == "notifications/initialized" {
					continue
				}

				var result any
				var err error
				switch method {
				case "initialize":
					initParams, ok := normalizedReq["params"].(map[string]any)
					if !ok {
						err = fmt.Errorf("invalid initialize params")
					} else {
						initReq := mcp.InitializeRequest{
							Params: mcp.InitializeParams{
								ProtocolVersion: initParams["protocolVersion"].(string),
								Capabilities:    mcp.ClientCapabilities{},
							},
						}
						resp, e := t.client.Initialize(t.ctx, initReq)
						if e != nil {
							// Check if this is an unsupported protocol version error
							if mcp.IsUnsupportedProtocolVersion(e) {
								err = fmt.Errorf("unsupported protocol version: %w", e)
							} else {
								err = e
							}
						} else {
							result = resp
						}
					}
				case "tools/list":
					if t.client != nil {
						listReq := mcp.ListToolsRequest{}
						resp, e := t.client.ListTools(t.ctx, listReq)
						if e != nil {
							err = e
						} else {
							result = resp
						}
					}
				case "tools/call":
					if t.client != nil {
						callParams, ok := normalizedReq["params"].(map[string]any)
						if !ok {
							err = fmt.Errorf("invalid tools/call params")
						} else {
							callReq := mcp.CallToolRequest{
								Params: mcp.CallToolParams{
									Name:      callParams["name"].(string),
									Arguments: callParams["arguments"].(map[string]any),
								},
							}
							resp, e := t.client.CallTool(t.ctx, callReq)
							if e != nil {
								err = e
							} else {
								result = resp
							}
						}
					}
				case "resources/list":
					if t.client != nil {
						listReq := mcp.ListResourcesRequest{}
						if params, ok := normalizedReq["params"].(map[string]any); ok {
							if cursor, ok := params["cursor"].(string); ok {
								listReq.Params.Cursor = mcp.Cursor(cursor)
							}
						}
						resp, e := t.client.ListResources(t.ctx, listReq)
						if e != nil {
							err = e
						} else {
							result = resp
						}
					}
				case "resources/read":
					if t.client != nil {
						readParams, ok := normalizedReq["params"].(map[string]any)
						if !ok {
							err = fmt.Errorf("invalid resources/read params")
						} else {
							uri, ok := readParams["uri"].(string)
							if !ok {
								err = fmt.Errorf("invalid uri parameter")
							} else {
								readReq := mcp.ReadResourceRequest{
									Params: mcp.ReadResourceParams{
										URI: uri,
									},
								}
								resp, e := t.client.ReadResource(t.ctx, readReq)
								if e != nil {
									err = e
								} else {
									result = resp
								}
							}
						}
					}
				case "prompts/list":
					if t.client != nil {
						listReq := mcp.ListPromptsRequest{}
						if params, ok := normalizedReq["params"].(map[string]any); ok {
							if cursor, ok := params["cursor"].(string); ok {
								listReq.Params.Cursor = mcp.Cursor(cursor)
							}
						}
						resp, e := t.client.ListPrompts(t.ctx, listReq)
						if e != nil {
							err = e
						} else {
							result = resp
						}
					}
				case "prompts/get":
					if t.client != nil {
						getParams, ok := normalizedReq["params"].(map[string]any)
						if !ok {
							err = fmt.Errorf("invalid prompts/get params")
						} else {
							name, ok := getParams["name"].(string)
							if !ok {
								err = fmt.Errorf("invalid name parameter")
							} else {
								var arguments map[string]string
								if args, ok := getParams["arguments"].(map[string]any); ok {
									arguments = make(map[string]string)
									for k, v := range args {
										arguments[k] = fmt.Sprint(v)
									}
								}
								getReq := mcp.GetPromptRequest{
									Params: mcp.GetPromptParams{
										Name:      name,
										Arguments: arguments,
									},
								}
								resp, e := t.client.GetPrompt(t.ctx, getReq)
								if e != nil {
									err = e
								} else {
									result = resp
								}
							}
						}
					}
				default:
					err = fmt.Errorf("method not supported: %s", method)
				}

				// JSON-RPC 2.0: Server MUST NOT reply to a Notification (request without ID)
				if idInt == nil {
					continue
				}

				resp := map[string]any{
					"jsonrpc": "2.0",
					"id":      idInt, // Use the request ID for responses
				}
				if err != nil {
					resp["error"] = map[string]any{
						"code":    -32603,
						"message": err.Error(),
					}
				} else {
					resp["result"] = result
				}
				t.sendResponse(resp)
			}
		}
	}
}

// sendResponse sends a JSON-RPC response to the receive channel
func (t *InMemoryTransport) sendResponse(resp map[string]any) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	select {
	case t.recvCh <- data:
	case <-t.ctx.Done():
		// Context cancelled, drop response
	}
}

// ADKTransportConnection wraps InMemoryTransport for ADK SDK
type ADKTransportConnection struct {
	transport *InMemoryTransport
}

// Read implements [mcptransport.Connection.Read]
func (c *ADKTransportConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	// Delegate to underlying transport's ReadMessage
	data, err := c.transport.ReadMessage()
	if err != nil {
		return nil, err
	}

	// Decode directly without normalization for responses
	msg, err := jsonrpc.DecodeMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON-RPC message: %w", err)
	}

	return msg, nil
}

// Write implements mcptransport.Connection.Write
func (c *ADKTransportConnection) Write(ctx context.Context, msg jsonrpc.Message) error {
	// Use MCP SDK's EncodeMessage to properly serialize the message
	data, err := jsonrpc.EncodeMessage(msg)
	if err != nil {
		return err
	}

	return c.transport.WriteMessage(data)
}

// Close implements mcptransport.Connection.Close
func (c *ADKTransportConnection) Close() error {
	// Delegate to underlying transport's Close
	return c.transport.Close()
}

// SessionID implements mcptransport.Connection.SessionID
func (c *ADKTransportConnection) SessionID() string {
	return "in-memory-transport"
}

// TransportBuilder helps construct MCP transports for different integration scenarios
//
// This builder provides transport creation utilities that can be used by different
// integration layers (ADK, CLI, etc.) to create appropriate transport mechanisms.
// For in-memory scenarios, it returns the built MCP server for direct integration.
type TransportBuilder struct {
	serverBuilder *ServerBuilder
}

// NewTransportBuilder creates a new transport builder
func NewTransportBuilder() *TransportBuilder {
	return &TransportBuilder{
		serverBuilder: NewServerBuilder(),
	}
}

// WithConfig sets the server configuration
func (tb *TransportBuilder) WithConfig(config *Config) *TransportBuilder {
	tb.serverBuilder.WithConfig(config)
	return tb
}

// WithVersion sets the server version
func (tb *TransportBuilder) WithVersion(version string) *TransportBuilder {
	tb.serverBuilder.WithVersion(version)
	return tb
}

// WithDefaultTools adds the default X509 certificate tools
func (tb *TransportBuilder) WithDefaultTools() *TransportBuilder {
	tb.serverBuilder.WithDefaultTools()
	return tb
}

// BuildInMemoryTransport creates an in-memory MCP transport for ADK integration
//
// This follows the ADK pattern where [mcp.NewInMemoryTransports] creates paired
// client and server transports, server connects to server transport, and client
// transport is returned for use with [mcptoolset.New].
//
// For our implementation using [mark3labs/mcp-go], we create the server using
// ServerBuilder, then return a transport that can communicate with it.
//
// [mark3labs/mcp-go]: https://pkg.go.dev/github.com/mark3labs/mcp-go
func (tb *TransportBuilder) BuildInMemoryTransport(ctx context.Context) (any, error) {
	// Build the server using ServerBuilder
	srv, err := tb.serverBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build server: %w", err)
	}

	// Create transport and connect server
	transport := NewInMemoryTransport(ctx)
	if err := transport.ConnectServer(ctx, srv); err != nil {
		return nil, fmt.Errorf("failed to connect server to transport: %w", err)
	}

	// Return the transport for ADK integration
	return transport, nil
}
