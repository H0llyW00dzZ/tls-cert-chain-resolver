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
	select {
	case t.sendCh <- data:
		return nil
	default:
		return fmt.Errorf("send channel full")
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
				continue
			}

			id := req["id"]
			method, _ := req["method"].(string)
			params := req["params"]

			var result any
			var err error

			switch method {
			case "initialize":
				initParams, ok := params.(map[string]any)
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
						err = e
					} else {
						result = resp
					}
				}
			case "tools/list":
				listReq := mcp.ListToolsRequest{}
				resp, e := t.client.ListTools(t.ctx, listReq)
				if e != nil {
					err = e
				} else {
					result = resp
				}
			case "tools/call":
				callParams, ok := params.(map[string]any)
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
			default:
				err = fmt.Errorf("method not supported: %s", method)
			}

			resp := map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
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

// sendResponse sends a JSON-RPC response to the receive channel
func (t *InMemoryTransport) sendResponse(resp map[string]any) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	select {
	case t.recvCh <- data:
	default:
		// Channel full, drop response
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

	// Try to decode as a proper JSON-RPC message
	msg, err := jsonrpc.DecodeMessage(data)
	if err != nil {
		// If decoding fails, return nil (this is expected for testing)
		return nil, err
	}

	return msg, nil
}

// Write implements mcptransport.Connection.Write
func (c *ADKTransportConnection) Write(ctx context.Context, msg jsonrpc.Message) error {
	// Convert message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Delegate to underlying transport's WriteMessage
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
func (b *TransportBuilder) WithConfig(config *Config) *TransportBuilder {
	b.serverBuilder.WithConfig(config)
	return b
}

// WithVersion sets the server version
func (b *TransportBuilder) WithVersion(version string) *TransportBuilder {
	b.serverBuilder.WithVersion(version)
	return b
}

// WithDefaultTools adds the default X509 certificate tools
func (b *TransportBuilder) WithDefaultTools() *TransportBuilder {
	b.serverBuilder.WithDefaultTools()
	return b
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
func (b *TransportBuilder) BuildInMemoryTransport(ctx context.Context) (any, error) {
	// Build the server using ServerBuilder
	srv, err := b.serverBuilder.Build()
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
