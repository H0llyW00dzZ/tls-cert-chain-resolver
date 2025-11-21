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

	jsonrpcInternal "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/jsonrpc"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcptransport "github.com/modelcontextprotocol/go-sdk/mcp"
)

// jsonRPCError represents a JSON-RPC 2.0 error object
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// jsonRPCResponse represents a JSON-RPC 2.0 response object
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

// InMemoryTransport implements ADK SDK mcp.Transport interface
// It bridges between [Official MCP SDK] transport expectations and [mark3labs/mcp-go] client
//
// [mark3labs/mcp-go]: https://pkg.go.dev/github.com/mark3labs/mcp-go
// [Official MCP SDK]: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk
type InMemoryTransport struct {
	client          *client.Client // mark3labs in-process client
	started         bool
	mu              sync.Mutex
	recvCh          chan []byte // channel for receiving messages (ReadMessage)
	sendCh          chan []byte // channel for sending messages (WriteMessage)
	ctx             context.Context
	cancel          context.CancelFunc
	samplingHandler client.SamplingHandler
	sem             chan struct{}  // Semaphore to limit concurrency
	shutdownWg      sync.WaitGroup // WaitGroup for graceful shutdown
	processWg       sync.WaitGroup // WaitGroup for message processing loop
}

// SetSamplingHandler sets the sampling handler for the transport
func (t *InMemoryTransport) SetSamplingHandler(handler client.SamplingHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.samplingHandler = handler
}

// SendJSONRPCNotification sends a JSON-RPC notification to the receive channel
// This is useful for streaming progress or other server-initiated events
func (t *InMemoryTransport) SendJSONRPCNotification(method string, params any) {
	notification := map[string]any{
		"jsonrpc": mcp.JSONRPC_VERSION,
		"method":  method,
		"params":  params,
	}
	t.sendResponse(notification)
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
		sem:    make(chan struct{}, 100), // Limit to 100 concurrent requests
	}
}

// ReadMessage implements [mcp.Transport.ReadMessage]
// For ADK compatibility, this should return JSON-RPC messages
// Uses channel-based message passing for in-memory communication
// This method blocks until a message is available or the context is cancelled
func (t *InMemoryTransport) ReadMessage() ([]byte, error) {
	select {
	case msg := <-t.recvCh:
		return msg, nil
	case <-t.ctx.Done():
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

	// Wait for message processor to stop (no new tasks added)
	t.processWg.Wait()

	// Wait for active goroutines to finish
	t.shutdownWg.Wait()

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

// ConnectServer connects a mark3labs MCP server to this transport using an in-process client.
//
// This enables direct in-memory communication without process overhead, making it ideal
// for embedding the server in custom integration scenarios (like Google ADK).
// It also configures notification forwarding to support bidirectional features such as AI sampling.
func (t *InMemoryTransport) ConnectServer(ctx context.Context, srv *server.MCPServer) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.started {
		return fmt.Errorf("transport already connected")
	}

	// Create mark3labs in-process client
	var err error
	if t.samplingHandler != nil {
		t.client, err = client.NewInProcessClientWithSamplingHandler(srv, t.samplingHandler)
	} else {
		t.client, err = client.NewInProcessClient(srv)
	}
	if err != nil {
		return fmt.Errorf("failed to create in-process client: %w", err)
	}

	// Register notification handler to forward server notifications to the bridge
	// This enables streaming support by forwarding server-initiated notifications
	t.client.OnNotification(func(n mcp.JSONRPCNotification) {
		// Create a generic JSON-RPC notification structure
		notification := map[string]any{
			"jsonrpc": mcp.JSONRPC_VERSION,
			"method":  n.Method,
			"params":  n.Params,
		}
		// Send to the ADK receive channel using sendResponse which handles marshaling
		t.sendResponse(notification)
	})

	// Start the client
	if err := t.client.Start(t.ctx); err != nil {
		return fmt.Errorf("failed to start client: %w", err)
	}

	// Start message processing goroutine
	t.processWg.Add(1)
	go t.processMessages()

	t.started = true
	return nil
}

// processMessages handles JSON-RPC message processing between ADK and the MCP client
func (t *InMemoryTransport) processMessages() {
	defer t.processWg.Done()

	for {

		select {
		case <-t.ctx.Done():
			return
		case data := <-t.sendCh:
			// Acquire semaphore token (non-blocking check for context)
			select {
			case t.sem <- struct{}{}:
				t.shutdownWg.Add(1)
				// Handle message in a goroutine to avoid blocking the transport loop
				// This ensures that long-running tool calls don't prevent other messages
				// (like notifications or concurrent requests) from being processed.
				go func(data []byte) {
					defer func() {
						<-t.sem // Release token
						t.shutdownWg.Done()
					}()

					var req map[string]any
					if err := json.Unmarshal(data, &req); err != nil {
						// Send parse error response
						resp := jsonRPCResponse{
							JSONRPC: mcp.JSONRPC_VERSION,
							Error: &jsonRPCError{
								Code:    -32700,
								Message: "Parse error",
							},
							ID: nil,
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
								resp := jsonRPCResponse{
									JSONRPC: mcp.JSONRPC_VERSION,
									ID:      idInt,
									Error: &jsonRPCError{
										Code:    -32600,
										Message: err.Error(),
									},
								}
								t.sendResponse(resp)
							}
							return
						}

						// Handle notifications that don't require a response or action in this bridge
						if method == "notifications/initialized" {
							return
						}

						var result any
						var err error
						switch method {
						case string(mcp.MethodInitialize):
							if initParams, e := getParams(normalizedReq, method); e != nil {
								err = e
							} else {
								var protocolVersion string
								if protocolVersion, err = getStringParam(initParams, method, "protocolVersion"); err == nil {
									// Preserve capabilities by marshaling/unmarshaling
									var capabilities mcp.ClientCapabilities
									if caps, ok := initParams["capabilities"]; ok {
										// Use helper for safe conversion
										_ = jsonrpcInternal.UnmarshalFromMap(caps, &capabilities)
									}

									initReq := mcp.InitializeRequest{
										Params: mcp.InitializeParams{
											ProtocolVersion: protocolVersion,
											Capabilities:    capabilities,
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
							}
						case string(mcp.MethodPing):
							if t.client != nil {
								err = t.client.Ping(t.ctx)
								if err == nil {
									result = map[string]any{}
								}
							}
						case string(mcp.MethodToolsList):
							if t.client != nil {
								listReq := mcp.ListToolsRequest{}
								resp, e := t.client.ListTools(t.ctx, listReq)
								if e != nil {
									err = e
								} else {
									result = resp
								}
							}
						case string(mcp.MethodToolsCall):
							if t.client != nil {
								if callParams, e := getParams(normalizedReq, string(mcp.MethodToolsCall)); e != nil {
									err = e
								} else {
									var name string
									var args map[string]any
									if name, err = getStringParam(callParams, method, "name"); err == nil {
										if args, err = getMapParam(callParams, method, "arguments"); err == nil {
											callReq := mcp.CallToolRequest{
												Params: mcp.CallToolParams{
													Name:      name,
													Arguments: args,
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
								}
							}
						case string(mcp.MethodResourcesList):
							if t.client != nil {
								listReq := mcp.ListResourcesRequest{}
								if params, ok := normalizedReq["params"].(map[string]any); ok {
									if cursor, err := getOptionalStringParam(params, method, "cursor"); err == nil {
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
						case string(mcp.MethodResourcesRead):
							if t.client != nil {
								if readParams, e := getParams(normalizedReq, string(mcp.MethodResourcesRead)); e != nil {
									err = e
								} else {
									var uri string
									if uri, err = getStringParam(readParams, method, "uri"); err == nil {
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
						case string(mcp.MethodPromptsList):
							if t.client != nil {
								listReq := mcp.ListPromptsRequest{}
								if params, ok := normalizedReq["params"].(map[string]any); ok {
									if cursor, err := getOptionalStringParam(params, method, "cursor"); err == nil {
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
						case string(mcp.MethodPromptsGet):
							if t.client != nil {
								if params, e := getParams(normalizedReq, string(mcp.MethodPromptsGet)); e != nil {
									err = e
								} else {
									var name string
									if name, err = getStringParam(params, method, "name"); err == nil {
										var arguments map[string]string
										if args, ok := params["arguments"].(map[string]any); ok {
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
							return
						}

						resp := jsonRPCResponse{
							JSONRPC: mcp.JSONRPC_VERSION,
							ID:      idInt,
						}
						if err != nil {
							code := -32603
							if strings.Contains(err.Error(), "invalid params") || strings.Contains(err.Error(), "missing params") {
								code = -32602
							}
							resp.Error = &jsonRPCError{
								Code:    code,
								Message: err.Error(),
							}
						} else {
							resp.Result = result
						}
						t.sendResponse(resp)
					}
				}(data)
			case <-t.ctx.Done():
				return
			}
		}
	}
}

// sendResponse sends a JSON-RPC response to the receive channel
func (t *InMemoryTransport) sendResponse(resp any) {
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
