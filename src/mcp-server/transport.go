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

	jsonrpchelper "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/jsonrpc"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcptransport "github.com/modelcontextprotocol/go-sdk/mcp"
)

// jsonRPCError represents a [JSON-RPC] 2.0 error object
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// jsonRPCResponse represents a [JSON-RPC] 2.0 response object
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

// InMemoryTransport implements the ADK SDK mcp.Transport interface.
// It bridges between [Official MCP SDK] transport expectations and [mark3labs/mcp-go] server.
// This transport enables in-memory communication between MCP clients and servers,
// supporting [JSON-RPC] message passing, sampling requests, and graceful shutdown.
//
// Key features:
//   - Channel-based message passing for thread-safe communication
//   - Sampling handler support for AI model interactions
//   - Context-aware cancellation and graceful shutdown
//
// [mark3labs/mcp-go]: https://pkg.go.dev/github.com/mark3labs/mcp-go
// [Official MCP SDK]: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
type InMemoryTransport struct {
	started         bool
	mu              sync.Mutex
	recvCh          chan []byte // channel for receiving messages (ReadMessage)
	sendCh          chan []byte // channel for sending messages (WriteMessage)
	internalRespCh  chan []byte // channel for internal responses (e.g. sampling)
	ctx             context.Context
	cancel          context.CancelFunc
	samplingHandler client.SamplingHandler
	shutdownWg      sync.WaitGroup // WaitGroup for graceful shutdown
	processWg       sync.WaitGroup // WaitGroup for message processing loop
}

// SetSamplingHandler sets the sampling handler for the transport.
// The sampling handler processes AI model requests (e.g., CreateMessage calls)
// that originate from the MCP server. This is thread-safe and can be called
// concurrently with other transport operations.
func (t *InMemoryTransport) SetSamplingHandler(handler client.SamplingHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.samplingHandler = handler
}

// SendJSONRPCNotification sends a [JSON-RPC] notification to the receive channel.
// This is useful for streaming progress updates, sampling tokens, or other
// server-initiated events. The notification is sent asynchronously and does not
// block if the receive channel is full (it will be dropped).
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func (t *InMemoryTransport) SendJSONRPCNotification(method string, params any) {
	notification := map[string]any{
		"jsonrpc": mcp.JSONRPC_VERSION,
		"method":  method,
		"params":  params,
	}
	t.sendResponse(notification)
}

// NewInMemoryTransport creates a new in-memory transport that implements mcp.Transport.
// This is designed to work with ADK's [mcptoolset.New] expectations.
// The transport uses buffered channels for message passing and supports
// context cancellation for graceful shutdown.
//
// Example usage:
//
//	transport := NewInMemoryTransport(ctx)
//	defer transport.Close()
//
//	// Connect server
//	err := transport.ConnectServer(ctx, server)
//
//	// Use with ADK
//	mcpToolSet, err := mcptoolset.New(mcptoolset.Config{Transport: transport})
func NewInMemoryTransport(ctx context.Context) *InMemoryTransport {
	ctx, cancel := context.WithCancel(ctx)
	return &InMemoryTransport{
		recvCh:         make(chan []byte, 1),
		sendCh:         make(chan []byte, 1),
		internalRespCh: make(chan []byte, 1),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// ReadMessage implements [mcp.Transport.ReadMessage].
// For ADK compatibility, this should return [JSON-RPC] messages.
// Uses channel-based message passing for in-memory communication.
// This method blocks until a message is available or the context is cancelled.
// Returns [io.EOF] when the context is cancelled.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func (t *InMemoryTransport) ReadMessage() ([]byte, error) {
	select {
	case msg := <-t.recvCh:
		return msg, nil
	case <-t.ctx.Done():
		return nil, io.EOF
	}
}

// WriteMessage implements [mcp.Transport.WriteMessage].
// For ADK compatibility, this should accept [JSON-RPC] messages.
// Uses channel-based message passing for in-memory communication.
// Returns an error if the context is cancelled or the channel is full.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
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

// Close implements mcp.Transport.Close().
// Cancels the transport context and waits for all goroutines to finish.
// This ensures graceful shutdown without leaking goroutines.
// Channels are not explicitly closed to avoid panics in concurrent operations.
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

// Connect implements ADK SDK mcp.Transport interface.
// Returns a connection wrapper that adapts this transport for ADK usage.
// The connection handles [JSON-RPC] message encoding/decoding automatically.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func (t *InMemoryTransport) Connect(ctx context.Context) (mcptransport.Connection, error) {
	// For ADK compatibility, return a connection that wraps this transport
	return &ADKTransportConnection{
		transport: t,
	}, nil
}

// ConnectServer connects a mark3labs MCP server to this transport using StdioServer.
// This method enables direct in-memory communication by piping the ADK transport channels
// directly to the StdioServer's input/output streams. This avoids manual [JSON-RPC]
// bridging and leverages the server's native handling.
//
// The server runs in a separate goroutine and can be cancelled via context.
// Options can be passed to configure the StdioServer behavior.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func (t *InMemoryTransport) ConnectServer(ctx context.Context, srv *server.MCPServer, opts ...server.StdioOption) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.started {
		return fmt.Errorf("transport already connected")
	}

	// Create StdioServer
	stdioServer := server.NewStdioServer(srv)
	// Apply options
	for _, opt := range opts {
		opt(stdioServer)
	}

	// Create pipes
	reader := &pipeReader{t: t}
	writer := &pipeWriter{t: t}

	// Start server in goroutine
	t.processWg.Go(func() {
		// Listen blocks until context is cancelled or error occurs
		if err := stdioServer.Listen(t.ctx, reader, writer); err != nil {
			// Context cancellation is expected
			if t.ctx.Err() == nil {
				// This would be an unexpected error
				fmt.Printf("StdioServer.Listen error: %v\n", err)
			}
		}
	})

	t.started = true
	return nil
}

// sendToRecv sends message to recvCh
func (t *InMemoryTransport) sendToRecv(msg []byte) {
	select {
	case t.recvCh <- msg:
	case <-t.ctx.Done():
	}
}

// handleSampling handles the sampling/createMessage request locally
func (t *InMemoryTransport) handleSampling(req map[string]any) {
	id := req["id"]

	if t.samplingHandler == nil {
		// No handler, return error
		t.sendInternalErrorResponse(id, -32601, "Method not found (no sampling handler)")
		return
	}

	// Extract params
	params, err := getParams(req, string(mcp.MethodSamplingCreateMessage))
	if err != nil {
		t.sendInternalErrorResponse(id, -32602, err.Error())
		return
	}

	// Use helper to unmarshal params into struct
	var samplingReq mcp.CreateMessageRequest
	if err := jsonrpchelper.UnmarshalFromMap(params, &samplingReq); err != nil {
		t.sendInternalErrorResponse(id, -32602, "Invalid params structure")
		return
	}

	// Call handler
	result, err := t.samplingHandler.CreateMessage(t.ctx, samplingReq)

	// Construct response
	resp := jsonRPCResponse{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      id,
	}

	if err != nil {
		resp.Error = &jsonRPCError{
			Code:    -32000,
			Message: err.Error(),
		}
	} else {
		resp.Result = result
	}

	t.sendInternalResponse(resp)
}

func (t *InMemoryTransport) sendInternalResponse(resp any) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	select {
	case t.internalRespCh <- data:
	case <-t.ctx.Done():
		// Context cancelled, drop response
	}
}

func (t *InMemoryTransport) sendInternalErrorResponse(id any, code int, msg string) {
	resp := jsonRPCResponse{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: msg,
		},
	}
	t.sendInternalResponse(resp)
}

func (t *InMemoryTransport) sendErrorResponse(id any, code int, msg string) {
	resp := jsonRPCResponse{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: msg,
		},
	}
	t.sendResponse(resp)
}

// sendResponse sends a [JSON-RPC] response to the receive channel
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
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

// ADKTransportConnection wraps InMemoryTransport for ADK SDK compatibility.
// It implements the mcptransport.Connection interface, providing
// [JSON-RPC] message encoding/decoding and session management.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
type ADKTransportConnection struct {
	transport *InMemoryTransport
}

// Read implements [mcptransport.Connection.Read].
// Reads and decodes a [JSON-RPC] message from the underlying transport.
// Uses the official MCP SDK's DecodeMessage for proper message parsing.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
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

// Write implements mcptransport.Connection.Write.
// Encodes and sends a [JSON-RPC] message through the underlying transport.
// Uses the official MCP SDK's EncodeMessage for proper message serialization.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func (c *ADKTransportConnection) Write(ctx context.Context, msg jsonrpc.Message) error {
	// Use MCP SDK's EncodeMessage to properly serialize the message
	data, err := jsonrpc.EncodeMessage(msg)
	if err != nil {
		return err
	}

	return c.transport.WriteMessage(data)
}

// Close implements mcptransport.Connection.Close.
// Delegates to the underlying transport's Close method for cleanup.
func (c *ADKTransportConnection) Close() error {
	// Delegate to underlying transport's Close
	return c.transport.Close()
}

// SessionID implements mcptransport.Connection.SessionID.
// Returns a static session identifier for this in-memory transport.
//
// TODO: Do we need a unique session ID that uses a cryptographic mechanism?
func (c *ADKTransportConnection) SessionID() string {
	return "in-memory-transport"
}

// TransportBuilder helps construct MCP transports for different integration scenarios.
// This builder provides transport creation utilities that can be used by different
// integration layers (ADK, CLI, etc.) to create appropriate transport mechanisms.
// For in-memory scenarios, it returns the built MCP server for direct integration.
//
// Example usage:
//
//	builder := NewTransportBuilder().
//		WithConfig(config).
//		WithVersion("1.0.0").
//		WithDefaultTools()
//	transport, err := builder.BuildInMemoryTransport(ctx)
type TransportBuilder struct {
	serverBuilder *ServerBuilder
}

// NewTransportBuilder creates a new transport builder.
// Returns a builder with default settings that can be configured fluently.
func NewTransportBuilder() *TransportBuilder {
	return &TransportBuilder{
		serverBuilder: NewServerBuilder(),
	}
}

// WithConfig sets the server configuration.
// Applies the provided configuration to the underlying server builder.
func (tb *TransportBuilder) WithConfig(config *Config) *TransportBuilder {
	tb.serverBuilder.WithConfig(config)
	return tb
}

// WithVersion sets the server version.
// Sets the version string that will be reported by the MCP server.
func (tb *TransportBuilder) WithVersion(version string) *TransportBuilder {
	tb.serverBuilder.WithVersion(version)
	return tb
}

// WithDefaultTools adds the default X509 certificate tools.
// Registers all standard certificate chain resolution, validation, and analysis tools.
func (tb *TransportBuilder) WithDefaultTools() *TransportBuilder {
	tb.serverBuilder.WithDefaultTools()
	return tb
}

// BuildInMemoryTransport creates an in-memory MCP transport for ADK integration.
// This follows the ADK pattern where [mcp.NewInMemoryTransports] creates paired
// client and server transports, server connects to server transport, and client
// transport is returned for use with [mcptoolset.New].
//
// For our implementation using [mark3labs/mcp-go], we create the server using
// ServerBuilder, then return a transport that can communicate with it.
//
// Returns an error if server building or transport connection fails.
//
// [mark3labs/mcp-go]: https://pkg.go.dev/github.com/mark3labs/mcp-go
func (tb *TransportBuilder) BuildInMemoryTransport(ctx context.Context) (mcptransport.Transport, error) {
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
