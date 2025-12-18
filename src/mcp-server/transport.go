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

// jsonRPCError represents a [JSON-RPC] 2.0 error object.
//
// This struct is used internally for constructing error responses
// that comply with the JSON-RPC 2.0 specification for error handling.
//
// Fields:
//   - Code: Error code following JSON-RPC conventions (e.g., -32600 for invalid request)
//   - Message: Human-readable error description
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
type jsonRPCError struct {
	// Code: JSON-RPC error code (standard codes like -32600, -32601, etc.)
	Code int `json:"code"`
	// Message: Human-readable error description
	Message string `json:"message"`
}

// jsonRPCResponse represents a [JSON-RPC] 2.0 response object.
//
// This struct encapsulates the complete response format for JSON-RPC 2.0,
// supporting both successful results and error responses. It ensures
// proper protocol compliance for MCP communication.
//
// Fields:
//   - JSONRPC: Protocol version string (always "2.0")
//   - ID: Request identifier for response correlation
//   - Result: Response data for successful requests (omitted for errors)
//   - Error: Error details for failed requests (omitted for success)
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
type jsonRPCResponse struct {
	// JSONRPC: JSON-RPC protocol version (always "2.0")
	JSONRPC string `json:"jsonrpc"`
	// ID: Request identifier matching the originating request
	ID any `json:"id"`
	// Result: Successful response data (omitted when Error is present)
	Result any `json:"result,omitempty"`
	// Error: Error details for failed requests (omitted when Result is present)
	Error *jsonRPCError `json:"error,omitempty"`
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
	// started: Indicates if the transport has been connected to a server
	started bool
	// mu: Mutex for thread-safe access to transport state
	mu sync.Mutex
	// recvCh: Channel for receiving messages from the server (ReadMessage)
	recvCh chan []byte
	// sendCh: Channel for sending messages to the server (WriteMessage)
	sendCh chan []byte
	// internalRespCh: Channel for internal responses (sampling, notifications)
	internalRespCh chan []byte
	// ctx: Context for cancellation and lifecycle management
	ctx context.Context
	// cancel: Function to cancel the transport context
	cancel context.CancelFunc
	// samplingHandler: Handler for AI model sampling requests
	samplingHandler client.SamplingHandler
	// shutdownWg: WaitGroup for graceful shutdown of active goroutines
	shutdownWg sync.WaitGroup
	// processWg: WaitGroup for the message processing loop
	processWg sync.WaitGroup
}

// SetSamplingHandler sets the sampling handler for AI model interactions.
//
// The sampling handler is responsible for processing AI model requests
// (such as CreateMessage calls) that originate from the MCP server.
// This enables bidirectional communication for certificate analysis
// and other AI-powered features.
//
// This method is thread-safe and can be called concurrently with
// other transport operations without requiring explicit synchronization.
//
// Parameters:
//   - handler: The sampling handler implementation for AI requests
func (t *InMemoryTransport) SetSamplingHandler(handler client.SamplingHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.samplingHandler = handler
}

// SendJSONRPCNotification sends a JSON-RPC notification asynchronously.
//
// This method sends server-initiated notifications such as streaming progress
// updates, sampling tokens, or other events that don't require a response.
// The notification is sent asynchronously and will not block if the receive
// channel is full (the notification will be dropped in that case).
//
// Common use cases:
// - Streaming AI token responses during certificate analysis
// - Progress updates for long-running certificate operations
// - Status notifications for certificate validation results
//
// Parameters:
//   - method: The JSON-RPC method name for the notification
//   - params: The notification parameters (can be any serializable type)
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

// NewInMemoryTransport creates a new in-memory transport for MCP communication.
//
// This constructor creates an InMemoryTransport that implements the official
// MCP SDK's Transport interface. It's designed for seamless integration with
// ADK's mcptoolset.New expectations and provides channel-based message passing
// with full context cancellation support for graceful shutdown.
//
// The transport uses buffered channels to prevent blocking and supports:
// - Thread-safe message passing between client and server
// - Context-aware cancellation for clean shutdown
// - Sampling handler integration for AI-powered features
//
// Parameters:
//   - ctx: Parent context for lifecycle management and cancellation
//
// Returns:
//   - *InMemoryTransport: Initialized transport ready for server connection
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

// Close implements graceful shutdown of the in-memory transport.
//
// It performs a coordinated shutdown by:
//  1. Canceling the transport context to signal all operations to stop
//  2. Waiting for the message processing loop to terminate (processWg)
//  3. Waiting for all active goroutines to complete (shutdownWg)
//
// Channels are intentionally not closed to prevent panics in concurrent
// operations. It ensures all goroutines exit cleanly without race conditions.
//
// Returns:
//   - error: Always nil (shutdown is synchronous)
//
// Thread Safety: Safe to call concurrently, but typically called once during shutdown.
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

// sendInternalResponse sends an internal response through the transport's response channel.
// It marshals the response to JSON and sends it via the internal response channel.
// If the context is cancelled during sending, the response is dropped.
//
// Parameters:
//   - resp: Response object to send (will be JSON marshaled)
//
// Thread Safety: Safe for concurrent use.
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

// sendInternalErrorResponse sends an internal JSON-RPC error response.
// It constructs a proper JSON-RPC error response and sends it via the internal response channel.
//
// Parameters:
//   - id: Request ID for the error response
//   - code: JSON-RPC error code
//   - msg: Error message
//
// Thread Safety: Safe for concurrent use.
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

// sendErrorResponse sends a JSON-RPC error response through the transport.
// It constructs a proper JSON-RPC error response and sends it via the main response channel.
//
// Parameters:
//   - id: Request ID for the error response
//   - code: JSON-RPC error code
//   - msg: Error message
//
// Thread Safety: Safe for concurrent use.
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
//
// This struct implements the official MCP SDK's Connection interface,
// providing JSON-RPC message encoding/decoding and session management
// for seamless ADK integration.
//
// Fields:
//   - transport: The underlying InMemoryTransport instance
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
type ADKTransportConnection struct {
	// transport: The underlying InMemoryTransport for message passing
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
//
// This builder pattern implementation provides transport creation utilities
// for various integration layers (ADK, CLI, etc.). It wraps a ServerBuilder
// to create appropriate transport mechanisms for different use cases.
//
// For in-memory scenarios, it builds the complete MCP server and returns
// a transport that can communicate with it directly.
//
// Fields:
//   - serverBuilder: The underlying ServerBuilder for MCP server construction
//
// Example usage:
//
//	builder := NewTransportBuilder().
//		WithConfig(config).
//		WithVersion("1.0.0").
//		WithDefaultTools()
//	transport, err := builder.BuildInMemoryTransport(ctx)
type TransportBuilder struct {
	// serverBuilder: The underlying ServerBuilder for MCP server construction
	serverBuilder *ServerBuilder
}

// NewTransportBuilder creates a new transport builder for MCP server construction.
//
// It initializes a TransportBuilder with a new ServerBuilder instance, providing
// a fluent interface for configuring and building MCP transports. The builder
// pattern allows for flexible configuration of server settings, tools, and
// transport options before creating the final transport.
//
// The builder supports fluent configuration methods like WithConfig(),
// WithVersion(), WithDefaultTools(), and finally BuildInMemoryTransport()
// to create an in-memory transport for ADK integration.
//
// Returns:
//   - *TransportBuilder: New builder instance ready for configuration
//
// Example usage:
//
//	builder := NewTransportBuilder().
//		WithConfig(config).
//		WithVersion("1.0.0").
//		WithDefaultTools()
//	transport, err := builder.BuildInMemoryTransport(ctx)
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
