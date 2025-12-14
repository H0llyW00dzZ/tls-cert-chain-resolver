// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
	"github.com/mark3labs/mcp-go/mcp"
)

// pipeReader implements io.Reader for StdioServer input.
// It reads from sendCh (ADK requests) and internalRespCh (local responses).
//
// pipeReader acts as the input stream for the StdioServer, bridging between
// the InMemoryTransport's channels and the server's I/O interface. It uses
// buffer pooling for efficient memory management during message processing.
//
// Fields:
//   - t: Reference to the InMemoryTransport for channel access
//   - activeBuf: Currently active buffer from the pool (gc.Buffer)
//   - offset: Current read offset within the active buffer
//
// The reader serves data from buffers obtained from gc.Default pool,
// automatically returning buffers to the pool when fully consumed.
// It handles context cancellation by returning io.EOF when the transport's
// context is done.
type pipeReader struct {
	t         *InMemoryTransport
	activeBuf gc.Buffer
	offset    int
}

// Read implements io.Reader for pipeReader.
//
// Read serves data from the active buffer if available, or waits for new messages
// from the transport's channels. It uses buffer pooling for efficient memory usage
// and ensures proper cleanup of buffers when fully consumed.
//
// The method follows this priority:
//  1. Serve remaining data from active buffer
//  2. Wait for new message from sendCh or internalRespCh
//  3. Prepare new buffer with message data
//  4. Copy data to provided slice
//
// Parameters:
//   - p: Destination byte slice to copy data into
//
// Returns:
//   - n: Number of bytes read
//   - err: io.EOF if context is cancelled, nil otherwise
//
// Thread Safety: Safe for concurrent use as it only reads from channels
// and uses per-reader buffer state.
func (r *pipeReader) Read(p []byte) (n int, err error) {
	// 1. Serve from active buffer if available
	if r.activeBuf != nil {
		data := r.activeBuf.Bytes()[r.offset:]
		n = copy(p, data)
		r.offset += n

		// If buffer is drained, return it to pool
		if r.offset >= r.activeBuf.Len() {
			r.activeBuf.Reset()
			gc.Default.Put(r.activeBuf)
			r.activeBuf = nil
			r.offset = 0
		}
		return n, nil
	}

	// 2. Wait for new message
	var msg []byte
	var ok bool

	select {
	case msg, ok = <-r.t.sendCh:
	case msg, ok = <-r.t.internalRespCh:
	case <-r.t.ctx.Done():
		return 0, io.EOF
	}

	if !ok {
		return 0, io.EOF
	}

	// 3. Prepare new buffer
	r.activeBuf = gc.Default.Get()
	r.activeBuf.Write(msg)

	// Ensure newline for StdioServer
	if r.activeBuf.Len() == 0 || r.activeBuf.Bytes()[r.activeBuf.Len()-1] != '\n' {
		r.activeBuf.WriteByte('\n')
	}

	// 4. Copy to p
	data := r.activeBuf.Bytes()
	n = copy(p, data)
	r.offset = n

	// If fully consumed, clean up immediately
	if r.offset >= r.activeBuf.Len() {
		r.activeBuf.Reset()
		gc.Default.Put(r.activeBuf)
		r.activeBuf = nil
		r.offset = 0
	}

	return n, nil
}

// pipeWriter implements io.Writer for StdioServer output.
// It writes to recvCh (ADK responses) but intercepts Sampling requests.
//
// pipeWriter acts as the output stream for the StdioServer, bridging between
// the InMemoryTransport's channels and the server's I/O interface. It intercepts
// sampling requests for local processing while forwarding other messages.
//
// Fields:
//   - t: Reference to the InMemoryTransport for channel access
//   - activeBuf: Active buffer for accumulating partial writes (gc.Buffer)
//
// The writer accumulates data until complete lines (terminated by \n) are received,
// then processes each line individually. Sampling requests are handled locally
// by spawning goroutines, while all other messages are forwarded to recvCh.
type pipeWriter struct {
	t         *InMemoryTransport
	activeBuf gc.Buffer
}

// Write implements io.Writer for pipeWriter.
//
// Write accumulates data in a buffer until complete lines are received,
// then processes each line individually. It handles partial writes by
// maintaining state across multiple Write calls.
//
// The method:
//  1. Accumulates data in activeBuf
//  2. Extracts complete lines (terminated by \n)
//  3. Processes each line via processLine()
//  4. Updates buffer with remaining partial data
//
// Parameters:
//   - p: Source byte slice containing data to write
//
// Returns:
//   - n: Always len(p) (never partial writes)
//   - err: Always nil (Write never fails)
//
// Thread Safety: Safe for concurrent use as it only writes to channels
// and uses per-writer buffer state.
func (w *pipeWriter) Write(p []byte) (n int, err error) {
	if w.activeBuf == nil {
		w.activeBuf = gc.Default.Get()
	}
	w.activeBuf.Write(p)

	data := w.activeBuf.Bytes()
	consumed := 0

	for {
		idx := bytes.IndexByte(data, '\n')
		if idx == -1 {
			break
		}

		// Extract line including newline
		lineLen := idx + 1
		line := data[:lineLen]

		// Make a copy to safely use outside buffer (sendToRecv expects independent slice)
		msg := make([]byte, len(line))
		copy(msg, line)

		// Check for interception (Sampling)
		w.processLine(msg)

		// Advance window
		data = data[lineLen:]
		consumed += lineLen
	}

	// Update buffer with remaining data
	if len(data) == 0 {
		// Fully consumed
		w.activeBuf.Reset()
		gc.Default.Put(w.activeBuf)
		w.activeBuf = nil
	} else {
		// Shift remaining to front
		// Note: Set() uses append(dst[:0], src...), which handles overlapping slices correctly
		w.activeBuf.Set(data)
	}

	return len(p), nil
}

// processLine processes a complete line of [JSON-RPC] data.
//
// processLine determines how to handle each complete line received from the StdioServer.
// It performs interception for sampling requests, forwarding them to local processing,
// while sending all other messages through the transport's receive channel.
//
// The method:
//  1. Performs quick check for "method" field (optimization)
//  2. Parses JSON to check for sampling requests
//  3. Intercepts sampling requests and handles them locally
//  4. Forwards all other messages to recvCh
//
// Parameters:
//   - line: Complete line of data including newline terminator
//
// For sampling requests (method == "sampling/createMessage" with id):
// - Spawns goroutine to handle locally via handleSampling()
// - Uses shutdownWg to track active sampling operations
//
// For all other messages:
// - Forwards to transport's recvCh for normal processing
//
// Thread Safety: Safe for concurrent use, spawns goroutines for sampling
// but uses transport's shutdownWg for coordination.
//
// [JSON-RPC]: https://grokipedia.com/page/JSON-RPC
func (w *pipeWriter) processLine(line []byte) {
	// Try to parse as partial JSON to check for method
	// We only care about Requests (have method and id)
	// Optimization: Quick check for "method" string
	if !bytes.Contains(line, []byte(`"method"`)) {
		// Not a request we care about (could be response or notification)
		w.t.sendToRecv(line)
		return
	}

	var req map[string]any
	if err := json.Unmarshal(line, &req); err != nil {
		// Parse error, just forward
		w.t.sendToRecv(line)
		return
	}

	// Check if it's a request (has id) and method is sampling
	if method, ok := req["method"].(string); ok && method == string(mcp.MethodSamplingCreateMessage) {
		if _, hasID := req["id"]; hasID {
			// It's a sampling request! Handle it locally.
			w.t.shutdownWg.Go(func() {
				w.t.handleSampling(req)
			})
			return
		}
	}

	// Forward everything else
	w.t.sendToRecv(line)
}
