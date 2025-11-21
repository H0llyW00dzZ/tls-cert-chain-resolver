// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/mark3labs/mcp-go/mcp"
)

// pipeReader implements io.Reader for StdioServer input
// It reads from sendCh (ADK requests) and internalRespCh (local responses)
type pipeReader struct {
	t   *InMemoryTransport
	buf []byte
}

func (r *pipeReader) Read(p []byte) (n int, err error) {
	if len(r.buf) > 0 {
		n = copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

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

	// Ensure newline for StdioServer
	if len(msg) == 0 || msg[len(msg)-1] != '\n' {
		msg = append(msg, '\n')
	}

	n = copy(p, msg)
	if n < len(msg) {
		r.buf = msg[n:]
	}
	return n, nil
}

// pipeWriter implements io.Writer for StdioServer output
// It writes to recvCh (ADK responses) but intercepts Sampling requests
type pipeWriter struct {
	t   *InMemoryTransport
	buf []byte
}

func (w *pipeWriter) Write(p []byte) (n int, err error) {
	w.buf = append(w.buf, p...)

	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx == -1 {
			break
		}

		// Extract line including newline (to preserve formatting if needed,
		// though we might strip it for ADK if strictly needed, but ADK ReadMessage returns []byte)
		line := w.buf[:idx+1]

		// Make a copy to safely use outside buffer
		msg := make([]byte, len(line))
		copy(msg, line)

		// Check for interception (Sampling)
		w.processLine(msg)

		w.buf = w.buf[idx+1:]
	}

	return len(p), nil
}

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
			w.t.shutdownWg.Add(1)
			go func() {
				defer w.t.shutdownWg.Done()
				w.t.handleSampling(req)
			}()
			return
		}
	}

	// Forward everything else
	w.t.sendToRecv(line)
}
