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

// pipeReader implements io.Reader for StdioServer input
// It reads from sendCh (ADK requests) and internalRespCh (local responses)
type pipeReader struct {
	t         *InMemoryTransport
	activeBuf gc.Buffer
	offset    int
}

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

// pipeWriter implements io.Writer for StdioServer output
// It writes to recvCh (ADK responses) but intercepts Sampling requests
type pipeWriter struct {
	t         *InMemoryTransport
	activeBuf gc.Buffer
}

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
