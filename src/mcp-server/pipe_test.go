// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// The implementation leverages Go's native channel primitives to facilitate communication between concurrent processes

package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSamplingResponseDestination(t *testing.T) {
	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	// Mock sampling handler that returns immediate result
	transport.SetSamplingHandler(&mockSamplingHandler{})

	writer := &pipeWriter{t: transport}

	// 1. Write a sampling request
	samplingRequest := `{"jsonrpc":"2.0","method":"sampling/createMessage","id":999,"params":{"messages":[{"role":"user","content":{"type":"text","text":"test"}}],"maxTokens":100}}` + "\n"
	_, err := writer.Write([]byte(samplingRequest))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// 2. Check where the response goes
	// It SHOULD go to internalRespCh (so pipeReader/StdioServer gets it)
	// It SHOULD NOT go to recvCh (which is for ADK client to read)

	select {
	case msg := <-transport.recvCh:
		// If we receive it here, it's WRONG.
		// We need to check if it's the sampling response.
		var resp map[string]any
		if err := json.Unmarshal(msg, &resp); err == nil {
			if id, ok := resp["id"].(float64); ok && id == 999 {
				t.Fatalf("FAIL: Sampling response sent to recvCh (ADK client), expected internalRespCh (Server)")
			}
		}
	case <-time.After(100 * time.Millisecond):
		// No response on recvCh, good so far (or slow)
	}

	// Now check internalRespCh (we can't access it directly easily as it is private field in another package...
	// wait, this test is in package mcpserver, so we CAN access private fields)

	select {
	case msg := <-transport.internalRespCh:
		var resp map[string]any
		if err := json.Unmarshal(msg, &resp); err == nil {
			if id, ok := resp["id"].(float64); ok && id == 999 {
				t.Logf("SUCCESS: Sampling response received on internalRespCh")
				return
			}
		}
		t.Logf("Received unrelated message on internalRespCh: %s", string(msg))
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("FAIL: No response received on internalRespCh")
	}
}

func TestPipeWriter_ErrorPaths(t *testing.T) {
	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)
	writer := &pipeWriter{t: transport}

	// 1. Malformed JSON with "method"
	// Should go to sendToRecv (recvCh)
	malformed := `{"method": "foo", invalid json` + "\n"
	_, err := writer.Write([]byte(malformed))
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	select {
	case msg := <-transport.recvCh:
		// Trim newline for comparison if needed, but pipeWriter might pass it as is
		if !strings.Contains(string(msg), "invalid json") {
			t.Errorf("Expected forwarded message to contain original content, got: %s", string(msg))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected message on recvCh for malformed JSON")
	}

	// 2. Sampling request without ID (should be forwarded to recvCh)
	noID := `{"jsonrpc":"2.0","method":"sampling/createMessage","params":{}}` + "\n"
	_, err = writer.Write([]byte(noID))
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	select {
	case msg := <-transport.recvCh:
		var req map[string]any
		if err := json.Unmarshal(msg, &req); err != nil {
			t.Errorf("Failed to unmarshal forwarded message: %v", err)
		}
		if req["method"] != "sampling/createMessage" {
			t.Errorf("Expected forwarded message to be the sampling request")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected message on recvCh for sampling request without ID")
	}
}
