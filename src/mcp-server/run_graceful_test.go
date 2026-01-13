// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

//go:build !windows

package mcpserver

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_GracefulShutdown(t *testing.T) {
	// This test is only compiled on non-Windows systems due to syscall usage

	// Use default config
	os.Unsetenv("MCP_X509_CONFIG_FILE")

	// Run the server in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- Run("1.0.0-test", "")
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Send SIGINT to trigger graceful shutdown
	err := syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	require.NoError(t, err, "Failed to send SIGINT")

	// Wait for graceful shutdown with timeout
	select {
	case err := <-done:
		assert.NoError(t, err, "Expected Run() to return nil on graceful shutdown")
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not shut down gracefully within 5 seconds")
	}
}
