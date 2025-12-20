//go:build !windows

package mcpserver

import (
	"os"
	"syscall"
	"testing"
	"time"
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
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("Failed to send SIGINT: %v", err)
	}

	// Wait for graceful shutdown with timeout
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Expected Run() to return nil on graceful shutdown, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not shut down gracefully within 5 seconds")
	}
}
