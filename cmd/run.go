// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/cli"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
	verpkg "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
)

var version string // set by ldflags or defaults to imported version

func init() {
	if version == "" {
		version = verpkg.Version
	}
}

func main() {
	// Create CLI logger
	log := logger.NewCLILogger()

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling using signal.NotifyContext for cleaner cancellation
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Channel to signal completion
	done := make(chan error, 1)

	// Run the CLI in a separate goroutine
	go func() {
		done <- cli.Execute(ctx, version, log)
	}()

	// Wait for either completion or context cancellation
	select {
	case err := <-done:
		if err != nil {
			log.Printf("CLI execution failed: %v", err)
			os.Exit(1)
		}
		// CLI completed successfully
		if cli.OperationPerformed {
			log.Println("Certificate chain resolution completed successfully.")
		}
	case <-ctx.Done():
		log.Println("Operation cancelled by signal. Exiting...")
		// Give the CLI a moment to clean up
		select {
		case <-done:
			// CLI finished cleaning up
		case <-time.After(100 * time.Millisecond):
			// Timeout waiting for cleanup
		}
		os.Exit(130) // Standard exit code for SIGINT
	}

	// Log successful completion
	if cli.OperationPerformedSuccessfully {
		log.Println("TLS certificate chain resolver stopped.")
	}
}
