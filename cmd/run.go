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

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/cli"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
)

var version = "0.2.9" // default version if not set

func main() {
	// Create CLI logger
	log := logger.NewCLILogger()

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Channel to signal completion with buffer size 1
	done := make(chan error, 1)

	// Run the CLI in a separate goroutine
	go func() {
		err := cli.Execute(ctx, version, log)
		// Use a select to prevent blocking if context is cancelled
		select {
		case done <- err:
			// Successfully sent the error
		case <-ctx.Done():
			// Context was cancelled, don't try to send on done channel
			log.Println("Operation cancelled, cleaning up...")
		}
	}()

	// Wait for either a signal or completion
	select {
	case <-sigs:
		log.Println("\nReceived termination signal. Exiting...")
		cancel()
		// We don't need to wait for the goroutine to finish
		// The buffered channel and select in the goroutine prevent blocking
	case err := <-done:
		// Only log successful completion, not errors (Cobra already logs them)
		if err == nil && cli.OperationPerformed {
			log.Println("Certificate chain resolution completed successfully.")
		}
	}

	// Log stop only if an operation was performed successfully
	if cli.OperationPerformedSuccessfully {
		log.Println("TLS certificate chain resolver stopped.")
	}
}
