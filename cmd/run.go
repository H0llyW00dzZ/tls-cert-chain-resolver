// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/cli"
)

var version = "0.2.5" // default version if not set

func main() {
	// Disable the default timestamp in log output
	log.SetFlags(0)

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Channel to signal completion
	done := make(chan error, 1)

	// Run the CLI in a separate goroutine
	go func() {
		// Note: Avoid formatting or logging the error here to prevent duplicate messages,
		// as it is already captured.
		if err := cli.Execute(ctx, version); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	select {
	case <-sigs:
		log.Println("\nReceived termination signal. Exiting...")
		cancel()
	case err := <-done:
		if err == nil && cli.OperationPerformed {
			log.Println("Certificate chain resolution completed successfully.")
		}
	}

	// Log stop only if an operation was performed successfully
	if cli.OperationPerformedSuccessfully {
		log.Println("TLS certificate chain resolver stopped.")
	}
}
