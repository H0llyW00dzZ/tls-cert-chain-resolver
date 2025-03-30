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
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/cli"
)

var version = "0.1.1" // default version if not set

func main() {
	// Disable the default timestamp in log output
	log.SetFlags(0)

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Log start with version
	log.Printf("Starting TLS certificate chain resolver (v%s)...", version)
	log.Println("Press CTRL+C to exit.")

	// Run the CLI in a separate goroutine
	go func() {
		cli.Execute(ctx, version)
	}()

	// Wait for a termination signal
	<-sigs

	// Log exit instruction
	log.Println("\nReceived termination signal. Exiting...")

	// Cancel the context to stop the CLI
	cancel()

	// Give some time for cleanup
	time.Sleep(3 * time.Second)

	// Log stop
	log.Println("TLS certificate chain resolver stopped.")
}
