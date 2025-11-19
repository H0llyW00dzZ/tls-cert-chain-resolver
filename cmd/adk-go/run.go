// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by terms
// of License Agreement, which you can find at LICENSE files.

//go:build adk

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"time"

	mcpserver "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server"
	mcptransport "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/adk/tool/mcptoolset"
)

// This example demonstrates how to use MCP tools with ADK for X.509 certificate operations.
// It creates an in-memory MCP server with certificate tools and integrates it with ADK.
//
// Prerequisites:
// - Set GOOGLE_API_KEY environment variable
// - ADK packages must be available (google.golang.org/adk/*)

func localMCPTransport(ctx context.Context) mcptransport.Transport {
	// Use our improved transport builder to create MCP server and transport
	builder := mcpserver.NewTransportBuilder().
		WithVersion("1.0.0").
		WithDefaultTools()

	// Build in-memory transport that includes server
	transportAny, err := builder.BuildInMemoryTransport(ctx)
	if err != nil {
		log.Fatalf("Failed to build MCP transport: %v", err)
	}

	// The transport now implements mcptransport.Transport interface
	transport, ok := transportAny.(mcptransport.Transport)
	if !ok {
		log.Fatalf("Built transport does not implement mcptransport.Transport")
	}

	return transport
}

func main() {
	// Create context that cancels on interrupt signal (Ctrl+C)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Check for required environment variables
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		log.Fatal("GOOGLE_API_KEY environment variable must be set")
	}

	var transport mcptransport.Transport
	transport = localMCPTransport(ctx)

	// Create MCP tool set
	_, err := mcptoolset.New(mcptoolset.Config{
		Transport: transport,
	})
	if err != nil {
		log.Fatalf("Failed to create MCP tool set: %v", err)
	}

	// Test the transport by attempting to connect
	conn, err := transport.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect transport: %v", err)
	}
	defer conn.Close()

	log.Printf("Certificate MCP transport created and connected successfully")
	log.Printf("MCP tool set initialized with transport")

	// Simple execution loop (with timeout for testing)
	select {
	case <-ctx.Done():
		log.Println("Shutting down certificate agent...")
		return
	case <-time.After(1 * time.Second):
		log.Println("Test completed successfully - transport working")
		return
	}
}
