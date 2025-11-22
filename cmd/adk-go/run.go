// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by terms
// of License Agreement, which you can find at LICENSE files.

//go:build adk

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	mcpserver "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server"
	mcptransport "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/mcptoolset"
	"google.golang.org/genai"
)

// This example demonstrates how to use MCP tools with ADK for X.509 certificate operations.
// It creates an in-memory MCP server with certificate tools and integrates it with ADK.
//
// Prerequisites:
// - Set GOOGLE_API_KEY environment variable
// - ADK packages must be available (google.golang.org/adk/*)

func localMCPTransport(ctx context.Context) mcptransport.Transport {
	// Use our improved ADK transport builder to create MCP server and transport with proper configuration
	transport, err := mcpserver.NewADKTransportBuilder().
		WithVersion("1.0.0").
		WithInMemoryTransport().
		BuildTransport(ctx)

	if err != nil {
		log.Fatalf("Failed to build MCP transport: %v", err)
	}

	return transport
}

// Example Output:
//
//	2025/11/22 01:24:19 Verifying MCP transport and tools...
//	2025/11/22 01:24:19 Available Tools (7):
//	2025/11/22 01:24:19 - analyze_certificate_with_ai: Analyze certificate data using AI collaboration (requires bidirectional communication)
//	2025/11/22 01:24:19 - batch_resolve_cert_chain: Resolve X509 certificate chains for multiple certificates in batch
//	2025/11/22 01:24:19 - check_cert_expiry: Check certificate expiry dates and warn about upcoming expirations
//	2025/11/22 01:24:19 - fetch_remote_cert: Fetch X509 certificate chain from a remote hostname/port
//	2025/11/22 01:24:19 - get_resource_usage: Get current resource usage statistics including memory, GC, and CPU information
//	2025/11/22 01:24:19 - resolve_cert_chain: Resolve X509 certificate chain from a certificate file or base64-encoded certificate data
//	2025/11/22 01:24:19 - validate_cert_chain: Validate a X509 certificate chain for correctness and trust
//	2025/11/22 01:24:19 Transport verification successful.
//	2025/11/22 01:24:19 Initializing ADK toolset...
//	2025/11/22 01:24:19 Certificate MCP transport created and connected successfully
//	2025/11/22 01:24:19 MCP tool set initialized with transport
//	2025/11/22 01:24:19 Created session: 79f04443-9dd1-41cd-b9bf-7ae6dbee6ed8
//	2025/11/22 01:24:19 Running agent with prompt: "What tools are available to you for certificate operations?"
//	2025/11/22 01:24:19 --- Agent Response ---
//	I have the following tools available for certificate operations:
//
//	*   **analyze_certificate_with_ai**: Analyze certificate data using AI collaboration.
//	*   **batch_resolve_cert_chain**: Resolve X509 certificate chains for multiple certificates in batch.
//	*   **check_cert_expiry**: Check certificate expiry dates and warn about upcoming expirations.
//	*   **fetch_remote_cert**: Fetch X509 certificate chain from a remote hostname/port.
//	*   **get_resource_usage**: Get current resource usage statistics including memory, GC, and CPU information.
//	*   **resolve_cert_chain**: Resolve X509 certificate chain from a certificate file or base64-encoded certificate data.
//	*   **validate_cert_chain**: Validate a X509 certificate chain for correctness and trust.
//	----------------------
//	2025/11/22 01:24:21 Agent execution completed
func main() {
	// Create context that cancels on interrupt signal (Ctrl+C)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Check for required environment variables
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		log.Fatal("GOOGLE_API_KEY environment variable must be set")
	}

	// 1. Initialize ADK toolset with a fresh transport
	log.Println("Initializing ADK toolset...")
	transport := localMCPTransport(ctx)

	// Create MCP tool set
	mcpToolSet, err := mcptoolset.New(mcptoolset.Config{
		Transport: transport,
	})
	if err != nil {
		log.Fatalf("Failed to create MCP tool set: %v", err)
	}

	log.Printf("Certificate MCP transport created and connected successfully")
	log.Printf("MCP tool set initialized with transport")

	// 2. Create Gemini model
	// Note: This requires GOOGLE_API_KEY to be valid for Gemini API.
	// To use other providers, implement a custom model wrapper similar to the Gemini implementation. ADK supports integration with other providers.
	// While implementing a custom provider is straightforward, this example focuses on the Gemini implementation for simplicity.
	model, err := gemini.NewModel(ctx, "gemini-2.5-flash", &genai.ClientConfig{
		APIKey: apiKey,
	})
	if err != nil {
		log.Fatalf("Failed to create model: %v", err)
	}

	// 3. Create Agent
	thinkingBudget := int32(2048) // Minimum usually 1024 for effective thinking
	a, err := llmagent.New(llmagent.Config{
		Name:        "cert_agent",
		Model:       model,
		Description: "Agent for resolving and validating certificates.",
		Instruction: "You are a helpful assistant that helps users resolve and validate certificate chains. Use the available tools to answer questions. When asked about tools, list them.",
		Toolsets:    []tool.Toolset{mcpToolSet},
		GenerateContentConfig: &genai.GenerateContentConfig{
			ThinkingConfig: &genai.ThinkingConfig{
				IncludeThoughts: true,
				ThinkingBudget:  &thinkingBudget,
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	// 4. Create Session Service and Runner
	sessionSvc := session.InMemoryService()
	r, err := runner.New(runner.Config{
		AppName:        "adk-go-example",
		Agent:          a,
		SessionService: sessionSvc,
	})
	if err != nil {
		log.Fatalf("Failed to create runner: %v", err)
	}

	// Create a session
	sessResp, err := sessionSvc.Create(ctx, &session.CreateRequest{
		AppName: "adk-go-example",
		UserID:  "test-user",
	})
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	sessionID := sessResp.Session.ID()
	log.Printf("Created session: %s", sessionID)

	// Use streaming mode
	runConfig := agent.RunConfig{
		StreamingMode: agent.StreamingModeSSE,
	}

	// Helper function to run agent query
	runQuery := func(promptText string) {
		log.Printf("Running agent with prompt: %q", promptText)
		fmt.Printf("\n--- User Request ---\n%s\n", promptText)
		userMsg := genai.NewContentFromText(promptText, "user")

		var isThinking bool
		fmt.Printf("--- Agent Response ---")
		for event, err := range r.Run(ctx, "test-user", sessionID, userMsg, runConfig) {
			if err != nil {
				log.Printf("\nAgent error: %v", err)
				break // Stop on error
			}

			if event.LLMResponse.Partial {
				// Handle partial (streaming) response
				if event.LLMResponse.Content != nil {
					for _, part := range event.LLMResponse.Content.Parts {
						if part.Thought {
							if !isThinking {
								fmt.Print("\n[Thinking] ")
								isThinking = true
							}
							fmt.Print(part.Text)
						} else {
							if isThinking {
								fmt.Print("\n\n----------------------\n\n")
								isThinking = false
							}
							fmt.Print(part.Text)
						}
					}
				}
			}
		}
		if isThinking {
			fmt.Println()
		}
		fmt.Println("\n----------------------")
	}

	// 5. Run first query
	runQuery("What tools are available to you for certificate operations?")

	// 6. Run second query
	//
	// Note: gemini-2.5-flash may fail to show formatted PEM output because this tool is not easy to use. Many models fail at this task as well.
	runQuery("Fetch the certificate chain for www.example.com on port 443. Return ONLY the full, correctly formatted PEM output for all certificates in the chain.")

	log.Println("Agent execution completed")
}
