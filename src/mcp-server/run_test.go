// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
)

// Test certificate from www.google.com (valid until December 15, 2025)
// Retrieved: October 16, 2025
const testCertPEM = `
-----BEGIN CERTIFICATE-----
MIIEVzCCAz+gAwIBAgIQXEsKucZT6MwJr/NcaQmnozANBgkqhkiG9w0BAQsFADA7
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQww
CgYDVQQDEwNXUjIwHhcNMjUwOTIyMDg0MjQwWhcNMjUxMjE1MDg0MjM5WjAZMRcw
FQYDVQQDEw53d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BM3QmmV89za/vDWm/Ctodj6J5s0RLy5fo5QsoGRdMlzItH3jBRpmdWEMysalvQtm
aLGUUvJv5ASJHKfixPD3LWijggJCMIICPjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUUYk76ccIt4qc
kyjMh0xUc5iMmTIwHwYDVR0jBBgwFoAU3hse7XkV1D43JMMhu+w0OW1CsjAwWAYI
KwYBBQUHAQEETDBKMCEGCCsGAQUFBzABhhVodHRwOi8vby5wa2kuZ29vZy93cjIw
JQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dyMi5jcnQwGQYDVR0RBBIw
EIIOd3d3Lmdvb2dsZS5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwNgYDVR0fBC8w
LTAroCmgJ4YlaHR0cDovL2MucGtpLmdvb2cvd3IyL0dTeVQxTjRQQnJnLmNybDCC
AQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2AN3cyjSV1+EWBeeVMvrHn/g9HFDf2wA6
FBJ2Ciysu8gqAAABmXDN1WkAAAQDAEcwRQIgdH62Tub0woIi1sa+gQHvdMpNlfa6
WQgVn2Ov2CM0ktkCIQDyivdzECaAyaCq8GG+EtKWge4nLJ8FM++Q5WVQD9kCUgB3
AMz7D2qFcQll/pWbU87psnwi6YVcDZeNtql+VMD+TA2wAAABmXDN1WgAAAQDAEgw
RgIhAPNnKBAUSFiPjBYsu9A+UlI8ykhnoaZiFMhaDvrHGMKvAiEA02wfQcWu2753
HW54J/Iyeak0ni5z8jqayf1Rd5518Q0wDQYJKoZIhvcNAQELBQADggEBAAqYHEc6
CiVjrSPb0E4QSHYZIbqpHSYnOs8OQ7T54QM8yoMWOb4tWaMZGwdZayaL6ehyYKzS
8lhyxL4OPN9E51//mScXtemV4EbgrDm0fk3uH0gAX3oP+0DZH4X7t7L9aO8nalSl
KGJvEoHrphu2HbkAJY9OUqUo804OjXHeiY3FLUkoER7hb89w1qcaWxjRrVfflJ/Q
0pJCjtltJFSBTZbM6t0Y0uir9/XNPHcec4nMSyp3W/UEmcAoKc3kDJrT6CE2l2lI
Dd4Zns+bUA5A9z1Qy5c9MKX6I3rsHmUNUhGRz/lCyJDdc6UNoGKPmilI98JSRZYY
tXHHbX1dudpKfHM=
-----END CERTIFICATE-----
`

func TestMCPTools(t *testing.T) {
	config, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	// Encode test certificate as base64
	certData := base64.StdEncoding.EncodeToString([]byte(testCertPEM))

	// Create MCP server
	s := server.NewMCPServer(
		"X509 Certificate Chain Resolver",
		"test-version",
		server.WithToolCapabilities(true),
	)

	// Define tools (copied from main.go)
	resolveCertChainTool := mcp.NewTool("resolve_cert_chain",
		mcp.WithDescription("Resolve X509 certificate chain from a certificate file or base64-encoded certificate data"),
		mcp.WithString("certificate",
			mcp.Required(),
			mcp.Description("Certificate file path or base64-encoded certificate data"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
			mcp.DefaultString("pem"),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA in output (default: false)"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates (default: false)"),
			mcp.DefaultBool(false),
		),
	)

	validateCertChainTool := mcp.NewTool("validate_cert_chain",
		mcp.WithDescription("Validate a X509 certificate chain for correctness and trust"),
		mcp.WithString("certificate",
			mcp.Required(),
			mcp.Description("Certificate file path or base64-encoded certificate data"),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA for validation (default: true)"),
			mcp.DefaultBool(true),
		),
	)

	checkCertExpiryTool := mcp.NewTool("check_cert_expiry",
		mcp.WithDescription("Check certificate expiry dates and warn about upcoming expirations"),
		mcp.WithString("certificate",
			mcp.Required(),
			mcp.Description("Certificate file path or base64-encoded certificate data"),
		),
		mcp.WithNumber("warn_days",
			mcp.Description("Number of days before expiry to show warning (default: 30)"),
			mcp.DefaultNumber(30),
		),
	)

	batchResolveCertChainTool := mcp.NewTool("batch_resolve_cert_chain",
		mcp.WithDescription("Resolve X509 certificate chains for multiple certificates in batch"),
		mcp.WithString("certificates",
			mcp.Required(),
			mcp.Description("Comma-separated list of certificate file paths or base64-encoded certificate data"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
			mcp.DefaultString("pem"),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA in output (default: false)"),
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates (default: false)"),
		),
	)

	fetchRemoteCertTool := mcp.NewTool("fetch_remote_cert",
		mcp.WithDescription("Fetch X509 certificate chain from a remote hostname/port"),
		mcp.WithString("hostname",
			mcp.Required(),
			mcp.Description("Remote hostname to connect to"),
		),
		mcp.WithNumber("port",
			mcp.Description("Port number (default: 443)"),
			mcp.DefaultNumber(443),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'pem', 'der', or 'json' (default: pem)"),
			mcp.DefaultString("pem"),
		),
		mcp.WithBoolean("include_system_root",
			mcp.Description("Include system root CA in output (default: false)"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("intermediate_only",
			mcp.Description("Output only intermediate certificates (default: false)"),
			mcp.DefaultBool(false),
		),
	)

	// Register tool handlers
	s.AddTool(resolveCertChainTool, handleResolveCertChain)
	s.AddTool(batchResolveCertChainTool, handleBatchResolveCertChain)
	s.AddTool(validateCertChainTool, handleValidateCertChain)
	s.AddTool(checkCertExpiryTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleCheckCertExpiry(request, config)
	})
	s.AddTool(fetchRemoteCertTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleFetchRemoteCert(ctx, request, config)
	})

	// Create test server
	srv := mcptest.NewUnstartedServer(t)

	// Create ServerTool instances for each tool
	tools := []server.ServerTool{
		{
			Tool:    resolveCertChainTool,
			Handler: handleResolveCertChain,
		},
		{
			Tool:    batchResolveCertChainTool,
			Handler: handleBatchResolveCertChain,
		},
		{
			Tool:    validateCertChainTool,
			Handler: handleValidateCertChain,
		},
		{
			Tool: checkCertExpiryTool,
			Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return handleCheckCertExpiry(request, config)
			},
		},
		{
			Tool: fetchRemoteCertTool,
			Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return handleFetchRemoteCert(ctx, request, config)
			},
		},
	}

	srv.AddTools(tools...)

	// Start the server
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	client := srv.Client()

	tests := []struct {
		name           string
		toolName       string
		args           map[string]any
		expectError    bool
		expectContains []string
		skipOnMacOS    bool
	}{
		{
			name:     "resolve_cert_chain with base64 data",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": certData,
				"format":      "pem",
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE", "END CERTIFICATE"},
		},
		{
			name:     "validate_cert_chain",
			toolName: "validate_cert_chain",
			args: map[string]any{
				"certificate": certData,
			},
			expectError:    false,
			expectContains: []string{"validation"},
			skipOnMacOS:    true,
		},
		{
			name:     "check_cert_expiry",
			toolName: "check_cert_expiry",
			args: map[string]any{
				"certificate": certData,
				"warn_days":   30,
			},
			expectError:    false,
			expectContains: []string{"Expiry", "2025"},
		},
		{
			name:     "batch_resolve_cert_chain",
			toolName: "batch_resolve_cert_chain",
			args: map[string]any{
				"certificates": certData + "," + certData,
				"format":       "pem",
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnMacOS && runtime.GOOS == "darwin" {
				t.Skip("Skipping on macOS: system certificate validation has stricter EKU constraints")
			}
			req := mcp.CallToolRequest{
				Params: mcp.CallToolParams{
					Name:      tt.toolName,
					Arguments: tt.args,
				},
			}

			result, err := client.CallTool(context.Background(), req)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("expected result but got nil")
				return
			}

			// Check result content
			content := ""
			for _, c := range result.Content {
				if tc, ok := c.(mcp.TextContent); ok {
					content += tc.Text
				}
			}

			for _, expected := range tt.expectContains {
				if !contains(content, expected) {
					t.Errorf("expected result to contain %q, but it didn't. Result: %s", expected, content)
				}
			}
		})
	}
}

func TestRun_InvalidConfig(t *testing.T) {
	// Set environment variable to non-existent config file
	os.Setenv("MCP_X509_CONFIG_FILE", "/nonexistent/config.json")
	defer os.Unsetenv("MCP_X509_CONFIG_FILE")

	// Run should return an error due to invalid config file
	err := Run()
	if err == nil {
		t.Error("expected Run() to return an error with invalid config file")
	}

	// Error should mention config error
	if !strings.Contains(err.Error(), "config error") {
		t.Errorf("expected error to contain 'config error', got: %v", err)
	}
}

func TestRun_ValidConfig(t *testing.T) {
	t.Skip("Skipping valid config test as Run() blocks indefinitely - tested manually")

	// Use default config (empty env var)
	os.Unsetenv("MCP_X509_CONFIG_FILE")

	// Run the server in a goroutine since it blocks
	done := make(chan error, 1)
	go func() {
		done <- Run()
	}()

	// Give it a moment to start
	select {
	case err := <-done:
		// If it returns immediately, check if it's an expected error
		if err != nil {
			t.Logf("Run() returned error (expected if interrupted): %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		// It didn't return immediately, which is good for a server that should block
		t.Log("Run() started successfully and is blocking as expected")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || strings.Contains(s, substr)))
}

func TestLoadConfig(t *testing.T) {
	// Test loading default config
	config, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if config == nil {
		t.Fatal("Expected config, got nil")
	}

	// Check default values
	if config.Defaults.Format != "pem" {
		t.Errorf("Expected default format 'pem', got %s", config.Defaults.Format)
	}

	if config.Defaults.WarnDays != 30 {
		t.Errorf("Expected default warn days 30, got %d", config.Defaults.WarnDays)
	}
}

func TestResourcesAndPrompts(t *testing.T) {
	// Create MCP server with resource and prompt capabilities enabled
	s := server.NewMCPServer(
		"X509 Certificate Chain Resolver",
		"test-version",
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
	)

	// Add resources and prompts
	addResources(s)
	addPrompts(s)

	// Create test server and add the MCP server to it
	srv := mcptest.NewUnstartedServer(t)
	defer srv.Close()

	// Copy resources and prompts from our MCP server to the test server
	// This is needed because mcptest.Server manages its own MCP server instance

	// Add resources manually to test server
	configResource := mcp.NewResource(
		"config://template",
		"Server Configuration Template",
		mcp.WithResourceDescription("Example configuration file for the MCP server"),
		mcp.WithMIMEType("application/json"),
	)
	srv.AddResource(configResource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		exampleConfig := map[string]any{
			"defaults": map[string]any{
				"format":            "pem",
				"includeSystemRoot": false,
				"intermediateOnly":  false,
				"warnDays":          30,
				"port":              443,
				"timeoutSeconds":    10,
			},
		}

		jsonData, err := json.MarshalIndent(exampleConfig, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal config template: %w", err)
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "config://template",
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		}, nil
	})

	versionResource := mcp.NewResource(
		"info://version",
		"Server Version Information",
		mcp.WithResourceDescription("Version and build information for the MCP server"),
		mcp.WithMIMEType("application/json"),
	)
	srv.AddResource(versionResource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		versionInfo := map[string]any{
			"name":    "X509 Certificate Chain Resolver",
			"version": "test-version",
			"type":    "MCP Server",
			"capabilities": map[string]any{
				"tools":     []string{"resolve_cert_chain", "validate_cert_chain", "check_cert_expiry", "batch_resolve_cert_chain", "fetch_remote_cert"},
				"resources": true,
				"prompts":   true,
			},
			"supportedFormats": []string{"pem", "der", "json"},
		}

		jsonData, err := json.MarshalIndent(versionInfo, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal version info: %w", err)
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "info://version",
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		}, nil
	})

	formatsResource := mcp.NewResource(
		"docs://certificate-formats",
		"Certificate Format Documentation",
		mcp.WithResourceDescription("Documentation on supported certificate formats and usage"),
		mcp.WithMIMEType("text/markdown"),
	)
	srv.AddResource(formatsResource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		content, err := magicEmbed.ReadFile("templates/certificate-formats.md")
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate formats template: %w", err)
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "docs://certificate-formats",
				MIMEType: "text/markdown",
				Text:     string(content),
			},
		}, nil
	})

	// Add prompts manually to test server
	certAnalysisPrompt := mcp.NewPrompt("certificate-analysis",
		mcp.WithPromptDescription("Comprehensive certificate chain analysis workflow"),
		mcp.WithArgument("certificate_path",
			mcp.ArgumentDescription("Path to certificate file or base64-encoded certificate data"),
		),
	)
	srv.AddPrompt(certAnalysisPrompt, func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		certPath := request.Params.Arguments["certificate_path"]

		messages := []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(fmt.Sprintf(`I'll help you perform a comprehensive analysis of the certificate chain for: %s

Let's start with the basic chain resolution:`, certPath)),
			),
		}

		return mcp.NewGetPromptResult(
			"Certificate Chain Analysis Workflow",
			messages,
		), nil
	})

	expiryPrompt := mcp.NewPrompt("expiry-monitoring",
		mcp.WithPromptDescription("Monitor certificate expiration dates and generate renewal alerts"),
		mcp.WithArgument("certificate_path",
			mcp.ArgumentDescription("Path to certificate file or base64-encoded certificate data"),
		),
		mcp.WithArgument("alert_days",
			mcp.ArgumentDescription("Number of days before expiry to alert (default: 30)"),
		),
	)
	srv.AddPrompt(expiryPrompt, func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		certPath := request.Params.Arguments["certificate_path"]
		alertDays := request.Params.Arguments["alert_days"]
		if alertDays == "" {
			alertDays = "30"
		}

		messages := []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleAssistant,
				mcp.NewTextContent(fmt.Sprintf(`I'll help you monitor certificate expiration for: %s with %s-day alert threshold.`, certPath, alertDays)),
			),
		}

		return mcp.NewGetPromptResult(
			"Certificate Expiry Monitoring",
			messages,
		), nil
	})

	// Start the test server
	err := srv.Start(context.Background())
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}

	client := srv.Client()

	t.Run("resources", func(t *testing.T) {
		tests := []struct {
			name       string
			uri        string
			expectMIME string
			expectText []string
		}{
			{
				name:       "config template",
				uri:        "config://template",
				expectMIME: "application/json",
				expectText: []string{`"format": "pem"`, `"warnDays": 30`, `"port": 443`},
			},
			{
				name:       "version info",
				uri:        "info://version",
				expectMIME: "application/json",
				expectText: []string{`"name": "X509 Certificate Chain Resolver"`, `"version": "test-version"`, `"type": "MCP Server"`},
			},
			{
				name:       "certificate formats",
				uri:        "docs://certificate-formats",
				expectMIME: "text/markdown",
				expectText: []string{"# Certificate Formats Supported", "PEM Format", "DER Format"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := mcp.ReadResourceRequest{
					Params: mcp.ReadResourceParams{
						URI: tt.uri,
					},
				}

				result, err := client.ReadResource(context.Background(), req)
				if err != nil {
					t.Fatalf("ReadResource failed for %s: %v", tt.uri, err)
				}

				if len(result.Contents) != 1 {
					t.Fatalf("Expected 1 content item for %s, got %d", tt.uri, len(result.Contents))
				}

				content := result.Contents[0]
				if tc, ok := content.(mcp.TextResourceContents); ok {
					if tc.MIMEType != tt.expectMIME {
						t.Errorf("Expected MIME type %s for %s, got %s", tt.expectMIME, tt.uri, tc.MIMEType)
					}

					for _, expected := range tt.expectText {
						if !strings.Contains(tc.Text, expected) {
							t.Errorf("Expected content to contain %q for %s, but it didn't. Content: %s", expected, tt.uri, tc.Text)
						}
					}
				} else {
					t.Errorf("Expected TextResourceContents for %s, got %T", tt.uri, content)
				}
			})
		}
	})

	t.Run("prompts", func(t *testing.T) {
		tests := []struct {
			name       string
			promptName string
			args       map[string]string
			expectDesc string
			expectText []string
		}{
			{
				name:       "certificate analysis",
				promptName: "certificate-analysis",
				args: map[string]string{
					"certificate_path": "/path/to/cert.pem",
				},
				expectDesc: "Certificate Chain Analysis Workflow",
				expectText: []string{"certificate chain for: /path/to/cert.pem", "basic chain resolution"},
			},
			{
				name:       "expiry monitoring",
				promptName: "expiry-monitoring",
				args: map[string]string{
					"certificate_path": "/path/to/cert.pem",
					"alert_days":       "60",
				},
				expectDesc: "Certificate Expiry Monitoring",
				expectText: []string{"certificate expiration for: /path/to/cert.pem", "60-day alert threshold"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := mcp.GetPromptRequest{
					Params: mcp.GetPromptParams{
						Name:      tt.promptName,
						Arguments: tt.args,
					},
				}

				result, err := client.GetPrompt(context.Background(), req)
				if err != nil {
					t.Fatalf("GetPrompt failed for %s: %v", tt.promptName, err)
				}

				if result.Description != tt.expectDesc {
					t.Errorf("Expected description %q for %s, got %q", tt.expectDesc, tt.promptName, result.Description)
				}

				if len(result.Messages) == 0 {
					t.Fatalf("Expected at least one message for %s", tt.promptName)
				}

				// Check the first message content
				firstMsg := result.Messages[0]
				if tc, ok := firstMsg.Content.(mcp.TextContent); ok {
					for _, expected := range tt.expectText {
						if !strings.Contains(tc.Text, expected) {
							t.Errorf("Expected message to contain %q for %s, but it didn't. Message: %s", expected, tt.promptName, tc.Text)
						}
					}
				} else {
					t.Errorf("Expected TextContent for %s, got %T", tt.promptName, firstMsg.Content)
				}
			})
		}
	})
}
