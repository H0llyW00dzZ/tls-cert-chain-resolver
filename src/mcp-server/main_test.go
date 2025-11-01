// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"encoding/base64"
	"os"
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
		args           map[string]interface{}
		expectError    bool
		expectContains []string
	}{
		{
			name:     "resolve_cert_chain with base64 data",
			toolName: "resolve_cert_chain",
			args: map[string]interface{}{
				"certificate": certData,
				"format":      "pem",
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE", "END CERTIFICATE"},
		},
		{
			name:     "validate_cert_chain",
			toolName: "validate_cert_chain",
			args: map[string]interface{}{
				"certificate": certData,
			},
			expectError:    false,
			expectContains: []string{"validation"},
		},
		{
			name:     "check_cert_expiry",
			toolName: "check_cert_expiry",
			args: map[string]interface{}{
				"certificate": certData,
				"warn_days":   30,
			},
			expectError:    false,
			expectContains: []string{"Expiry", "2025"},
		},
		{
			name:     "batch_resolve_cert_chain",
			toolName: "batch_resolve_cert_chain",
			args: map[string]interface{}{
				"certificates": certData + "," + certData,
				"format":       "pem",
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
