// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
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
		return handleCheckCertExpiry(ctx, request, config)
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
				return handleCheckCertExpiry(ctx, request, config)
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
			name:     "batch_resolve_cert_chain with mixed valid and invalid",
			toolName: "batch_resolve_cert_chain",
			args: map[string]any{
				"certificates": certData + ",invalid-cert,another-invalid",
				"format":       "pem",
			},
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:     "fetch_remote_cert",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname": "example.com",
				"port":     443,
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE"},
		},
		{
			name:     "resolve_cert_chain with json format",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": certData,
				"format":      "json",
			},
			expectError:    false,
			expectContains: []string{`"listCertificates"`, "Certificate Chain"},
		},
		{
			name:     "resolve_cert_chain with der format",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": certData,
				"format":      "der",
			},
			expectError:    false,
			expectContains: []string{}, // DER is binary, no text to check
		},
		{
			name:     "resolve_cert_chain with include_system_root",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate":         certData,
				"include_system_root": true,
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE"},
		},
		{
			name:     "resolve_cert_chain with intermediate_only",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate":       certData,
				"intermediate_only": true,
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE"},
		},
		{
			name:     "resolve_cert_chain with invalid certificate data",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": "invalid-cert-data",
			},
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:     "resolve_cert_chain with invalid file path",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": "/nonexistent/file.pem",
			},
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:     "validate_cert_chain with invalid certificate",
			toolName: "validate_cert_chain",
			args: map[string]any{
				"certificate": "invalid-cert-data",
			},
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:     "batch_resolve_cert_chain with invalid certificates",
			toolName: "batch_resolve_cert_chain",
			args: map[string]any{
				"certificates": "invalid-cert1,invalid-cert2",
			},
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:     "fetch_remote_cert with invalid hostname",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname": "invalid.hostname.that.does.not.exist.example",
			},
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:           "resolve_cert_chain missing certificate parameter",
			toolName:       "resolve_cert_chain",
			args:           map[string]any{}, // Empty args
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:           "validate_cert_chain missing certificate parameter",
			toolName:       "validate_cert_chain",
			args:           map[string]any{}, // Empty args
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:           "batch_resolve_cert_chain missing certificates parameter",
			toolName:       "batch_resolve_cert_chain",
			args:           map[string]any{}, // Empty args
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:           "check_cert_expiry missing certificate parameter",
			toolName:       "check_cert_expiry",
			args:           map[string]any{}, // Empty args
			expectError:    true,
			expectContains: []string{},
		},
		{
			name:           "fetch_remote_cert missing hostname parameter",
			toolName:       "fetch_remote_cert",
			args:           map[string]any{}, // Empty args
			expectError:    true,
			expectContains: []string{},
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
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				// Check if result contains error message
				content := ""
				for _, c := range result.Content {
					if tc, ok := c.(mcp.TextContent); ok {
						content += tc.Text
					}
				}
				if !strings.Contains(content, "error") && !strings.Contains(content, "failed") && !strings.Contains(content, "required") {
					t.Errorf("expected error message in result, but got: %s", content)
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

func TestHandlerErrorPaths(t *testing.T) {
	testCases := []struct {
		name          string
		toolName      string
		args          map[string]any
		expectError   bool
		errorContains []string
	}{
		{
			name:     "resolve_cert_chain with empty certificate",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": "",
			},
			expectError:   true,
			errorContains: []string{"failed to decode certificate"},
		},
		{
			name:     "resolve_cert_chain with invalid base64",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": "invalid-base64!",
			},
			expectError:   true,
			errorContains: []string{"failed to read certificate"},
		},
		{
			name:     "resolve_cert_chain with nonexistent file",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": "/dev/null/nonexistent.pem",
			},
			expectError:   true,
			errorContains: []string{"failed to read certificate"},
		},
		{
			name:     "validate_cert_chain with malformed PEM",
			toolName: "validate_cert_chain",
			args: map[string]any{
				"certificate": base64.StdEncoding.EncodeToString([]byte("not-a-certificate")),
			},
			expectError:   true,
			errorContains: []string{"failed to decode certificate"},
		},
		{
			name:     "check_cert_expiry with invalid warn_days",
			toolName: "check_cert_expiry",
			args: map[string]any{
				"certificate": testCertPEM,
				"warn_days":   "not-a-number",
			},
			expectError: false, // Should use default
		},
		{
			name:     "fetch_remote_cert with invalid hostname",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname": "invalid.hostname.that.does.not.exist.example",
			},
			expectError:   true,
			errorContains: []string{"failed to connect"},
		},
		{
			name:     "batch_resolve_cert_chain with empty list",
			toolName: "batch_resolve_cert_chain",
			args: map[string]any{
				"certificates": "",
			},
			expectError:   false, // Returns empty batch result
			errorContains: []string{},
		},
		{
			name:          "resolve_cert_chain missing certificate parameter",
			toolName:      "resolve_cert_chain",
			args:          map[string]any{}, // Empty args
			expectError:   true,
			errorContains: []string{"certificate parameter required"},
		},
		{
			name:          "validate_cert_chain missing certificate parameter",
			toolName:      "validate_cert_chain",
			args:          map[string]any{}, // Empty args
			expectError:   true,
			errorContains: []string{"certificate parameter required"},
		},
		{
			name:          "batch_resolve_cert_chain missing certificates parameter",
			toolName:      "batch_resolve_cert_chain",
			args:          map[string]any{}, // Empty args
			expectError:   true,
			errorContains: []string{"certificates parameter required"},
		},
		{
			name:          "check_cert_expiry missing certificate parameter",
			toolName:      "check_cert_expiry",
			args:          map[string]any{}, // Empty args
			expectError:   true,
			errorContains: []string{"certificate parameter required"},
		},
		{
			name:          "fetch_remote_cert missing hostname parameter",
			toolName:      "fetch_remote_cert",
			args:          map[string]any{}, // Empty args
			expectError:   true,
			errorContains: []string{"hostname parameter required"},
		},
	}

	// Test with direct handler calls to avoid MCP server setup overhead
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.CallToolRequest{
				Params: mcp.CallToolParams{
					Name:      tt.toolName,
					Arguments: tt.args,
				},
			}

			var result *mcp.CallToolResult
			var err error

			// Call the appropriate handler directly
			switch tt.toolName {
			case "resolve_cert_chain":
				result, err = handleResolveCertChain(context.Background(), req)
			case "validate_cert_chain":
				result, err = handleValidateCertChain(context.Background(), req)
			case "batch_resolve_cert_chain":
				result, err = handleBatchResolveCertChain(context.Background(), req)
			case "check_cert_expiry":
				config, _ := loadConfig("")
				result, err = handleCheckCertExpiry(context.Background(), req, config)
			case "fetch_remote_cert":
				config, _ := loadConfig("")
				result, err = handleFetchRemoteCert(context.Background(), req, config)
			default:
				t.Fatalf("Unknown tool name: %s", tt.toolName)
			}

			if tt.expectError {
				if err == nil {
					// Check if result contains error message instead
					if result != nil {
						content := ""
						for _, c := range result.Content {
							if tc, ok := c.(mcp.TextContent); ok {
								content += tc.Text
							}
						}
						foundError := false
						for _, errStr := range tt.errorContains {
							if strings.Contains(content, errStr) {
								foundError = true
								break
							}
						}
						if !foundError {
							t.Errorf("Expected error message containing %v in result, but got: %s", tt.errorContains, content)
						}
					} else {
						t.Error("Expected error but got nil result")
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("Expected result but got nil")
			}
		})
	}
}

func TestContextCancellation(t *testing.T) {
	// Test context cancellation and timeout scenarios
	testCases := []struct {
		name        string
		toolName    string
		setupCtx    func() (context.Context, context.CancelFunc)
		args        map[string]any
		expectError bool
	}{
		{
			name:     "resolve_cert_chain with cancelled context",
			toolName: "resolve_cert_chain",
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately
				return ctx, cancel
			},
			args: map[string]any{
				"certificate": testCertPEM,
			},
			expectError: true,
		},
		{
			name:     "validate_cert_chain with cancelled context",
			toolName: "validate_cert_chain",
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately
				return ctx, cancel
			},
			args: map[string]any{
				"certificate": testCertPEM,
			},
			expectError: true,
		},
		{
			name:     "batch_resolve_cert_chain with cancelled context",
			toolName: "batch_resolve_cert_chain",
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately
				return ctx, cancel
			},
			args: map[string]any{
				"certificates": testCertPEM,
			},
			expectError: true,
		},
		{
			name:     "fetch_remote_cert with timeout",
			toolName: "fetch_remote_cert",
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 1*time.Nanosecond)
			},
			args: map[string]any{
				"hostname": "example.com",
				"port":     443,
			},
			expectError: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := tt.setupCtx()

			req := mcp.CallToolRequest{
				Params: mcp.CallToolParams{
					Name:      tt.toolName,
					Arguments: tt.args,
				},
			}

			var result *mcp.CallToolResult
			var err error

			// Call the appropriate handler
			switch tt.toolName {
			case "resolve_cert_chain":
				result, err = handleResolveCertChain(ctx, req)
			case "validate_cert_chain":
				result, err = handleValidateCertChain(ctx, req)
			case "batch_resolve_cert_chain":
				result, err = handleBatchResolveCertChain(ctx, req)
			case "fetch_remote_cert":
				config, _ := loadConfig("")
				result, err = handleFetchRemoteCert(ctx, req, config)
			default:
				t.Fatalf("Unknown tool name: %s", tt.toolName)
			}

			if tt.expectError {
				if err == nil && result == nil {
					t.Error("Expected error or result with error message, but got neither")
				}
				// Either err != nil or result contains error message
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Error("Expected result but got nil")
				}
			}
		})
	}
}

func TestEdgeCases(t *testing.T) {
	// Test edge cases and boundary conditions
	testCases := []struct {
		name        string
		toolName    string
		args        map[string]any
		expectError bool
		description string
	}{
		{
			name:     "check_cert_expiry with very large warn_days",
			toolName: "check_cert_expiry",
			args: map[string]any{
				"certificate": testCertPEM,
				"warn_days":   float64(999999), // Very large number
			},
			expectError: false,
			description: "Should handle large warn_days gracefully",
		},
		{
			name:     "fetch_remote_cert with port 0",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname": "example.com",
				"port":     float64(0), // Invalid port
			},
			expectError: true,
			description: "Should reject invalid ports",
		},
		{
			name:     "fetch_remote_cert with port 65536",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname": "example.com",
				"port":     float64(65536), // Invalid port
			},
			expectError: true,
			description: "Should reject ports > 65535",
		},
		{
			name:     "resolve_cert_chain with very long certificate data",
			toolName: "resolve_cert_chain",
			args: map[string]any{
				"certificate": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 100000))), // 100KB of data
			},
			expectError: true, // Should fail to decode
			description: "Should handle large certificate data appropriately",
		},
		{
			name:     "batch_resolve_cert_chain with many separators",
			toolName: "batch_resolve_cert_chain",
			args: map[string]any{
				"certificates": ",,,", // Multiple empty entries
			},
			expectError: false,
			description: "Should handle empty entries in batch",
		},
		{
			name:     "validate_cert_chain with unicode in certificate subject",
			toolName: "validate_cert_chain",
			args: map[string]any{
				"certificate": testCertPEM, // Test cert has standard subject
			},
			expectError: false,
			description: "Should handle standard certificates",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.CallToolRequest{
				Params: mcp.CallToolParams{
					Name:      tt.toolName,
					Arguments: tt.args,
				},
			}

			var result *mcp.CallToolResult
			var err error

			// Call the appropriate handler
			switch tt.toolName {
			case "resolve_cert_chain":
				result, err = handleResolveCertChain(context.Background(), req)
			case "validate_cert_chain":
				result, err = handleValidateCertChain(context.Background(), req)
			case "batch_resolve_cert_chain":
				result, err = handleBatchResolveCertChain(context.Background(), req)
			case "check_cert_expiry":
				config, _ := loadConfig("")
				result, err = handleCheckCertExpiry(context.Background(), req, config)
			case "fetch_remote_cert":
				config, _ := loadConfig("")
				result, err = handleFetchRemoteCert(context.Background(), req, config)
			default:
				t.Fatalf("Unknown tool name: %s", tt.toolName)
			}

			if tt.expectError {
				if err == nil && result == nil {
					t.Errorf("Expected error for %s, but got neither error nor result", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tt.description, err)
				}
				if result == nil {
					t.Errorf("Expected result for %s, but got nil", tt.description)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || strings.Contains(s, substr)))
}

func TestResourceHandlers(t *testing.T) {
	// Use the real createResources function to test actual handlers
	resources := createResources()

	// Create test server and add the real resources
	srv := mcptest.NewUnstartedServer(t)
	srv.AddResources(resources...)

	// Start the server
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	client := srv.Client()

	tests := []struct {
		name           string
		uri            string
		expectError    bool
		expectContains []string
		expectMIMEType string
	}{
		{
			name:           "read config template resource",
			uri:            "config://template",
			expectError:    false,
			expectContains: []string{`"format"`, `"includeSystemRoot"`, `"warnDays"`},
			expectMIMEType: "application/json",
		},
		{
			name:           "read version info resource",
			uri:            "info://version",
			expectError:    false,
			expectContains: []string{`"name"`, `"version"`, `"capabilities"`, `"supportedFormats"`},
			expectMIMEType: "application/json",
		},
		{
			name:           "read certificate formats resource",
			uri:            "docs://certificate-formats",
			expectError:    false,
			expectContains: []string{"Certificate", "Format"},
			expectMIMEType: "text/markdown",
		},
		{
			name:           "read server status resource",
			uri:            "status://server-status",
			expectError:    false,
			expectContains: []string{`"status"`, `"healthy"`, `"timestamp"`, `"server"`},
			expectMIMEType: "application/json",
		},
		{
			name:           "read nonexistent resource",
			uri:            "nonexistent://resource",
			expectError:    true,
			expectContains: []string{},
			expectMIMEType: "",
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
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for URI %s, but got none", tt.uri)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for URI %s: %v", tt.uri, err)
				return
			}

			if result == nil {
				t.Errorf("expected result for URI %s, but got nil", tt.uri)
				return
			}

			if len(result.Contents) == 0 {
				t.Errorf("expected contents for URI %s, but got empty", tt.uri)
				return
			}

			// Check the first content item
			content := result.Contents[0]
			if textContent, ok := content.(mcp.TextResourceContents); ok {
				if textContent.MIMEType != tt.expectMIMEType {
					t.Errorf("expected MIME type %s for URI %s, but got %s", tt.expectMIMEType, tt.uri, textContent.MIMEType)
				}

				for _, expected := range tt.expectContains {
					if !contains(textContent.Text, expected) {
						t.Errorf("expected content to contain %q for URI %s, but it didn't. Content: %s", expected, tt.uri, textContent.Text[:min(200, len(textContent.Text))])
					}
				}
			} else {
				t.Errorf("expected TextResourceContents for URI %s, but got %T", tt.uri, content)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestAddResources(t *testing.T) {
	// Create MCP server
	s := server.NewMCPServer(
		"Test Server",
		"1.0.0",
		server.WithResourceCapabilities(true, true),
	)

	// Call addResources to test it
	addResources(s)

	// Verify resources were added
	// Note: This is a basic test that addResources doesn't panic
	// Full integration testing is done in TestResourceHandlers
	if s == nil {
		t.Error("Server should not be nil after addResources")
	}
}

func TestCreateResources(t *testing.T) {
	resources := createResources()

	// Verify we get the expected number of resources
	if len(resources) != 4 {
		t.Errorf("Expected 4 resources, got %d", len(resources))
	}

	// Verify resource URIs
	expectedURIs := []string{
		"config://template",
		"info://version",
		"docs://certificate-formats",
		"status://server-status",
	}

	for i, resource := range resources {
		if resource.Resource.URI != expectedURIs[i] {
			t.Errorf("Resource %d: expected URI %s, got %s", i, expectedURIs[i], resource.Resource.URI)
		}
		if resource.Handler == nil {
			t.Errorf("Resource %d (%s) has nil handler", i, resource.Resource.URI)
		}
	}
}

func TestHandleConfigResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "config://template",
		},
	}

	result, err := handleConfigResource(context.Background(), req)
	if err != nil {
		t.Fatalf("handleConfigResource failed: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result))
	}

	content, ok := result[0].(mcp.TextResourceContents)
	if !ok {
		t.Errorf("Expected TextResourceContents, got %T", result[0])
	}

	if content.URI != "config://template" {
		t.Errorf("Expected URI 'config://template', got %s", content.URI)
	}

	if content.MIMEType != "application/json" {
		t.Errorf("Expected MIME type 'application/json', got %s", content.MIMEType)
	}

	// Verify JSON structure
	var config map[string]any
	if err := json.Unmarshal([]byte(content.Text), &config); err != nil {
		t.Errorf("Failed to unmarshal config JSON: %v", err)
	}

	if _, ok := config["defaults"]; !ok {
		t.Error("Config should contain 'defaults' key")
	}
}

func TestHandleVersionResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "info://version",
		},
	}

	result, err := handleVersionResource(context.Background(), req)
	if err != nil {
		t.Fatalf("handleVersionResource failed: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result))
	}

	content, ok := result[0].(mcp.TextResourceContents)
	if !ok {
		t.Errorf("Expected TextResourceContents, got %T", result[0])
	}

	if content.URI != "info://version" {
		t.Errorf("Expected URI 'info://version', got %s", content.URI)
	}

	if content.MIMEType != "application/json" {
		t.Errorf("Expected MIME type 'application/json', got %s", content.MIMEType)
	}

	// Verify JSON structure contains expected fields
	var versionInfo map[string]any
	if err := json.Unmarshal([]byte(content.Text), &versionInfo); err != nil {
		t.Errorf("Failed to unmarshal version JSON: %v", err)
	}

	expectedFields := []string{"name", "version", "type", "capabilities", "supportedFormats"}
	for _, field := range expectedFields {
		if _, ok := versionInfo[field]; !ok {
			t.Errorf("Version info should contain '%s' key", field)
		}
	}
}

func TestHandleFormatsResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "docs://certificate-formats",
		},
	}

	result, err := handleFormatsResource(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFormatsResource failed: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result))
	}

	content, ok := result[0].(mcp.TextResourceContents)
	if !ok {
		t.Errorf("Expected TextResourceContents, got %T", result[0])
	}

	if content.URI != "docs://certificate-formats" {
		t.Errorf("Expected URI 'docs://certificate-formats', got %s", content.URI)
	}

	if content.MIMEType != "text/markdown" {
		t.Errorf("Expected MIME type 'text/markdown', got %s", content.MIMEType)
	}

	// Content should contain markdown
	if !strings.Contains(content.Text, "#") {
		t.Error("Expected markdown content with headers")
	}
}

func TestHandleStatusResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "status://server-status",
		},
	}

	result, err := handleStatusResource(context.Background(), req)
	if err != nil {
		t.Fatalf("handleStatusResource failed: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result))
	}

	content, ok := result[0].(mcp.TextResourceContents)
	if !ok {
		t.Errorf("Expected TextResourceContents, got %T", result[0])
	}

	if content.URI != "status://server-status" {
		t.Errorf("Expected URI 'status://server-status', got %s", content.URI)
	}

	if content.MIMEType != "application/json" {
		t.Errorf("Expected MIME type 'application/json', got %s", content.MIMEType)
	}

	// Verify JSON structure contains expected fields
	var statusInfo map[string]any
	if err := json.Unmarshal([]byte(content.Text), &statusInfo); err != nil {
		t.Errorf("Failed to unmarshal status JSON: %v", err)
	}

	expectedFields := []string{"status", "timestamp", "server", "version", "capabilities", "supportedFormats"}
	for _, field := range expectedFields {
		if _, ok := statusInfo[field]; !ok {
			t.Errorf("Status info should contain '%s' key", field)
		}
	}

	if statusInfo["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", statusInfo["status"])
	}
}

func TestHandleCertificateAnalysisPrompt(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "certificate-analysis",
			Arguments: map[string]string{
				"certificate_path": "/path/to/cert.pem",
			},
		},
	}

	result, err := handleCertificateAnalysisPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleCertificateAnalysisPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) != 8 {
		t.Errorf("Expected 8 messages, got %d", len(result.Messages))
	}

	if result.Description != "Certificate Chain Analysis Workflow" {
		t.Errorf("Expected description 'Certificate Chain Analysis Workflow', got %s", result.Description)
	}
}

func TestHandleExpiryMonitoringPrompt(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "expiry-monitoring",
			Arguments: map[string]string{
				"certificate_path": "/path/to/cert.pem",
				"alert_days":       "45",
			},
		},
	}

	result, err := handleExpiryMonitoringPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExpiryMonitoringPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) != 4 {
		t.Errorf("Expected 4 messages, got %d", len(result.Messages))
	}

	if result.Description != "Certificate Expiry Monitoring" {
		t.Errorf("Expected description 'Certificate Expiry Monitoring', got %s", result.Description)
	}
}

func TestHandleSecurityAuditPrompt(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "security-audit",
			Arguments: map[string]string{
				"hostname": "example.com",
				"port":     "8443",
			},
		},
	}

	result, err := handleSecurityAuditPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecurityAuditPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) < 8 {
		t.Errorf("Expected at least 8 messages, got %d", len(result.Messages))
	}

	if result.Description != "SSL/TLS Security Audit" {
		t.Errorf("Expected description 'SSL/TLS Security Audit', got %s", result.Description)
	}
}

func TestHandleTroubleshootingPrompt_ChainIssue(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "troubleshooting",
			Arguments: map[string]string{
				"issue_type":       "chain",
				"certificate_path": "/path/to/cert.pem",
			},
		},
	}

	result, err := handleTroubleshootingPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleTroubleshootingPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) < 3 {
		t.Errorf("Expected at least 3 messages for chain issue, got %d", len(result.Messages))
	}

	if result.Description != "Certificate Troubleshooting Guide" {
		t.Errorf("Expected description 'Certificate Troubleshooting Guide', got %s", result.Description)
	}
}

func TestHandleTroubleshootingPrompt_ValidationIssue(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "troubleshooting",
			Arguments: map[string]string{
				"issue_type":       "validation",
				"certificate_path": "/path/to/cert.pem",
			},
		},
	}

	result, err := handleTroubleshootingPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleTroubleshootingPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) < 2 {
		t.Errorf("Expected at least 2 messages for validation issue, got %d", len(result.Messages))
	}

	if result.Description != "Certificate Troubleshooting Guide" {
		t.Errorf("Expected description 'Certificate Troubleshooting Guide', got %s", result.Description)
	}
}

func TestHandleTroubleshootingPrompt_ExpiryIssue(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "troubleshooting",
			Arguments: map[string]string{
				"issue_type":       "expiry",
				"certificate_path": "/path/to/cert.pem",
			},
		},
	}

	result, err := handleTroubleshootingPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleTroubleshootingPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) < 2 {
		t.Errorf("Expected at least 2 messages for expiry issue, got %d", len(result.Messages))
	}

	if result.Description != "Certificate Troubleshooting Guide" {
		t.Errorf("Expected description 'Certificate Troubleshooting Guide', got %s", result.Description)
	}
}

func TestHandleTroubleshootingPrompt_ConnectionIssue(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "troubleshooting",
			Arguments: map[string]string{
				"issue_type": "connection",
				"hostname":   "example.com",
			},
		},
	}

	result, err := handleTroubleshootingPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleTroubleshootingPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) < 2 {
		t.Errorf("Expected at least 2 messages for connection issue, got %d", len(result.Messages))
	}

	if result.Description != "Certificate Troubleshooting Guide" {
		t.Errorf("Expected description 'Certificate Troubleshooting Guide', got %s", result.Description)
	}
}

func TestHandleTroubleshootingPrompt_InvalidIssueType(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "troubleshooting",
			Arguments: map[string]string{
				"issue_type": "invalid",
			},
		},
	}

	result, err := handleTroubleshootingPrompt(context.Background(), req)
	if err != nil {
		t.Fatalf("handleTroubleshootingPrompt failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Messages) != 1 {
		t.Errorf("Expected 1 message for invalid issue type, got %d", len(result.Messages))
	}

	if result.Description != "Certificate Troubleshooting Guide" {
		t.Errorf("Expected description 'Certificate Troubleshooting Guide', got %s", result.Description)
	}
}

func TestFormatJSON(t *testing.T) {
	// Test the formatJSON function directly
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		SerialNumber:       big.NewInt(12345),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	certs := []*x509.Certificate{cert}
	certManager := &x509certs.Certificate{} // Mock interface

	result := formatJSON(certs, certManager)

	// Should be valid JSON
	var jsonResult map[string]any
	if err := json.Unmarshal([]byte(result), &jsonResult); err != nil {
		t.Fatalf("formatJSON should return valid JSON: %v", err)
	}

	// Check structure
	if jsonResult["title"] != "TLS Certificate Chain" {
		t.Errorf("Expected title 'TLS Certificate Chain', got %v", jsonResult["title"])
	}

	if jsonResult["totalChained"].(float64) != 1 {
		t.Errorf("Expected totalChained 1, got %v", jsonResult["totalChained"])
	}
}

func TestServerBuilder_Build_WithoutTools(t *testing.T) {
	builder := NewServerBuilder().
		WithConfig(&Config{}).
		WithVersion("1.0.0")

	server, err := builder.Build()
	if err != nil {
		t.Fatalf("Build should succeed without tools: %v", err)
	}

	if server == nil {
		t.Error("Expected server, got nil")
	}
}

func TestDefaultChainResolver_New(t *testing.T) {
	// Create a test certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	resolver := DefaultChainResolver{}
	chain := resolver.New(cert, "1.0.0")

	if chain == nil {
		t.Fatal("Expected chain, got nil")
	}

	// The chain should contain the certificate
	if len(chain.Certs) == 0 {
		t.Error("Expected chain to contain at least one certificate")
	}

	if chain.Certs[0].Subject.CommonName != "test.example.com" {
		t.Errorf("Expected certificate CN 'test.example.com', got %s", chain.Certs[0].Subject.CommonName)
	}
}
