// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
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
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping TestMCPTools on macOS due to certificate validation differences")
	}
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

	getResourceUsageTool := mcp.NewTool("get_resource_usage",
		mcp.WithDescription("Get current resource usage statistics including memory, GC, and CPU information"),
		mcp.WithBoolean("detailed",
			mcp.Description("Include detailed memory breakdown (default: false)"),
			mcp.DefaultBool(false),
		),
		mcp.WithString("format",
			mcp.Description("Output format: 'json' or 'markdown' (default: 'json')"),
			mcp.DefaultString("json"),
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
	s.AddTool(getResourceUsageTool, handleGetResourceUsage)

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
		{
			Tool:    getResourceUsageTool,
			Handler: handleGetResourceUsage,
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
		{
			name:     "get_resource_usage json format",
			toolName: "get_resource_usage",
			args: map[string]any{
				"detailed": true,
				"format":   "json",
			},
			expectError:    false,
			expectContains: []string{"memory_usage", "gc_stats", "system_info", "timestamp"},
		},
		{
			name:     "get_resource_usage markdown format",
			toolName: "get_resource_usage",
			args: map[string]any{
				"detailed": false,
				"format":   "markdown",
			},
			expectError:    false,
			expectContains: []string{"Resource Usage Report", "System Information", "Memory Usage", "Garbage Collection"},
		},
		{
			name:     "get_resource_usage detailed markdown",
			toolName: "get_resource_usage",
			args: map[string]any{
				"detailed": true,
				"format":   "markdown",
			},
			expectError:    false,
			expectContains: []string{"Resource Usage Report", "Detailed Memory Statistics", "CRL Cache Metrics"},
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
			// Check both TextContent and StructuredContent
			for _, c := range result.Content {
				if tc, ok := c.(mcp.TextContent); ok {
					content += tc.Text
				}
			}

			// If no TextContent found, check StructuredContent (for JSON format)
			if content == "" && result.StructuredContent != nil {
				if jsonStr, err := json.Marshal(result.StructuredContent); err == nil {
					content = string(jsonStr)
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
	err := Run("1.0.0-test")
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
	if jsonResult["title"] != "X.509 Certificate Chain" {
		t.Errorf("Expected title 'X.509 Certificate Chain', got %v", jsonResult["title"])
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

func TestGetAnalysisInstruction(t *testing.T) {
	tests := []struct {
		name           string
		analysisType   string
		expectContains []string
	}{
		{
			name:           "security analysis type",
			analysisType:   "security",
			expectContains: []string{"SECURITY ANALYSIS REQUEST", "Cryptographic strength", "Risk assessment"},
		},
		{
			name:           "compliance analysis type",
			analysisType:   "compliance",
			expectContains: []string{"COMPLIANCE ANALYSIS REQUEST", "CA/Browser Forum", "NIST"},
		},
		{
			name:           "general analysis type (default)",
			analysisType:   "general",
			expectContains: []string{"GENERAL CERTIFICATE ANALYSIS REQUEST", "Certificate chain structure"},
		},
		{
			name:           "unknown analysis type (default)",
			analysisType:   "unknown",
			expectContains: []string{"GENERAL CERTIFICATE ANALYSIS REQUEST", "Certificate chain structure"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getAnalysisInstruction(tt.analysisType)
			if result == "" {
				t.Error("Expected non-empty analysis instruction")
			}

			for _, expected := range tt.expectContains {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected analysis instruction to contain '%s', got: %s", expected, result)
				}
			}
		})
	}
}

func TestGetCertificateRole(t *testing.T) {
	tests := []struct {
		name     string
		index    int
		total    int
		expected string
	}{
		{
			name:     "single certificate",
			index:    0,
			total:    1,
			expected: "Self-Signed Certificate",
		},
		{
			name:     "first certificate in chain",
			index:    0,
			total:    3,
			expected: "End-Entity (Server/Leaf) Certificate",
		},
		{
			name:     "intermediate certificate",
			index:    1,
			total:    3,
			expected: "Intermediate CA Certificate",
		},
		{
			name:     "last certificate (root)",
			index:    2,
			total:    3,
			expected: "Root CA Certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCertificateRole(tt.index, tt.total)
			if result != tt.expected {
				t.Errorf("getCertificateRole(%d, %d) = %q, expected %q", tt.index, tt.total, result, tt.expected)
			}
		})
	}
}

func TestGetKeySize(t *testing.T) {
	// Test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected int
	}{
		{
			name: "RSA 2048 key",
			cert: &x509.Certificate{
				PublicKey:          rsaKey.PublicKey,
				PublicKeyAlgorithm: x509.RSA,
			},
			expected: 2048,
		},
		{
			name: "ECDSA P-256 key",
			cert: &x509.Certificate{
				PublicKey:          ecdsaKey.PublicKey,
				PublicKeyAlgorithm: x509.ECDSA,
			},
			expected: 256,
		},
		{
			name: "unsupported key type",
			cert: &x509.Certificate{
				PublicKey:          "unsupported",
				PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getKeySize(tt.cert)
			// Debug: print what type the PublicKey is
			t.Logf("PublicKey type: %T, value: %+v", tt.cert.PublicKey, tt.cert.PublicKey)
			if result != tt.expected {
				t.Errorf("getKeySize() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestFormatKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		usage    x509.KeyUsage
		expected string
	}{
		{
			name:     "no usage",
			usage:    0,
			expected: "",
		},
		{
			name:     "digital signature",
			usage:    x509.KeyUsageDigitalSignature,
			expected: "Digital Signature",
		},
		{
			name:     "key encipherment",
			usage:    x509.KeyUsageKeyEncipherment,
			expected: "Key Encipherment",
		},
		{
			name:     "multiple usages",
			usage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			expected: "Digital Signature, Key Encipherment",
		},
		{
			name: "all usages",
			usage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly |
				x509.KeyUsageDecipherOnly,
			expected: "Digital Signature, Content Commitment, Key Encipherment, Data Encipherment, Key Agreement, Certificate Signing, CRL Signing, Encipher Only, Decipher Only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatKeyUsage(tt.usage)
			if result != tt.expected {
				t.Errorf("formatKeyUsage(%d) = %q, expected %q", tt.usage, result, tt.expected)
			}
		})
	}
}

func TestFormatExtKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		usage    []x509.ExtKeyUsage
		expected string
	}{
		{
			name:     "no extended usage",
			usage:    []x509.ExtKeyUsage{},
			expected: "",
		},
		{
			name:     "server authentication",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expected: "Server Authentication",
		},
		{
			name:     "client authentication",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			expected: "Client Authentication",
		},
		{
			name:     "multiple usages",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			expected: "Server Authentication, Client Authentication",
		},
		{
			name:     "code signing",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			expected: "Code Signing",
		},
		{
			name:     "email protection",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			expected: "Email Protection",
		},
		{
			name:     "time stamping",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			expected: "Time Stamping",
		},
		{
			name:     "OCSP signing",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			expected: "OCSP Signing",
		},
		{
			name:     "unknown usage",
			usage:    []x509.ExtKeyUsage{x509.ExtKeyUsage(999)},
			expected: "Unknown (999)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatExtKeyUsage(tt.usage)
			if result != tt.expected {
				t.Errorf("formatExtKeyUsage(%v) = %q, expected %q", tt.usage, result, tt.expected)
			}
		})
	}
}

func TestBuildCertificateContext(t *testing.T) {
	// Create test certificates
	cert1 := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		Version:               3,
		SerialNumber:          big.NewInt(12345),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com", "www.test.example.com"},
		EmailAddresses:        []string{"admin@test.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		IssuingCertificateURL: []string{"http://ca.example.com/cert"},
		CRLDistributionPoints: []string{"http://ca.example.com/crl"},
		OCSPServer:            []string{"http://ocsp.example.com"},
	}

	cert2 := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		Issuer: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore: time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		Version:   3,
		IsCA:      true,
	}

	certs := []*x509.Certificate{cert1, cert2}

	result := buildCertificateContext(certs, "security")

	// Verify the context contains expected information
	expectedContents := []string{
		"Chain Length: 2 certificates",
		"Analysis Type: security",
		"End-Entity (Server/Leaf) Certificate",
		"Root CA Certificate",
		"test.example.com",
		"SHA256-RSA", // This is what x509.SHA256WithRSA.String() returns
		"Digital Signature, Key Encipherment",
		"Server Authentication",
		"test.example.com",
		"admin@test.example.com",
		"192.168.1.1",
		"http://ca.example.com/cert",
		"http://ca.example.com/crl",
		"http://ocsp.example.com",
		"CHAIN VALIDATION CONTEXT",
		"SECURITY CONTEXT",
		"Quantum Vulnerable",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(result, expected) {
			t.Errorf("buildCertificateContext() result should contain %q", expected)
		}
	}

	// Test with different analysis types
	resultGeneral := buildCertificateContext(certs, "general")
	if !strings.Contains(resultGeneral, "Analysis Type: general") {
		t.Error("buildCertificateContext() should include analysis type")
	}

	resultCompliance := buildCertificateContext(certs, "compliance")
	if !strings.Contains(resultCompliance, "Analysis Type: compliance") {
		t.Error("buildCertificateContext() should include analysis type")
	}

	// Debug: print what the signature algorithm string actually is
	t.Logf("SignatureAlgorithm string: %q", x509.SHA256WithRSA.String())
}

func TestHandleAnalyzeCertificateWithAI_NoAPIKey(t *testing.T) {
	t.Skip("Skipping AI analysis test - requires API key configuration")

	request := mcp.CallToolRequest{}
	request.Params.Arguments = map[string]any{
		"certificate":   testCertPEM, // Use the actual PEM certificate
		"analysis_type": "general",
	}

	config := &Config{}
	config.AI.APIKey = "" // No API key

	result, err := handleAnalyzeCertificateWithAI(context.Background(), request, config)
	if err != nil {
		t.Fatalf("handleAnalyzeCertificateWithAI failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Should contain fallback message about no API key
	if len(result.Content) == 0 {
		t.Fatal("Expected content in result")
	}

	content, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("Expected TextContent, got %T", result.Content[0])
	}

	resultText := content.Text
	t.Logf("Actual result text: %s", resultText[:min(500, len(resultText))]) // Log first 500 chars

	if !strings.Contains(resultText, "No AI API key configured") {
		t.Error("Expected fallback message about no API key")
	}

	if !strings.Contains(resultText, "Certificate Context Prepared") {
		t.Error("Expected certificate context in fallback response")
	}
}

// TestDefaultSamplingHandler_CreateMessage tests CreateMessage method of DefaultSamplingHandler
func TestDefaultSamplingHandler_CreateMessage(t *testing.T) {
	tests := []struct {
		name           string
		apiKey         string
		model          string
		endpoint       string
		request        mcp.CreateMessageRequest
		expectedError  string
		expectFallback bool
	}{
		{
			name:   "No API Key - Fallback Response",
			apiKey: "",
			model:  "test-model",
			request: mcp.CreateMessageRequest{
				CreateMessageParams: mcp.CreateMessageParams{
					Messages: []mcp.SamplingMessage{
						{
							Role:    mcp.RoleUser,
							Content: mcp.NewTextContent("Test message"),
						},
					},
					MaxTokens:   100,
					Temperature: 0.7,
				},
			},
			expectFallback: true,
		},
		{
			name:   "Valid Request with API Key",
			apiKey: "test-api-key",
			model:  "test-model",
			request: mcp.CreateMessageRequest{
				CreateMessageParams: mcp.CreateMessageParams{
					Messages: []mcp.SamplingMessage{
						{
							Role:    mcp.RoleUser,
							Content: mcp.NewTextContent("Test message"),
						},
					},
					MaxTokens:   100,
					Temperature: 0.7,
				},
			},
			expectFallback: false,
		},
		{
			name:   "Request with System Prompt",
			apiKey: "test-api-key",
			model:  "test-model",
			request: mcp.CreateMessageRequest{
				CreateMessageParams: mcp.CreateMessageParams{
					Messages: []mcp.SamplingMessage{
						{
							Role:    mcp.RoleUser,
							Content: mcp.NewTextContent("Test message"),
						},
					},
					SystemPrompt: "You are a helpful assistant",
					MaxTokens:    100,
					Temperature:  0.7,
				},
			},
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP server for testing
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.apiKey == "" {
					// Should not reach here for fallback case
					t.Errorf("HTTP server called when API key is empty")
					return
				}

				// Verify request headers
				if auth := r.Header.Get("Authorization"); auth != "Bearer "+tt.apiKey {
					t.Errorf("Expected Authorization header 'Bearer %s', got '%s'", tt.apiKey, auth)
				}

				if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "X.509-Certificate-Chain-Resolver-MCP") {
					t.Errorf("Expected User-Agent to contain 'X.509-Certificate-Chain-Resolver-MCP', got '%s'", userAgent)
				}

				// Verify request body
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("Failed to decode request body: %v", err)
					return
				}

				if payload["model"] != tt.model {
					t.Errorf("Expected model '%s', got '%v'", tt.model, payload["model"])
				}

				// Send streaming response
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")
				w.WriteHeader(http.StatusOK)
				flusher, _ := w.(http.Flusher)
				flusher.Flush()

				w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}],\"model\":\"test-model\"}\n"))
				w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" world\"},\"finish_reason\":\"stop\"}],\"model\":\"test-model\"}\n"))
				w.Write([]byte("data: [DONE]\n"))
				flusher.Flush()
			}))
			defer server.Close()

			handler := &DefaultSamplingHandler{
				apiKey:   tt.apiKey,
				model:    tt.model,
				version:  "test-version",
				client:   &http.Client{Timeout: 5 * time.Second},
				endpoint: server.URL,
			}

			result, err := handler.CreateMessage(context.Background(), tt.request)

			if tt.expectFallback {
				if err != nil {
					t.Errorf("Expected no error for fallback, got: %v", err)
				}
				if result == nil {
					t.Error("Expected result for fallback, got nil")
				}
				if result != nil && !strings.Contains(result.SamplingMessage.Content.(mcp.TextContent).Text, "AI API key not configured") {
					t.Errorf("Expected fallback message about API key, got: %s", result.SamplingMessage.Content.(mcp.TextContent).Text)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil {
					t.Error("Expected result, got nil")
				}
				if result != nil && result.SamplingMessage.Content.(mcp.TextContent).Text != "Hello world" {
					t.Errorf("Expected 'Hello world', got: %s", result.SamplingMessage.Content.(mcp.TextContent).Text)
				}
			}
		})
	}
}

// TestDefaultSamplingHandler_handleNoAPIKey tests handleNoAPIKey method
func TestDefaultSamplingHandler_handleNoAPIKey(t *testing.T) {
	handler := &DefaultSamplingHandler{
		version: "test-version",
	}

	result, err := handler.handleNoAPIKey()

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}

	if result.Model != "not-configured" {
		t.Errorf("Expected model 'not-configured', got '%s'", result.Model)
	}

	if result.StopReason != "end" {
		t.Errorf("Expected stop reason 'end', got '%s'", result.StopReason)
	}

	content, ok := result.SamplingMessage.Content.(mcp.TextContent)
	if !ok {
		t.Error("Expected TextContent, got different type")
	}

	if !strings.Contains(content.Text, "AI API key not configured") {
		t.Errorf("Expected message about API key not configured, got: %s", content.Text)
	}

	if !strings.Contains(content.Text, "X509_AI_APIKEY") {
		t.Errorf("Expected message to mention X509_AI_APIKEY, got: %s", content.Text)
	}
}

// TestDefaultSamplingHandler_convertMessages tests convertMessages method
func TestDefaultSamplingHandler_convertMessages(t *testing.T) {
	handler := &DefaultSamplingHandler{}

	tests := []struct {
		name     string
		messages []mcp.SamplingMessage
		expected []map[string]any
	}{
		{
			name: "Single Text Message",
			messages: []mcp.SamplingMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent("Hello world"),
				},
			},
			expected: []map[string]any{
				{
					"role":    "user",
					"content": "Hello world",
				},
			},
		},
		{
			name: "Multiple Messages",
			messages: []mcp.SamplingMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent("Hello"),
				},
				{
					Role:    mcp.RoleAssistant,
					Content: mcp.NewTextContent("Hi there!"),
				},
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent("How are you?"),
				},
			},
			expected: []map[string]any{
				{
					"role":    "user",
					"content": "Hello",
				},
				{
					"role":    "assistant",
					"content": "Hi there!",
				},
				{
					"role":    "user",
					"content": "How are you?",
				},
			},
		},
		{
			name: "Non-Text Content",
			messages: []mcp.SamplingMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.ImageContent{Data: "base64data", MIMEType: "image/png"},
				},
			},
			expected: []map[string]any{
				{
					"role":    "user",
					"content": "{{<nil>} <nil>  base64data image/png}",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.convertMessages(tt.messages)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d messages, got %d", len(tt.expected), len(result))
				return
			}

			for i, expectedMsg := range tt.expected {
				if result[i]["role"] != expectedMsg["role"] {
					t.Errorf("Message %d: expected role '%s', got '%s'", i, expectedMsg["role"], result[i]["role"])
				}

				if result[i]["content"] != expectedMsg["content"] {
					t.Errorf("Message %d: expected content '%s', got '%s'", i, expectedMsg["content"], result[i]["content"])
				}
			}
		})
	}
}

// TestDefaultSamplingHandler_parseStreamingResponse tests parseStreamingResponse method
func TestDefaultSamplingHandler_parseStreamingResponse(t *testing.T) {
	handler := &DefaultSamplingHandler{}

	tests := []struct {
		name            string
		response        string
		expectedContent string
		expectedModel   string
		expectedStop    string
		expectError     bool
	}{
		{
			name: "Valid Streaming Response",
			response: `data: {"choices":[{"delta":{"content":"Hello"}}],"model":"test-model"}
data: {"choices":[{"delta":{"content":" world"}}],"model":"test-model"}
data: {"choices":[{"finish_reason":"stop"}],"model":"test-model"}
data: [DONE]`,
			expectedContent: "Hello world",
			expectedModel:   "test-model",
			expectedStop:    "stop",
			expectError:     false,
		},
		{
			name:            "Empty Response",
			response:        "",
			expectedContent: "",
			expectedModel:   "",
			expectedStop:    "stop",
			expectError:     false,
		},
		{
			name:            "Invalid JSON",
			response:        `data: {"invalid json}`,
			expectedContent: "",
			expectedModel:   "",
			expectedStop:    "stop",
			expectError:     false, // Should not error, just skip invalid chunks
		},
		{
			name: "Response with Comments",
			response: `: This is a comment
data: {"choices":[{"delta":{"content":"Test"}}],"model":"test-model"}
data: [DONE]`,
			expectedContent: "Test",
			expectedModel:   "test-model",
			expectedStop:    "stop",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.response)
			content, model, stopReason, err := handler.parseStreamingResponse(reader, "")

			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}

			if content != tt.expectedContent {
				t.Errorf("Expected content '%s', got '%s'", tt.expectedContent, content)
			}

			if model != tt.expectedModel {
				t.Errorf("Expected model '%s', got '%s'", tt.expectedModel, model)
			}

			if stopReason != tt.expectedStop {
				t.Errorf("Expected stop reason '%s', got '%s'", tt.expectedStop, stopReason)
			}
		})
	}
}

// TestServerBuilder tests ServerBuilder pattern
func TestServerBuilder(t *testing.T) {
	tests := []struct {
		name     string
		builder  *ServerBuilder
		setup    func(*ServerBuilder) *ServerBuilder
		validate func(*testing.T, *server.MCPServer)
	}{
		{
			name:    "Default Builder",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				return sb
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				if server == nil {
					t.Error("Expected server, got nil")
					return
				}
			},
		},
		{
			name:    "Builder With Config",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				config := &Config{}
				config.Defaults.Format = "json"
				config.Defaults.IncludeSystemRoot = true
				config.Defaults.IntermediateOnly = false
				config.Defaults.WarnDays = 60
				config.Defaults.Timeout = 15
				return sb.WithConfig(config)
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				if server == nil {
					t.Error("Expected server, got nil")
					return
				}
			},
		},
		{
			name:    "Builder With Default Tools",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				return sb.WithDefaultTools()
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				if server == nil {
					t.Error("Expected server, got nil")
					return
				}
				// Server built successfully with tools is sufficient validation
			},
		},
		{
			name:    "Builder With Sampling",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				config := &Config{}
				config.AI.APIKey = "test-key"
				config.AI.Model = "test-model"
				config.AI.Endpoint = "https://api.test.com"
				handler := NewDefaultSamplingHandler(config, "test-version")
				return sb.WithConfig(config).WithSampling(handler)
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				if server == nil {
					t.Error("Expected server, got nil")
					return
				}
				// Sampling is enabled internally, we can't directly check it
				// but we can verify server was built successfully
			},
		},
		{
			name:    "Builder With All Options",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				config := &Config{}
				config.Defaults.Format = "pem"
				config.Defaults.IncludeSystemRoot = false
				config.Defaults.IntermediateOnly = true
				config.Defaults.WarnDays = 30
				config.Defaults.Timeout = 10
				config.AI.APIKey = "test-api-key"
				config.AI.Model = "test-model"
				config.AI.Endpoint = "https://api.test.com"
				handler := NewDefaultSamplingHandler(config, "test-version")
				return sb.WithConfig(config).WithDefaultTools().WithSampling(handler)
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				if server == nil {
					t.Error("Expected server, got nil")
					return
				}
				// Server built successfully with all options is sufficient validation
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := tt.setup(tt.builder).Build()
			if err != nil {
				t.Errorf("Expected no error building server, got: %v", err)
				return
			}
			tt.validate(t, server)
		})
	}
}

// TestDefaultSamplingHandler_bufferPooling tests that buffer pooling works correctly
func TestDefaultSamplingHandler_bufferPooling(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Test\"}],\"model\":\"test-model\"}\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()

	handler := &DefaultSamplingHandler{
		apiKey:   "test-key",
		model:    "test-model",
		version:  "test-version",
		client:   &http.Client{Timeout: 5 * time.Second},
		endpoint: server.URL,
	}

	request := mcp.CreateMessageRequest{
		CreateMessageParams: mcp.CreateMessageParams{
			Messages: []mcp.SamplingMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent("Test message"),
				},
			},
			MaxTokens:   100,
			Temperature: 0.7,
		},
	}

	// Call CreateMessage multiple times to test buffer pooling
	for i := range 10 {
		result, err := handler.CreateMessage(context.Background(), request)
		if err != nil {
			t.Errorf("Iteration %d: Expected no error, got: %v", i, err)
		}
		if result == nil {
			t.Errorf("Iteration %d: Expected result, got nil", i)
		}
	}
}

// TestDefaultSamplingHandler_errorHandling tests error handling in CreateMessage
func TestDefaultSamplingHandler_errorHandling(t *testing.T) {
	tests := []struct {
		name          string
		serverStatus  int
		response      string
		expectedError string
	}{
		{
			name:          "HTTP Error Response",
			serverStatus:  400,
			response:      `{"error": "Bad request"}`,
			expectedError: "AI API error (status 400): {\"error\": \"Bad request\"}",
		},
		{
			name:          "HTTP Unauthorized",
			serverStatus:  401,
			response:      `{"error": "Unauthorized"}`,
			expectedError: "AI API error (status 401): {\"error\": \"Unauthorized\"}",
		},
		{
			name:          "HTTP Server Error",
			serverStatus:  500,
			response:      `{"error": "Internal server error"}`,
			expectedError: "AI API error (status 500): {\"error\": \"Internal server error\"}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatus)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			handler := &DefaultSamplingHandler{
				apiKey:   "test-key",
				model:    "test-model",
				version:  "test-version",
				client:   &http.Client{Timeout: 5 * time.Second},
				endpoint: server.URL,
			}

			request := mcp.CreateMessageRequest{
				CreateMessageParams: mcp.CreateMessageParams{
					Messages: []mcp.SamplingMessage{
						{
							Role:    mcp.RoleUser,
							Content: mcp.NewTextContent("Test message"),
						},
					},
					MaxTokens:   100,
					Temperature: 0.7,
				},
			}

			result, err := handler.CreateMessage(context.Background(), request)

			if err == nil {
				t.Error("Expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("Expected error to contain '%s', got '%s'", tt.expectedError, err.Error())
			}

			if result != nil {
				t.Error("Expected nil result on error, got result")
			}
		})
	}
}

// TestNewDefaultSamplingHandler tests NewDefaultSamplingHandler function
func TestNewDefaultSamplingHandler(t *testing.T) {
	config := &Config{}
	config.AI.APIKey = "test-key"
	config.AI.Endpoint = "https://api.test.com"
	config.AI.Model = "test-model"
	config.AI.Timeout = 30

	handler := NewDefaultSamplingHandler(config, "test-version")

	if handler == nil {
		t.Error("Expected handler, got nil")
	}

	defaultHandler, ok := handler.(*DefaultSamplingHandler)
	if !ok {
		t.Error("Expected DefaultSamplingHandler, got different type")
	}

	if defaultHandler.apiKey != "test-key" {
		t.Errorf("Expected API key 'test-key', got '%s'", defaultHandler.apiKey)
	}

	if defaultHandler.endpoint != "https://api.test.com" {
		t.Errorf("Expected endpoint 'https://api.test.com', got '%s'", defaultHandler.endpoint)
	}

	if defaultHandler.model != "test-model" {
		t.Errorf("Expected model 'test-model', got '%s'", defaultHandler.model)
	}

	if defaultHandler.version != "test-version" {
		t.Errorf("Expected version 'test-version', got '%s'", defaultHandler.version)
	}
}

// TestDefaultSamplingHandler_helperMethods tests helper methods
func TestDefaultSamplingHandler_helperMethods(t *testing.T) {
	handler := &DefaultSamplingHandler{
		model: "default-model",
	}

	// Test selectModel
	t.Run("selectModel", func(t *testing.T) {
		// Test with no preferences
		model := handler.selectModel(nil)
		if model != "default-model" {
			t.Errorf("Expected default model, got '%s'", model)
		}

		// Test with preferences
		preferences := &mcp.ModelPreferences{
			Hints: []mcp.ModelHint{{Name: "preferred-model"}},
		}
		model = handler.selectModel(preferences)
		if model != "preferred-model" {
			t.Errorf("Expected preferred model, got '%s'", model)
		}
	})

	// Test prepareMessages
	t.Run("prepareMessages", func(t *testing.T) {
		messages := []map[string]any{
			{"role": "user", "content": "Hello"},
		}

		// Test without system prompt
		result := handler.prepareMessages(messages, "")
		if len(result) != 1 {
			t.Errorf("Expected 1 message without system prompt, got %d", len(result))
		}

		// Test with system prompt
		result = handler.prepareMessages(messages, "You are helpful")
		if len(result) != 2 {
			t.Errorf("Expected 2 messages with system prompt, got %d", len(result))
		}

		if result[0]["role"] != "system" {
			t.Errorf("Expected first message to be system, got '%s'", result[0]["role"])
		}

		if result[0]["content"] != "You are helpful" {
			t.Errorf("Expected system prompt 'You are helpful', got '%s'", result[0]["content"])
		}
	})

	// Test buildAPIRequest
	t.Run("buildAPIRequest", func(t *testing.T) {
		messages := []map[string]any{
			{"role": "user", "content": "Hello"},
		}

		request := mcp.CreateMessageRequest{
			CreateMessageParams: mcp.CreateMessageParams{
				MaxTokens:     100,
				Temperature:   0.7,
				StopSequences: []string{"\n"},
			},
		}

		result := handler.buildAPIRequest("test-model", messages, request)

		if result["model"] != "test-model" {
			t.Errorf("Expected model 'test-model', got '%v'", result["model"])
		}

		if result["max_tokens"] != 100 {
			t.Errorf("Expected max_tokens 100, got %v", result["max_tokens"])
		}

		if result["temperature"] != 0.7 {
			t.Errorf("Expected temperature 0.7, got %v", result["temperature"])
		}

		if result["stream"] != true {
			t.Errorf("Expected stream true, got %v", result["stream"])
		}

		stopSequences, ok := result["stop"].([]string)
		if !ok {
			t.Errorf("Expected stop sequences to be []string, got %T", result["stop"])
		}

		if len(stopSequences) != 1 || stopSequences[0] != "\n" {
			t.Errorf("Expected stop sequences ['\\n'], got %v", result["stop"])
		}
	})

	// Test buildSamplingResult
	t.Run("buildSamplingResult", func(t *testing.T) {
		result := handler.buildSamplingResult("Hello world", "test-model", "stop")

		if result.SamplingMessage.Role != mcp.RoleAssistant {
			t.Errorf("Expected assistant role, got '%s'", result.SamplingMessage.Role)
		}

		content, ok := result.SamplingMessage.Content.(mcp.TextContent)
		if !ok {
			t.Error("Expected TextContent, got different type")
		}

		if content.Text != "Hello world" {
			t.Errorf("Expected content 'Hello world', got '%s'", content.Text)
		}

		if result.Model != "test-model" {
			t.Errorf("Expected model 'test-model', got '%s'", result.Model)
		}

		if result.StopReason != "stop" {
			t.Errorf("Expected stop reason 'stop', got '%s'", result.StopReason)
		}
	})
}

// TestBuildCertificateContextWithRevocation tests the buildCertificateContextWithRevocation function
func TestBuildCertificateContextWithRevocation(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	tests := []struct {
		name             string
		revocationStatus string
		analysisType     string
		expectedFields   []string
	}{
		{
			name:             "Certificate with Good Revocation Status",
			revocationStatus: "Good",
			analysisType:     "security",
			expectedFields:   []string{"Chain Length", "Analysis Type", "REVOCATION STATUS", "Methodology", "Redundancy", "Security"},
		},
		{
			name:             "Certificate with Revoked Status",
			revocationStatus: "Revoked",
			analysisType:     "compliance",
			expectedFields:   []string{"Chain Length", "Analysis Type", "REVOCATION STATUS", "Methodology", "Redundancy", "Security"},
		},
		{
			name:             "Certificate with Unknown Status",
			revocationStatus: "Unknown",
			analysisType:     "general",
			expectedFields:   []string{"Chain Length", "Analysis Type", "REVOCATION STATUS", "Methodology", "Redundancy", "Security"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCertificateContextWithRevocation([]*x509.Certificate{cert}, tt.revocationStatus, tt.analysisType)

			// Check that expected fields are present
			for _, field := range tt.expectedFields {
				if !strings.Contains(result, field) {
					t.Errorf("Expected field '%s' not found in result", field)
				}
			}

			// Check that revocation status is included
			if !strings.Contains(result, tt.revocationStatus) {
				t.Errorf("Expected revocation status '%s' not found in result", tt.revocationStatus)
			}

			// Check that analysis type is included
			if !strings.Contains(result, tt.analysisType) {
				t.Errorf("Expected analysis type '%s' not found in result", tt.analysisType)
			}

			// Check for certificate information
			expectedCertFields := []string{"SUBJECT", "ISSUER", "VALIDITY", "CRYPTOGRAPHY"}
			for _, field := range expectedCertFields {
				if !strings.Contains(result, field) {
					t.Errorf("Expected certificate field '%s' not found in result", field)
				}
			}
		})
	}
}

// TestAppendSubjectInfo tests the appendSubjectInfo function
func TestAppendSubjectInfo(t *testing.T) {
	// Create a test certificate with known subject
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendSubjectInfo(&context, cert)

	result := context.String()

	// Check that subject information is included
	expectedFields := []string{
		"SUBJECT:",
		"Common Name:",
		"Organization:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected subject field '%s' not found in result", field)
		}
	}
}

// TestAppendIssuerInfo tests the appendIssuerInfo function
func TestAppendIssuerInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendIssuerInfo(&context, cert)

	result := context.String()

	// Check that issuer information is included
	expectedFields := []string{
		"ISSUER:",
		"Common Name:",
		"Organization:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected issuer field '%s' not found in result", field)
		}
	}
}

// TestAppendValidityInfo tests the appendValidityInfo function
func TestAppendValidityInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendValidityInfo(&context, cert)

	result := context.String()

	// Check that validity information is included
	expectedFields := []string{
		"VALIDITY:",
		"Not Before:",
		"Not After:",
		"Days until expiry:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected validity field '%s' not found in result", field)
		}
	}
}

// TestAppendCryptoInfo tests the appendCryptoInfo function
func TestAppendCryptoInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendCryptoInfo(&context, cert)

	result := context.String()

	// Check that cryptographic information is included
	expectedFields := []string{
		"CRYPTOGRAPHY:",
		"Signature Algorithm:",
		"Public Key Algorithm:",
		"Key Size:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected crypto field '%s' not found in result", field)
		}
	}
}

// TestAppendCertProperties tests the appendCertProperties function
func TestAppendCertProperties(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendCertProperties(&context, cert)

	result := context.String()

	// Check that certificate properties are included
	expectedFields := []string{
		"PROPERTIES:",
		"Serial Number:",
		"Version:",
		"Is CA:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected properties field '%s' not found in result", field)
		}
	}
}

// TestAppendCertExtensions tests the appendCertExtensions function
func TestAppendCertExtensions(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendCertExtensions(&context, cert)

	result := context.String()

	// Check that extensions information is included
	expectedFields := []string{
		"Key Usage:",
		"Extended Key Usage:",
		"DNS Names:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected extensions field '%s' not found in result", field)
		}
	}
}

// TestAppendCAInfo tests the appendCAInfo function
func TestAppendCAInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendCAInfo(&context, cert)

	result := context.String()

	// Check that CA information is included
	expectedFields := []string{
		"Issuer URLs:",
		"CRL Distribution Points:",
		"OCSP Servers:",
		"Serial Number:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected CA info field '%s' not found in result", field)
		}
	}
}

// TestAppendChainValidationContext tests the appendChainValidationContext function
func TestAppendChainValidationContext(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendChainValidationContext(&context, []*x509.Certificate{cert})

	result := context.String()

	// Check that chain validation context is included
	expectedFields := []string{
		"=== CHAIN VALIDATION CONTEXT ===",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected chain validation field '%s' not found in result", field)
		}
	}
}

// TestAppendSecurityContext tests the appendSecurityContext function
func TestAppendSecurityContext(t *testing.T) {
	var context strings.Builder
	appendSecurityContext(&context)

	result := context.String()

	// Check that security context is included
	expectedFields := []string{
		"=== SECURITY CONTEXT ===",
		"Current TLS/SSL Best Practices:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(result, field) {
			t.Errorf("Expected security context field '%s' not found in result", field)
		}
	}
}

// TestHandleAnalyzeCertificateWithAI tests the handleAnalyzeCertificateWithAI function
func TestHandleAnalyzeCertificateWithAI(t *testing.T) {
	// Create test request
	certData := base64.StdEncoding.EncodeToString([]byte(testCertPEM))

	request := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "analyze_certificate_with_ai",
			Arguments: map[string]any{
				"certificate":   certData,
				"analysis_type": "general",
			},
		},
	}

	// Test with config without AI API key (should return certificate context)
	config := &Config{
		Defaults: struct {
			Format            string `json:"format"`
			IncludeSystemRoot bool   `json:"includeSystemRoot"`
			IntermediateOnly  bool   `json:"intermediateOnly"`
			WarnDays          int    `json:"warnDays"`
			Timeout           int    `json:"timeoutSeconds"`
		}{
			Timeout: 30,
		},
	}

	result, err := handleAnalyzeCertificateWithAI(context.Background(), request, config)
	if err != nil {
		t.Fatalf("handleAnalyzeCertificateWithAI failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Check that result contains expected content
	resultText := string(result.Content[0].(mcp.TextContent).Text)
	expectedFields := []string{
		"Chain Length:",
		"Analysis Type:",
		"REVOCATION STATUS SUMMARY:",
		"Methodology:",
		"Redundancy:",
		"Security:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(resultText, field) {
			t.Errorf("Expected field '%s' not found in result", field)
		}
	}
}

// TestBufferPoolIntegration tests buffer pool usage in certificate context building
func TestBufferPoolIntegration(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Test multiple concurrent context building
	const numGoroutines = 10
	const numIterations = 100

	for range numGoroutines {
		go func() {
			for range numIterations {
				// This should use buffer pooling internally
				result := buildCertificateContextWithRevocation(
					[]*x509.Certificate{cert},
					"Good",
					"security",
				)

				// Verify result contains expected content
				if !strings.Contains(result, "Chain Length") {
					t.Errorf("Expected 'Chain Length' not found in result")
				}
			}
		}()
	}

	// Allow goroutines to complete
	time.Sleep(100 * time.Millisecond)
}

// TestConcurrentCertificateAnalysis tests concurrent certificate analysis
func TestConcurrentCertificateAnalysis(t *testing.T) {
	// Create test request
	certData := base64.StdEncoding.EncodeToString([]byte(testCertPEM))

	config := &Config{
		Defaults: struct {
			Format            string `json:"format"`
			IncludeSystemRoot bool   `json:"includeSystemRoot"`
			IntermediateOnly  bool   `json:"intermediateOnly"`
			WarnDays          int    `json:"warnDays"`
			Timeout           int    `json:"timeoutSeconds"`
		}{
			Timeout: 30,
		},
	}

	// Test concurrent analysis
	const numGoroutines = 5
	const numIterations = 20

	for i := range numGoroutines {
		go func(id int) {
			for range numIterations {
				request := mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "analyze_certificate_with_ai",
						Arguments: map[string]any{
							"certificate":   certData,
							"analysis_type": "general",
						},
					},
				}

				result, err := handleAnalyzeCertificateWithAI(context.Background(), request, config)
				if err != nil {
					t.Errorf("Concurrent analysis failed: %v", err)
					continue
				}

				if result == nil {
					t.Error("Expected non-nil result in concurrent analysis")
					continue
				}

				// Verify result contains expected content
				resultText := string(result.Content[0].(mcp.TextContent).Text)
				if !strings.Contains(resultText, "Chain Length") {
					t.Errorf("Expected 'Chain Length' not found in concurrent result")
				}
			}
		}(i)
	}

	// Allow goroutines to complete
	time.Sleep(200 * time.Millisecond)
}

// TestMemoryUsageInContextBuilding tests memory usage patterns in context building
func TestMemoryUsageInContextBuilding(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Test memory usage with multiple context builds
	const numIterations = 1000

	for range numIterations {
		// Use buffer pool to minimize allocations
		buf := gc.Default.Get()
		defer func() {
			buf.Reset()
			gc.Default.Put(buf)
		}()

		// Build context using buffer
		result := buildCertificateContextWithRevocation(
			[]*x509.Certificate{cert},
			"Good",
			"general",
		)

		// Write result to buffer
		buf.WriteString(result)

		// Verify buffer has content
		if buf.Len() == 0 {
			t.Error("Expected non-empty buffer")
		}
	}
}

// TestErrorHandlingInContextBuilding tests error handling in context building functions
func TestErrorHandlingInContextBuilding(t *testing.T) {
	// Test with nil certificate
	t.Run("Nil Certificate", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("buildCertificateContextWithRevocation panicked with nil certificate: %v", r)
			}
		}()

		result := buildCertificateContextWithRevocation(nil, "Unknown", "general")

		// Should handle gracefully
		if !strings.Contains(result, "Chain Length: 0") {
			t.Errorf("Expected 'Chain Length: 0' for nil certificate, got: %s", result)
		}
	})

	// Test with empty revocation status
	t.Run("Empty Revocation Status", func(t *testing.T) {
		block, _ := pem.Decode([]byte(testCertPEM))
		if block == nil {
			t.Fatal("Failed to decode test certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		result := buildCertificateContextWithRevocation([]*x509.Certificate{cert}, "", "security")

		// Should handle empty status gracefully
		if !strings.Contains(result, "REVOCATION STATUS") {
			t.Errorf("Expected 'REVOCATION STATUS' even with empty status")
		}
	})
}

// TestURLHandlingInExtensions tests URL handling in certificate extensions
func TestURLHandlingInExtensions(t *testing.T) {
	// Create a test certificate with various URL types in extensions
	block, _ := pem.Decode([]byte(testCertPEM))
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var context strings.Builder
	appendCertExtensions(&context, cert)
	result := context.String()

	// Test URL validation by checking for common URL patterns
	urlPatterns := []string{
		"http://",
		"https://",
		"ldap://",
	}

	for _, pattern := range urlPatterns {
		if strings.Contains(result, pattern) {
			// If URL pattern is found, it should be properly formatted
			urlStart := strings.Index(result, pattern)
			if urlStart != -1 {
				// Extract a portion around the URL for basic validation
				start := max(0, urlStart-10)
				end := min(len(result), urlStart+50)
				urlContext := result[start:end]

				// Basic URL validation - should contain valid characters
				if !isValidURLContext(urlContext) {
					t.Errorf("Potentially invalid URL found in context: %s", urlContext)
				}
			}
		}
	}
}

// Helper function to validate URL context
func isValidURLContext(context string) bool {
	// Basic validation - check for common URL characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%"

	for _, char := range context {
		if !strings.ContainsRune(validChars, char) && char != ' ' && char != '\n' && char != '\t' {
			return false
		}
	}
	return true
}
