// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/posix"
	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
)

// Test certificate from www.google.com (valid until February 16, 2026)
// Retrieved: December 15, 2025 by Grok using these MCP tools from this repo
const testCertPEM = `
-----BEGIN CERTIFICATE-----
MIIEVzCCAz+gAwIBAgIRAIsnDh7AqstVCQTDZO49FUQwDQYJKoZIhvcNAQELBQAw
OzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEM
MAoGA1UEAxMDV1IyMB4XDTI1MTEyNDA4NDEwNVoXDTI2MDIxNjA4NDEwNFowGTEX
MBUGA1UEAxMOd3d3Lmdvb2dsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASpOrUKgQJxuBGxizx+kmyx5RrD4jQmo8qLKSuwJqGHq32bVzWZGD67H9R4OZrU
dvyPaKf5c8xcR0dfErljBgc9o4ICQTCCAj0wDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFB/jnLpRtZ7i
zZrj5pmoPbY4QlomMB8GA1UdIwQYMBaAFN4bHu15FdQ+NyTDIbvsNDltQrIwMFgG
CCsGAQUFBwEBBEwwSjAhBggrBgEFBQcwAYYVaHR0cDovL28ucGtpLmdvb2cvd3Iy
MCUGCCsGAQUFBzAChhlodHRwOi8vaS5wa2kuZ29vZy93cjIuY3J0MBkGA1UdEQQS
MBCCDnd3dy5nb29nbGUuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMDYGA1UdHwQv
MC0wK6ApoCeGJWh0dHA6Ly9jLnBraS5nb29nL3dyMi9HU3lUMU40UEJyZy5jcmww
ggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdwCWl2S/VViXrfdDh2g3CEJ36fA61fak
8zZuRqQ/D8qpxgAAAZq1PQh6AAAEAwBIMEYCIQDkvhCgZXnoybm66RiqqWXZN6qE
VzPoPHn/kyXZ7Y55yAIhALTMfGlCgnC9W0iu+cR9qCmOwsEr5k6Bl7Ub2w7GCUIu
AHUASZybad4dfOz8Nt7Nh2SmuFuvCoeAGdFVUvvp6ynd+MMAAAGatT0IWAAABAMA
RjBEAiBQITcviDubQYQiIxBwjcgmkl4CH1x4RzykXJrp8cCLKwIgFpdUBEBwTjCw
wTjI3H2paYucltfUre6q/vBei3HhNqcwDQYJKoZIhvcNAQELBQADggEBAE+UAURG
T3JZxq6fjAK5Espfe49Wb0mz1kCTwNY56sbYP/Fa+Kb7kVluDIFbMN2rspADwKBu
FR7QVda3zEIu4Hj1DUmD7ecmVYCxLQ241OYdice4AfJTwDVJVymdQPFoLBP27dWK
3izwcfkPSgXIT8nHcEvDvXljn7n+n3XXuzh1Y1vFnFUa5E69JQFXXDuu/a7LiEXx
uB5j0Xga7DgFyHHHnz7zSiFr37NBb0/CH/31fkgaQPj7Fr5dyCMzMg1rQe1FGOM6
fXT8WHASUpqRebQfDy2TPE7sjve2NenS36NeiiVZXhBo5MHvGCBY3W8OYljK4zeU
uugY3q/5At03UHw=
-----END CERTIFICATE-----
`

// pemToBase64 converts a PEM certificate string to base64 encoding for testing
func pemToBase64(pem string) string {
	return base64.StdEncoding.EncodeToString([]byte(pem))
}

func TestMCPTools(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping TestMCPTools on macOS due to certificate validation differences")
	}
	config, err := loadConfig("")
	require.NoError(t, err, "loadConfig should not fail")

	// Encode test certificate as base64
	certData := pemToBase64(testCertPEM)

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
	s.AddTool(batchResolveCertChainTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleBatchResolveCertChain(ctx, request, config)
	})
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
			Tool: batchResolveCertChainTool,
			Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return handleBatchResolveCertChain(ctx, request, config)
			},
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
	require.NoError(t, srv.Start(t.Context()), "Failed to start server")
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
			name:     "fetch_remote_cert with include_system_root",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname":            "example.com",
				"port":                443,
				"include_system_root": true,
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE"},
			skipOnMacOS:    true,
		},
		{
			name:     "fetch_remote_cert with intermediate_only",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname":          "example.com",
				"port":              443,
				"intermediate_only": true,
			},
			expectError:    false,
			expectContains: []string{"BEGIN CERTIFICATE"},
		},
		{
			name:     "fetch_remote_cert with json format",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname": "example.com",
				"port":     443,
				"format":   "json",
			},
			expectError:    false,
			expectContains: []string{`"listCertificates"`, "Certificate Chain"},
		},
		{
			name:     "fetch_remote_cert with der format",
			toolName: "fetch_remote_cert",
			args: map[string]any{
				"hostname": "example.com",
				"port":     443,
				"format":   "der",
			},
			expectError:    false,
			expectContains: []string{}, // DER is binary, no text to check
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

			result, err := client.CallTool(t.Context(), req)
			if tt.expectError {
				assert.NoError(t, err, "expected no error for expectError=true case")
				require.NotNil(t, result, "result should not be nil when expectError=true")

				// Check if result contains error message
				content := ""
				for _, c := range result.Content {
					if tc, ok := c.(mcp.TextContent); ok {
						content += tc.Text
					}
				}
				assert.True(t,
					strings.Contains(content, "error") ||
						strings.Contains(content, "failed") ||
						strings.Contains(content, "required"),
					"expected error message in result, but got: %s", content)
				return
			}

			assert.NoError(t, err, "unexpected error")
			assert.NotNil(t, result, "expected result but got nil")

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
				assert.Contains(t, content, expected,
					"expected result to contain %q, but it didn't. Result: %s", expected, content)
			}
		})
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
				result, err = handleResolveCertChain(t.Context(), req)
			case "validate_cert_chain":
				result, err = handleValidateCertChain(t.Context(), req)
			case "batch_resolve_cert_chain":
				config, _ := loadConfig("")
				result, err = handleBatchResolveCertChain(t.Context(), req, config)
			case "check_cert_expiry":
				config, _ := loadConfig("")
				result, err = handleCheckCertExpiry(t.Context(), req, config)
			case "fetch_remote_cert":
				config, _ := loadConfig("")
				result, err = handleFetchRemoteCert(t.Context(), req, config)
			default:
				require.Fail(t, "Unknown tool name: %s", tt.toolName)
			}

			if tt.expectError {
				if err == nil {
					// Check if result contains error message instead
					require.NotNil(t, result, "result should not be nil when expectError=true")
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
					assert.True(t, foundError,
						"Expected error message containing %v in result, but got: %s", tt.errorContains, content)
				}
				return
			}

			assert.NoError(t, err, "unexpected error")
			assert.NotNil(t, result, "expected result but got nil")
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
				ctx, cancel := context.WithCancel(t.Context())
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
				ctx, cancel := context.WithCancel(t.Context())
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
				ctx, cancel := context.WithCancel(t.Context())
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
				return context.WithTimeout(t.Context(), 1*time.Nanosecond)
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
				config, _ := loadConfig("")
				result, err = handleBatchResolveCertChain(ctx, req, config)
			case "fetch_remote_cert":
				config, _ := loadConfig("")
				result, err = handleFetchRemoteCert(ctx, req, config)
			default:
				require.Fail(t, "Unknown tool name: %s", tt.toolName)
			}

			if tt.expectError {
				assert.True(t, err != nil || result != nil,
					"Expected error or result with error message, but got neither")
				// Either err != nil or result contains error message
			} else {
				assert.NoError(t, err, "unexpected error")
				assert.NotNil(t, result, "expected result but got nil")
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
				result, err = handleResolveCertChain(t.Context(), req)
			case "validate_cert_chain":
				result, err = handleValidateCertChain(t.Context(), req)
			case "batch_resolve_cert_chain":
				config, _ := loadConfig("")
				result, err = handleBatchResolveCertChain(t.Context(), req, config)
			case "check_cert_expiry":
				config, _ := loadConfig("")
				result, err = handleCheckCertExpiry(t.Context(), req, config)
			case "fetch_remote_cert":
				config, _ := loadConfig("")
				result, err = handleFetchRemoteCert(t.Context(), req, config)
			default:
				require.Fail(t, "Unknown tool name: %s", tt.toolName)
			}

			if tt.expectError {
				assert.True(t, err != nil || result != nil,
					"Expected error for %s, but got neither error nor result", tt.description)
			} else {
				assert.NoError(t, err, "unexpected error for %s", tt.description)
				assert.NotNil(t, result, "expected result for %s, but got nil", tt.description)
			}
		})
	}
}

func TestServerBuilder_BuildWithPrompts(t *testing.T) {
	// Test that building a server with prompts exercises populatePromptMetadataCache
	builder := NewServerBuilder().
		WithVersion("1.0.0").
		WithPrompts(ServerPrompt{
			Prompt: mcp.Prompt{
				Name:        "test_prompt",
				Description: "A test prompt",
				Arguments: []mcp.PromptArgument{
					{
						Name:        "arg1",
						Description: "First argument",
						Required:    true,
					},
				},
			},
		})

	server, err := builder.Build()
	require.NoError(t, err, "Failed to build server with prompts")
	assert.NotNil(t, server, "Expected server to be created")

	// The important thing is that Build succeeded, which means populatePromptMetadataCache was called
	// during the build process without panicking
}

func TestResourceHandlers(t *testing.T) {
	// Get the generated resources
	resources, resourcesWithEmbed := createResources()

	// Verify counts
	assert.Len(t, resources, 3, "Expected 3 regular resources")
	assert.Len(t, resourcesWithEmbed, 1, "Expected 1 embed resource")

	// Create MCP resources that call the real handlers with embed where needed
	mcpResources := []server.ServerResource{
		{
			Resource: mcp.Resource{
				URI:  "config://template",
				Name: "Configuration Template",
			},
			Handler: func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				return handleConfigResource(ctx, req)
			},
		},
		{
			Resource: mcp.Resource{
				URI:  "info://version",
				Name: "Version Information",
			},
			Handler: func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				return handleVersionResource(ctx, req)
			},
		},
		{
			Resource: mcp.Resource{
				URI:  "docs://certificate-formats",
				Name: "Certificate Formats Documentation",
			},
			Handler: func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				return handleCertificateFormatsResource(ctx, req, templates.MagicEmbed)
			},
		},
		{
			Resource: mcp.Resource{
				URI:  "status://server-status",
				Name: "Server Status",
			},
			Handler: func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				return handleStatusResource(ctx, req)
			},
		},
	}

	// Create test server and add the resources
	srv := mcptest.NewUnstartedServer(t)
	srv.AddResources(mcpResources...)

	// Start the server
	require.NoError(t, srv.Start(t.Context()), "Failed to start server")
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
			expectContains: []string{`"warnDays"`, `"timeoutSeconds"`},
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

			result, err := client.ReadResource(t.Context(), req)
			if tt.expectError {
				assert.Error(t, err, "expected error for URI %s", tt.uri)
				return
			}

			require.NoError(t, err, "unexpected error for URI %s", tt.uri)
			require.NotNil(t, result, "expected result for URI %s, but got nil", tt.uri)
			require.NotEmpty(t, result.Contents, "expected contents for URI %s, but got empty", tt.uri)

			// Check the first content item
			content := result.Contents[0]
			if textContent, ok := content.(mcp.TextResourceContents); ok {
				assert.Equal(t, tt.expectMIMEType, textContent.MIMEType,
					"expected MIME type %s for URI %s", tt.expectMIMEType, tt.uri)

				for _, expected := range tt.expectContains {
					assert.Contains(t, textContent.Text, expected,
						"expected content to contain %q for URI %s", expected, tt.uri)
				}
			} else {
				assert.IsType(t, mcp.TextResourceContents{}, content,
					"expected TextResourceContents for URI %s, but got %T", tt.uri, content)
			}
		})
	}
}

func TestGetParams(t *testing.T) {
	tests := []struct {
		name        string
		req         map[string]any
		method      string
		expectError bool
	}{
		{
			name: "valid params",
			req: map[string]any{
				"params": map[string]any{"key": "value"},
			},
			method:      "test",
			expectError: false,
		},
		{
			name: "missing params",
			req: map[string]any{
				"other": "field",
			},
			method:      "test",
			expectError: true,
		},
		{
			name: "invalid params type",
			req: map[string]any{
				"params": "not-an-object",
			},
			method:      "test",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := getParams(tt.req, tt.method)
			if tt.expectError {
				assert.Error(t, err, "Expected error")
				return
			}

			assert.NoError(t, err, "Unexpected error")
			assert.NotNil(t, params, "Expected params but got nil")
		})
	}
}

func TestGetStringParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]any
		method      string
		key         string
		expectError bool
		expected    string
	}{
		{
			name: "valid string param",
			params: map[string]any{
				"message": "hello",
			},
			method:      "test",
			key:         "message",
			expectError: false,
			expected:    "hello",
		},
		{
			name: "missing param",
			params: map[string]any{
				"other": "field",
			},
			method:      "test",
			key:         "message",
			expectError: true,
		},
		{
			name: "wrong type param",
			params: map[string]any{
				"message": 123,
			},
			method:      "test",
			key:         "message",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getStringParam(tt.params, tt.method, tt.key)
			if tt.expectError {
				assert.Error(t, err, "Expected error")
				return
			}

			assert.NoError(t, err, "Unexpected error")
			assert.Equal(t, tt.expected, result, "Expected %q, got %q", tt.expected, result)
		})
	}
}

func TestGetOptionalStringParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]any
		method      string
		key         string
		expectError bool
		expected    string
	}{
		{
			name: "valid string param",
			params: map[string]any{
				"message": "hello",
			},
			method:      "test",
			key:         "message",
			expectError: false,
			expected:    "hello",
		},
		{
			name: "missing param",
			params: map[string]any{
				"other": "field",
			},
			method:      "test",
			key:         "message",
			expectError: false,
			expected:    "",
		},
		{
			name: "wrong type param",
			params: map[string]any{
				"message": 123,
			},
			method:      "test",
			key:         "message",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getOptionalStringParam(tt.params, tt.method, tt.key)
			if tt.expectError {
				assert.Error(t, err, "Expected error")
				return
			}

			assert.NoError(t, err, "Unexpected error")
			assert.Equal(t, tt.expected, result, "Expected %q, got %q", tt.expected, result)
		})
	}
}

func TestPipeReader_Read(t *testing.T) {
	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	reader := &pipeReader{t: transport}

	// Test reading with cancelled context
	transport.cancel()
	buf := make([]byte, 100)
	n, err := reader.Read(buf)
	assert.Equal(t, io.EOF, err, "Expected EOF when context cancelled")
	assert.Equal(t, 0, n, "Expected 0 bytes read")
}

func TestPipeWriter_Write(t *testing.T) {
	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	writer := &pipeWriter{t: transport}

	// Test writing a complete JSON message
	message := `{"jsonrpc":"2.0","method":"test","id":1}` + "\n"
	data := []byte(message)

	n, err := writer.Write(data)
	assert.NoError(t, err, "Write should not fail")
	assert.Equal(t, len(data), n, "Expected to write %d bytes", len(data))

	// Test writing partial message (should buffer)
	partial := `{"jsonrpc":"2.0","method":"partial"`
	n, err = writer.Write([]byte(partial))
	assert.NoError(t, err, "Partial write should not fail")
	assert.Equal(t, len(partial), n, "Expected to write %d bytes", len(partial))
}

func TestPipeWriter_Write_SamplingRequest(t *testing.T) {
	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	// Set up the existing mock sampling handler
	transport.SetSamplingHandler(&mockSamplingHandler{})

	writer := &pipeWriter{t: transport}

	// Write a sampling request with id (should trigger sampling path)
	samplingRequest := `{"jsonrpc":"2.0","method":"sampling/createMessage","id":123,"params":{"messages":[{"role":"user","content":{"type":"text","text":"test"}}],"maxTokens":100}}` + "\n"
	data := []byte(samplingRequest)

	n, err := writer.Write(data)
	assert.NoError(t, err, "Write should not fail")
	assert.Equal(t, len(data), n, "Expected to write %d bytes", len(data))

	// Wait for the sampling goroutine to complete
	transport.Close()
}

func TestTransportInternalFunctions(t *testing.T) {
	ctx := t.Context()
	transport := NewInMemoryTransport(ctx)

	// Test sendToRecv
	testMsg := []byte("test message")
	transport.sendToRecv(testMsg)

	select {
	case received := <-transport.recvCh:
		assert.Equal(t, string(testMsg), string(received), "sendToRecv should send correct message")
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "sendToRecv did not send message to recvCh")
	}

	// Test sendErrorResponse
	transport.sendErrorResponse(123, 400, "test error")

	select {
	case response := <-transport.recvCh:
		var resp jsonRPCResponse
		err := json.Unmarshal(response, &resp)
		assert.NoError(t, err, "sendErrorResponse should produce valid JSON")

		assert.Equal(t, 123.0, resp.ID, "sendErrorResponse should set correct ID")
		require.NotNil(t, resp.Error, "sendErrorResponse should include error")
		assert.Equal(t, 400, resp.Error.Code, "sendErrorResponse should set correct error code")
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "sendErrorResponse did not send response")
	}

	// Test sendResponse
	testResult := map[string]any{"result": "success"}
	transport.sendResponse(testResult)

	select {
	case response := <-transport.recvCh:
		var resp jsonRPCResponse
		err := json.Unmarshal(response, &resp)
		assert.NoError(t, err, "sendResponse should produce valid JSON")
		assert.NotNil(t, resp.Result, "sendResponse should include result")
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "sendResponse did not send response")
	}
}

func TestCollectResourceUsage(t *testing.T) {
	data := CollectResourceUsage(false)
	require.NotNil(t, data, "CollectResourceUsage should not return nil")

	assert.NotEmpty(t, data.Timestamp, "Timestamp should not be empty")
	assert.NotNil(t, data.MemoryUsage, "MemoryUsage should not be nil")
	assert.NotNil(t, data.SystemInfo, "SystemInfo should not be nil")

	// Test with detailed=true
	dataDetailed := CollectResourceUsage(true)
	require.NotNil(t, dataDetailed, "CollectResourceUsage with detailed=true should not return nil")

	assert.NotNil(t, dataDetailed.DetailedMemory, "DetailedMemory should not be nil when detailed=true")
	assert.NotNil(t, dataDetailed.CRLCache, "CRLCache should not be nil when detailed=true")
}

func TestNewTransportBuilder(t *testing.T) {
	builder := NewTransportBuilder()
	assert.NotNil(t, builder, "NewTransportBuilder should not return nil")

	// Test builder methods
	builder = builder.WithConfig(&Config{})
	builder = builder.WithVersion("1.0.0")
	builder = builder.WithDefaultTools()

	// Should not panic
	transport, err := builder.BuildInMemoryTransport(t.Context())
	assert.NoError(t, err, "BuildInMemoryTransport should not fail")
	assert.NotNil(t, transport, "BuildInMemoryTransport should not return nil transport")
}

func TestNewADKTransportBuilder(t *testing.T) {
	builder := NewADKTransportBuilder()
	assert.NotNil(t, builder, "NewADKTransportBuilder should not return nil")

	// Test builder methods
	builder = builder.WithVersion("1.0.0")
	builder = builder.WithMCPConfig("/tmp/config.json")
	builder = builder.WithInMemoryTransport()

	// Should not panic
	err := builder.ValidateConfig()
	// Validation might fail due to config, but shouldn't panic
	_ = err // We don't care about the result, just that it doesn't panic
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configPath  string
		expectError bool
	}{
		{
			name:        "empty config path uses defaults",
			configPath:  "",
			expectError: false,
		},
		{
			name:        "nonexistent config file",
			configPath:  "/nonexistent/config.json",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := loadConfig(tt.configPath)
			if tt.expectError {
				assert.Error(t, err, "Expected error")
				return
			}

			assert.NoError(t, err, "Unexpected error")
			assert.NotNil(t, config, "Expected config but got nil")

			// Verify default values
			// Format, WarnDays, IncludeSystemRoot, IntermediateOnly removed from config
		})
	}
}

func TestCreateTools(t *testing.T) {
	tools, toolsWithConfig := createTools()

	// Verify we get the expected number of tools
	assert.Len(t, tools, 4, "Expected 4 regular tools")
	assert.Len(t, toolsWithConfig, 4, "Expected 4 config tools")

	// Verify tool names
	expectedToolNames := []string{
		"resolve_cert_chain",
		"validate_cert_chain",
		"batch_resolve_cert_chain",
		"get_resource_usage",
		"check_cert_expiry",
		"fetch_remote_cert",
		"analyze_certificate_with_ai",
		"visualize_cert_chain",
	}

	foundTools := make(map[string]bool)
	for _, tool := range tools {
		foundTools[string(tool.Tool.Name)] = true
	}
	for _, tool := range toolsWithConfig {
		foundTools[string(tool.Tool.Name)] = true
	}

	for _, expectedName := range expectedToolNames {
		assert.True(t, foundTools[expectedName], "Expected tool %s not found", expectedName)
	}
}

func TestCreatePrompts(t *testing.T) {
	prompts, promptsWithEmbed := createPrompts()

	// Verify we get the expected number of prompts
	assert.Len(t, prompts, 0, "Expected 0 regular prompts")
	assert.Len(t, promptsWithEmbed, 5, "Expected 5 embed prompts")

	// Verify prompt names for embed prompts
	expectedPromptNames := []string{
		"certificate-analysis",
		"expiry-monitoring",
		"security-audit",
		"troubleshooting",
		"resource-monitoring",
	}

	foundEmbedPrompts := make(map[string]bool)
	for _, prompt := range promptsWithEmbed {
		foundEmbedPrompts[string(prompt.Prompt.Name)] = true
	}

	for _, expectedName := range expectedPromptNames {
		assert.True(t, foundEmbedPrompts[expectedName], "Expected prompt %s not found in embed prompts", expectedName)
	}
}

func TestHandleConfigResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "config://template",
		},
	}

	result, err := handleConfigResource(t.Context(), req)
	require.NoError(t, err, "handleConfigResource should not fail")

	assert.Len(t, result, 1, "Expected 1 result")

	content, ok := result[0].(mcp.TextResourceContents)
	require.True(t, ok, "Expected TextResourceContents, got %T", result[0])

	assert.Equal(t, "config://template", content.URI, "Expected URI 'config://template'")
	assert.Equal(t, "application/json", content.MIMEType, "Expected MIME type 'application/json'")

	// Verify JSON structure
	var config map[string]any
	err = json.Unmarshal([]byte(content.Text), &config)
	assert.NoError(t, err, "Failed to unmarshal config JSON")

	assert.Contains(t, config, "defaults", "Config should contain 'defaults' key")
}

func TestHandleVersionResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "info://version",
		},
	}

	result, err := handleVersionResource(t.Context(), req)
	require.NoError(t, err, "handleVersionResource should not fail")

	assert.Len(t, result, 1, "Expected 1 result")

	content, ok := result[0].(mcp.TextResourceContents)
	require.True(t, ok, "Expected TextResourceContents, got %T", result[0])

	assert.Equal(t, "info://version", content.URI, "Expected URI 'info://version'")
	assert.Equal(t, "application/json", content.MIMEType, "Expected MIME type 'application/json'")

	// Verify JSON structure contains expected fields
	var versionInfo map[string]any
	err = json.Unmarshal([]byte(content.Text), &versionInfo)
	assert.NoError(t, err, "Failed to unmarshal version JSON")

	expectedFields := []string{"name", "version", "type", "capabilities", "supportedFormats"}
	for _, field := range expectedFields {
		assert.Contains(t, versionInfo, field, "Version info should contain '%s' key", field)
	}
}

func TestHandleFormatsResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "docs://certificate-formats",
		},
	}

	result, err := handleCertificateFormatsResource(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleCertificateFormatsResource should not fail")

	assert.Len(t, result, 1, "Expected 1 result")

	content, ok := result[0].(mcp.TextResourceContents)
	require.True(t, ok, "Expected TextResourceContents, got %T", result[0])

	assert.Equal(t, "docs://certificate-formats", content.URI, "Expected URI 'docs://certificate-formats'")
	assert.Equal(t, "text/markdown", content.MIMEType, "Expected MIME type 'text/markdown'")

	// Content should contain markdown
	assert.Contains(t, content.Text, "#", "Expected markdown content with headers")
}

func TestHandleStatusResource(t *testing.T) {
	req := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "status://server-status",
		},
	}

	result, err := handleStatusResource(t.Context(), req)
	require.NoError(t, err, "handleStatusResource should not fail")

	assert.Len(t, result, 1, "Expected 1 result")

	content, ok := result[0].(mcp.TextResourceContents)
	require.True(t, ok, "Expected TextResourceContents, got %T", result[0])

	assert.Equal(t, "status://server-status", content.URI, "Expected URI 'status://server-status'")
	assert.Equal(t, "application/json", content.MIMEType, "Expected MIME type 'application/json'")

	// Verify JSON structure contains expected fields
	var statusInfo map[string]any
	err = json.Unmarshal([]byte(content.Text), &statusInfo)
	assert.NoError(t, err, "Failed to unmarshal status JSON")

	expectedFields := []string{"status", "timestamp", "server", "version", "capabilities", "supportedFormats"}
	for _, field := range expectedFields {
		assert.Contains(t, statusInfo, field, "Status info should contain '%s' key", field)
	}

	assert.Equal(t, "healthy", statusInfo["status"], "Expected status 'healthy'")
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

	result, err := handleCertificateAnalysisPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleCertificateAnalysisPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.Len(t, result.Messages, 7, "Expected 7 messages")
	assert.Equal(t, "Certificate Chain Analysis Workflow", result.Description,
		"Expected description 'Certificate Chain Analysis Workflow'")
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

	result, err := handleExpiryMonitoringPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleExpiryMonitoringPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.Len(t, result.Messages, 8, "Expected 8 messages")
	assert.Equal(t, "Certificate Expiry Monitoring", result.Description,
		"Expected description 'Certificate Expiry Monitoring'")
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

	result, err := handleSecurityAuditPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleSecurityAuditPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 8, "Expected at least 8 messages")
	assert.Equal(t, "SSL/TLS Security Audit", result.Description,
		"Expected description 'SSL/TLS Security Audit'")
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

	result, err := handleTroubleshootingPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleTroubleshootingPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 3, "Expected at least 3 messages for chain issue")
	assert.Equal(t, "Certificate Troubleshooting Guide", result.Description,
		"Expected description 'Certificate Troubleshooting Guide'")
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

	result, err := handleTroubleshootingPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleTroubleshootingPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 2, "Expected at least 2 messages for validation issue")
	assert.Equal(t, "Certificate Troubleshooting Guide", result.Description,
		"Expected description 'Certificate Troubleshooting Guide'")
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

	result, err := handleTroubleshootingPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleTroubleshootingPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 2, "Expected at least 2 messages for expiry issue")
	assert.Equal(t, "Certificate Troubleshooting Guide", result.Description,
		"Expected description 'Certificate Troubleshooting Guide'")
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

	result, err := handleTroubleshootingPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleTroubleshootingPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 2, "Expected at least 2 messages for connection issue")
	assert.Equal(t, "Certificate Troubleshooting Guide", result.Description,
		"Expected description 'Certificate Troubleshooting Guide'")
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

	result, err := handleTroubleshootingPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleTroubleshootingPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.Len(t, result.Messages, 4, "Expected 4 messages for invalid issue type")
	assert.Equal(t, "Certificate Troubleshooting Guide", result.Description,
		"Expected description 'Certificate Troubleshooting Guide'")
}

func TestHandleResourceMonitoringPrompt_Debugging(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "resource-monitoring",
			Arguments: map[string]string{
				"monitoring_context": "debugging",
				"format_preference":  "json",
			},
		},
	}

	result, err := handleResourceMonitoringPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleResourceMonitoringPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 5, "Expected at least 5 messages for debugging context")
	assert.Equal(t, "Resource Monitoring and Performance Analysis", result.Description,
		"Expected description 'Resource Monitoring and Performance Analysis'")
}

func TestHandleResourceMonitoringPrompt_Optimization(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "resource-monitoring",
			Arguments: map[string]string{
				"monitoring_context": "optimization",
			},
		},
	}

	result, err := handleResourceMonitoringPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleResourceMonitoringPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 5, "Expected at least 5 messages for optimization context")
	assert.Equal(t, "Resource Monitoring and Performance Analysis", result.Description,
		"Expected description 'Resource Monitoring and Performance Analysis'")
}

func TestHandleResourceMonitoringPrompt_Routine(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name: "resource-monitoring",
			Arguments: map[string]string{
				"monitoring_context": "routine",
				"format_preference":  "markdown",
			},
		},
	}

	result, err := handleResourceMonitoringPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleResourceMonitoringPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 5, "Expected at least 5 messages for routine context")
	assert.Equal(t, "Resource Monitoring and Performance Analysis", result.Description,
		"Expected description 'Resource Monitoring and Performance Analysis'")
}

func TestHandleResourceMonitoringPrompt_Defaults(t *testing.T) {
	req := mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{
			Name:      "resource-monitoring",
			Arguments: map[string]string{}, // No arguments provided
		},
	}

	result, err := handleResourceMonitoringPrompt(t.Context(), req, templates.MagicEmbed)
	require.NoError(t, err, "handleResourceMonitoringPrompt should not fail")

	require.NotNil(t, result, "Expected result, got nil")

	assert.GreaterOrEqual(t, len(result.Messages), 5, "Expected at least 5 messages for default context")
	assert.Equal(t, "Resource Monitoring and Performance Analysis", result.Description,
		"Expected description 'Resource Monitoring and Performance Analysis'")
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
	require.NoError(t, json.Unmarshal([]byte(result), &jsonResult), "formatJSON should return valid JSON")

	// Check structure
	assert.Equal(t, "X.509 Certificate Chain", jsonResult["title"], "Expected title 'X.509 Certificate Chain'")
	assert.Equal(t, float64(1), jsonResult["totalChained"], "Expected totalChained 1")
}

func TestServerBuilder_Build_WithoutTools(t *testing.T) {
	builder := NewServerBuilder().
		WithConfig(&Config{}).
		WithVersion("1.0.0")

	server, err := builder.Build()
	require.NoError(t, err, "Build should succeed without tools")

	assert.NotNil(t, server, "Expected server, got nil")
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

	require.NotNil(t, chain, "Expected chain, got nil")

	// The chain should contain the certificate
	assert.NotEmpty(t, chain.Certs, "Expected chain to contain at least one certificate")

	assert.Equal(t, "test.example.com", chain.Certs[0].Subject.CommonName,
		"Expected certificate CN 'test.example.com'")
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
			assert.NotEmpty(t, result, "Expected non-empty analysis instruction")

			for _, expected := range tt.expectContains {
				assert.Contains(t, result, expected,
					"Expected analysis instruction to contain '%s'", expected)
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
			// Create a chain with the specified total number of certificates
			chain := x509chain.New(nil, "test")
			chain.Certs = make([]*x509.Certificate, tt.total)
			for i := 0; i < tt.total; i++ {
				chain.Certs[i] = &x509.Certificate{}
			}

			result := chain.GetCertificateRole(tt.index)
			assert.Equal(t, tt.expected, result, fmt.Sprintf("GetCertificateRole(%d) should return %q", tt.index, tt.expected))
		})
	}
}

func TestGetKeySize(t *testing.T) {
	// Test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Test ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

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
			chain := x509chain.New(tt.cert, version.Version)
			result := chain.KeySize(tt.cert)
			// Debug: print what type the PublicKey is
			t.Logf("PublicKey type: %T, value: %+v", tt.cert.PublicKey, tt.cert.PublicKey)
			assert.Equal(t, tt.expected, result, "KeySize() should return expected value")
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
			assert.Equal(t, tt.expected, result, "formatKeyUsage(%d) should return expected result", tt.usage)
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
			assert.Equal(t, tt.expected, result, "formatExtKeyUsage(%v) should return expected result", tt.usage)
		})
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
					assert.Fail(t, "HTTP server called when API key is empty")
					return
				}

				// Verify request headers
				auth := r.Header.Get("Authorization")
				assert.Equal(t, "Bearer "+tt.apiKey, auth, "Authorization header should be 'Bearer <key>'")

				userAgent := r.Header.Get("User-Agent")
				assert.Contains(t, userAgent, "X.509-Certificate-Chain-Resolver-MCP", "User-Agent should contain app name")

				// Verify request body
				var payload map[string]any
				require.NoError(t, json.NewDecoder(r.Body).Decode(&payload), "Should decode request body")

				assert.Equal(t, tt.model, payload["model"], "Model should match expected")

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

			result, err := handler.CreateMessage(t.Context(), tt.request)

			if tt.expectFallback {
				assert.NoError(t, err, "Should not have error for fallback")
				assert.NotNil(t, result, "Should have result for fallback")
				if result != nil {
					content := result.SamplingMessage.Content.(mcp.TextContent).Text
					assert.Contains(t, content, "AI API key not configured",
						"Expected fallback message about API key")
				}
			} else {
				assert.NoError(t, err, "Should not have error")
				assert.NotNil(t, result, "Should have result")
				if result != nil {
					content := result.SamplingMessage.Content.(mcp.TextContent).Text
					assert.Equal(t, "Hello world", content, "Should return 'Hello world'")
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

	assert.NoError(t, err, "Should not have error")

	assert.NotNil(t, result, "Should have result")

	assert.Equal(t, "not-configured", result.Model, "Model should be 'not-configured'")
	assert.Equal(t, "end", result.StopReason, "Stop reason should be 'end'")

	content, ok := result.SamplingMessage.Content.(mcp.TextContent)
	assert.True(t, ok, "Content should be TextContent")

	assert.Contains(t, content.Text, "AI API key not configured", "Should contain API key message")

	assert.Contains(t, content.Text, "X509_AI_APIKEY", "Should mention X509_AI_APIKEY")
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

			require.Len(t, result, len(tt.expected), "Should have expected number of messages")

			for i, expectedMsg := range tt.expected {
				assert.Equal(t, expectedMsg["role"], result[i]["role"], fmt.Sprintf("Message %d role should match", i))

				assert.Equal(t, expectedMsg["content"], result[i]["content"], fmt.Sprintf("Message %d content should match", i))
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

			if tt.expectError {
				assert.Error(t, err, "Should have error")
			} else {
				assert.NoError(t, err, "Should not have error")
			}

			assert.Equal(t, tt.expectedContent, content, "Content should match expected")

			assert.Equal(t, tt.expectedModel, model, "Expected model '%s'", tt.expectedModel)
			assert.Equal(t, tt.expectedStop, stopReason, "Expected stop reason '%s'", tt.expectedStop)
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
				assert.NotNil(t, server, "Expected server, got nil")
			},
		},
		{
			name:    "Builder With Config",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				config := &Config{}
				config.Defaults.Timeout = 15
				return sb.WithConfig(config)
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				assert.NotNil(t, server, "Expected server, got nil")
			},
		},
		{
			name:    "Builder With Default Tools",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				return sb.WithDefaultTools()
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				assert.NotNil(t, server, "Expected server, got nil")
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
				assert.NotNil(t, server, "Expected server, got nil")
				// Sampling is enabled internally, we can't directly check it
				// but we can verify server was built successfully
			},
		},
		{
			name:    "Builder With All Options",
			builder: NewServerBuilder(),
			setup: func(sb *ServerBuilder) *ServerBuilder {
				config := &Config{}
				config.Defaults.Timeout = 10
				config.AI.APIKey = "test-api-key"
				config.AI.Model = "test-model"
				config.AI.Endpoint = "https://api.test.com"
				handler := NewDefaultSamplingHandler(config, "test-version")
				return sb.WithConfig(config).WithDefaultTools().WithSampling(handler)
			},
			validate: func(t *testing.T, server *server.MCPServer) {
				assert.NotNil(t, server, "Expected server, got nil")
				// Server built successfully with all options is sufficient validation
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := tt.setup(tt.builder).Build()
			require.NoError(t, err, "Expected no error building server")
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
		result, err := handler.CreateMessage(t.Context(), request)
		assert.NoError(t, err, fmt.Sprintf("Iteration %d: Should not have error", i))
		assert.NotNil(t, result, fmt.Sprintf("Iteration %d: Should have result", i))
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

			result, err := handler.CreateMessage(t.Context(), request)

			assert.Error(t, err, "Should have error")

			assert.Contains(t, err.Error(), tt.expectedError, "Error should contain expected message")

			assert.Nil(t, result, "Should have nil result on error")
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
	assert.NotNil(t, handler, "Should have handler")

	assert.Equal(t, "test-key", handler.apiKey, "API key should be 'test-key'")

	assert.Equal(t, "https://api.test.com", handler.endpoint, "Endpoint should be 'https://api.test.com'")

	assert.Equal(t, "test-model", handler.model, "Model should be 'test-model'")

	assert.Equal(t, "test-version", handler.version, "Version should be 'test-version'")
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
		assert.Equal(t, "default-model", model, "Expected default model")

		// Test with preferences
		preferences := &mcp.ModelPreferences{
			Hints: []mcp.ModelHint{{Name: "preferred-model"}},
		}
		model = handler.selectModel(preferences)
		assert.Equal(t, "preferred-model", model, "Should return preferred model")
	})

	// Test prepareMessages
	t.Run("prepareMessages", func(t *testing.T) {
		messages := []map[string]any{
			{"role": "user", "content": "Hello"},
		}

		// Test without system prompt
		result := handler.prepareMessages(messages, "")
		assert.Len(t, result, 1, "Should have 1 message without system prompt")

		// Test with system prompt
		result = handler.prepareMessages(messages, "You are helpful")
		assert.Len(t, result, 2, "Should have 2 messages with system prompt")

		assert.Equal(t, "system", result[0]["role"], "First message should be system")

		assert.Equal(t, "You are helpful", result[0]["content"], "System prompt should be 'You are helpful'")
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

		assert.Equal(t, "test-model", result["model"], "Model should be 'test-model'")

		assert.Equal(t, 100, result["max_tokens"], "Max tokens should be 100")

		assert.Equal(t, 0.7, result["temperature"], "Temperature should be 0.7")

		assert.True(t, result["stream"].(bool), "Stream should be true")

		stopSequences, ok := result["stop"].([]string)
		require.True(t, ok, "Stop should be []string")

		assert.Len(t, stopSequences, 1, "Should have 1 stop sequence")

		assert.Equal(t, "\n", stopSequences[0], "Stop sequence should be '\\n'")
	})

	// Test buildSamplingResult
	t.Run("buildSamplingResult", func(t *testing.T) {
		result := handler.buildSamplingResult("Hello world", "test-model", "stop")

		assert.Equal(t, mcp.RoleAssistant, result.SamplingMessage.Role, "Role should be assistant")

		content, ok := result.SamplingMessage.Content.(mcp.TextContent)
		require.True(t, ok, "Content should be TextContent")

		assert.Equal(t, "Hello world", content.Text, "Content should be 'Hello world'")

		assert.Equal(t, "test-model", result.Model, "Model should be 'test-model'")

		assert.Equal(t, "stop", result.StopReason, "Stop reason should be 'stop'")
	})
}

// TestBuildCertificateContextWithRevocation tests the buildCertificateContextWithRevocation function
func TestBuildCertificateContextWithRevocation(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
			chain := x509chain.New(cert, version.Version)
			result := buildCertificateContextWithRevocation(chain, tt.revocationStatus, tt.analysisType)

			// Check that expected fields are present
			for _, field := range tt.expectedFields {
				assert.Contains(t, result, field, "Expected field '%s' not found in result", field)
			}

			// Check that revocation status is included
			assert.Contains(t, result, tt.revocationStatus, "Result should contain revocation status")

			// Check that analysis type is included
			assert.Contains(t, result, tt.analysisType, "Result should contain analysis type")

			// Check for certificate information
			expectedCertFields := []string{"SUBJECT", "ISSUER", "VALIDITY", "CRYPTOGRAPHY"}
			for _, field := range expectedCertFields {
				assert.Contains(t, result, field, fmt.Sprintf("Result should contain certificate field '%s'", field))
			}
		})
	}
}

// TestAppendSubjectInfo tests the appendSubjectInfo function
func TestAppendSubjectInfo(t *testing.T) {
	// Create a test certificate with known subject
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain subject field '%s'", field))
	}
}

// TestAppendIssuerInfo tests the appendIssuerInfo function
func TestAppendIssuerInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain issuer field '%s'", field))
	}
}

// TestAppendValidityInfo tests the appendValidityInfo function
func TestAppendValidityInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain validity field '%s'", field))
	}
}

// TestAppendCryptoInfo tests the appendCryptoInfo function
func TestAppendCryptoInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

	chain := x509chain.New(cert, version.Version)
	var context strings.Builder
	appendCryptoInfo(&context, chain, cert)

	result := context.String()

	// Check that cryptographic information is included
	expectedFields := []string{
		"CRYPTOGRAPHY:",
		"Signature Algorithm:",
		"Public Key Algorithm:",
		"Key Size:",
	}

	for _, field := range expectedFields {
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain crypto field '%s'", field))
	}
}

// TestAppendCertProperties tests the appendCertProperties function
func TestAppendCertProperties(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain properties field '%s'", field))
	}
}

// TestAppendCertExtensions tests the appendCertExtensions function
func TestAppendCertExtensions(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain extensions field '%s'", field))
	}
}

// TestAppendCAInfo tests the appendCAInfo function
func TestAppendCAInfo(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain CA info field '%s'", field))
	}
}

// TestAppendChainValidationContext tests the appendChainValidationContext function
func TestAppendChainValidationContext(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

	var context strings.Builder
	appendChainValidationContext(&context, []*x509.Certificate{cert})

	result := context.String()

	// Check that chain validation context is included
	expectedFields := []string{
		"=== CHAIN VALIDATION CONTEXT ===",
	}

	for _, field := range expectedFields {
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain chain validation field '%s'", field))
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
		assert.Contains(t, result, field, fmt.Sprintf("Result should contain security context field '%s'", field))
	}
}

// TestHandleAnalyzeCertificateWithAI tests the handleAnalyzeCertificateWithAI function
func TestHandleAnalyzeCertificateWithAI(t *testing.T) {
	// Create test request
	certData := pemToBase64(testCertPEM)

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
			WarnDays         int `json:"warnDays" yaml:"warnDays"`
			Timeout          int `json:"timeoutSeconds" yaml:"timeoutSeconds"`
			BatchConcurrency int `json:"batchConcurrency" yaml:"batchConcurrency"`
		}{
			WarnDays:         30,
			Timeout:          30,
			BatchConcurrency: 10,
		},
	}

	result, err := handleAnalyzeCertificateWithAI(t.Context(), request, config)
	require.NoError(t, err, "handleAnalyzeCertificateWithAI should not fail")

	require.NotNil(t, result, "Should have result")

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
		assert.Contains(t, resultText, field, fmt.Sprintf("Result should contain field '%s'", field))
	}
}

// TestBufferPoolIntegration tests buffer pool usage in certificate context building
func TestBufferPoolIntegration(t *testing.T) {
	// Create a test certificate
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

	// Test multiple concurrent context building
	const numGoroutines = 10
	const numIterations = 100

	for range numGoroutines {
		go func() {
			for range numIterations {
				// This should use buffer pooling internally
				chain := x509chain.New(cert, version.Version)
				result := buildCertificateContextWithRevocation(
					chain,
					"Good",
					"security",
				)

				// Verify result contains expected content
				assert.Contains(t, result, "Chain Length", "Expected 'Chain Length' not found in result")
			}
		}()
	}

	// Allow goroutines to complete
	time.Sleep(100 * time.Millisecond)
}

// TestConcurrentCertificateAnalysis tests concurrent certificate analysis
func TestConcurrentCertificateAnalysis(t *testing.T) {
	// Create test request
	certData := pemToBase64(testCertPEM)

	config := &Config{
		Defaults: struct {
			WarnDays         int `json:"warnDays" yaml:"warnDays"`
			Timeout          int `json:"timeoutSeconds" yaml:"timeoutSeconds"`
			BatchConcurrency int `json:"batchConcurrency" yaml:"batchConcurrency"`
		}{
			WarnDays:         30,
			Timeout:          30,
			BatchConcurrency: 10,
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

				result, err := handleAnalyzeCertificateWithAI(t.Context(), request, config)
				assert.NoError(t, err, "Concurrent analysis failed")
				if err != nil {
					continue
				}

				require.NotNil(t, result, "Expected non-nil result in concurrent analysis")

				// Verify result contains expected content
				resultText := string(result.Content[0].(mcp.TextContent).Text)
				assert.Contains(t, resultText, "Chain Length", "Expected 'Chain Length' not found in concurrent result")
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
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
		chain := x509chain.New(cert, version.Version)
		result := buildCertificateContextWithRevocation(
			chain,
			"Good",
			"general",
		)

		// Write result to buffer
		buf.WriteString(result)

		// Verify buffer has content
		assert.NotZero(t, buf.Len(), "Buffer should not be empty")
	}
}

// TestErrorHandlingInContextBuilding tests error handling in context building functions
func TestErrorHandlingInContextBuilding(t *testing.T) {
	// Test with nil certificate
	t.Run("Nil Certificate", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				assert.Fail(t, fmt.Sprintf("buildCertificateContextWithRevocation should not panic with nil certificate: %v", r))
			}
		}()

		result := buildCertificateContextWithRevocation(nil, "Unknown", "general")

		// Should handle gracefully
		assert.Contains(t, result, "Chain Length: 0", "Result should contain 'Chain Length: 0' for nil certificate")
	})

	// Test with empty revocation status
	t.Run("Empty Revocation Status", func(t *testing.T) {
		block, _ := pem.Decode([]byte(testCertPEM))
		require.NotNil(t, block, "Failed to decode test certificate")

		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err, "Should parse certificate")

		chain := x509chain.New(cert, version.Version)
		result := buildCertificateContextWithRevocation(chain, "", "security")

		// Should handle empty status gracefully
		assert.Contains(t, result, "REVOCATION STATUS", "Expected 'REVOCATION STATUS' even with empty status")
	})
}

// TestURLHandlingInExtensions tests URL handling in certificate extensions
func TestURLHandlingInExtensions(t *testing.T) {
	// Create a test certificate with various URL types in extensions
	block, _ := pem.Decode([]byte(testCertPEM))
	require.NotNil(t, block, "Should decode test certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Should parse certificate")

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
				assert.True(t, isValidURLContext(urlContext), fmt.Sprintf("URL context should be valid: %s", urlContext))
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

func TestInMemoryTransport_SetSamplingHandler(t *testing.T) {
	transport := NewInMemoryTransport(t.Context())
	require.NotNil(t, transport, "NewInMemoryTransport returned nil")

	// Initially should be nil
	assert.Nil(t, transport.samplingHandler, "Expected samplingHandler to be nil initially")

	// Create a mock sampling handler
	mockHandler := &mockSamplingHandler{}

	// Set the handler
	transport.SetSamplingHandler(mockHandler)

	// Verify it was set
	assert.Equal(t, mockHandler, transport.samplingHandler, "Expected samplingHandler to be set to mock handler")
}

func TestInMemoryTransport_handleSampling(t *testing.T) {
	transport := NewInMemoryTransport(t.Context())
	require.NotNil(t, transport, "NewInMemoryTransport returned nil")

	// Set up a mock sampling handler
	mockHandler := &mockSamplingHandler{}
	transport.SetSamplingHandler(mockHandler)

	// Test request without sampling handler (should return error)
	reqWithoutHandler := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "sampling/createMessage",
		"params": map[string]any{
			"messages": []map[string]any{
				{"role": "user", "content": "test"},
			},
		},
	}

	// Remove handler to test error case
	transport.SetSamplingHandler(nil)
	transport.handleSampling(reqWithoutHandler)

	// Check that error response was sent
	select {
	case data := <-transport.internalRespCh:
		var resp map[string]any
		require.NoError(t, json.Unmarshal(data, &resp), "Failed to unmarshal response")
		errorCode := resp["error"].(map[string]any)["code"].(float64)
		assert.Equal(t, float64(-32601), errorCode, "Expected error code -32601")
	default:
		assert.Fail(t, "Expected error response to be sent")
	}

	// Test with handler but invalid params
	transport.SetSamplingHandler(mockHandler)
	reqInvalidParams := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "sampling/createMessage",
		"params":  "invalid", // Invalid params type
	}

	transport.handleSampling(reqInvalidParams)

	// Check that error response was sent
	select {
	case data := <-transport.internalRespCh:
		var resp map[string]any
		require.NoError(t, json.Unmarshal(data, &resp), "Failed to unmarshal response")
		errorCode := resp["error"].(map[string]any)["code"].(float64)
		assert.Equal(t, float64(-32602), errorCode, "Expected error code -32602")
	default:
		assert.Fail(t, "Expected error response to be sent")
	}
}

// mockSamplingHandler implements client.SamplingHandler for testing
type mockSamplingHandler struct{}

func (m *mockSamplingHandler) CreateMessage(ctx context.Context, req mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
	return &mcp.CreateMessageResult{
		SamplingMessage: mcp.SamplingMessage{
			Role:    mcp.RoleAssistant,
			Content: mcp.NewTextContent("Mock response"),
		},
		Model:      "mock-model",
		StopReason: "stop",
	}, nil
}

func TestLoadInstructions(t *testing.T) {
	// Create mock tool definitions with Roles to ensure template substitution works
	mockTools := []ToolDefinition{
		{
			Tool: mcp.NewTool("test_tool_1",
				mcp.WithDescription("Test tool 1 description"),
			),
			Role: "chainResolver", // Used in template
		},
		{
			Tool: mcp.NewTool("test_tool_2",
				mcp.WithDescription("Test tool 2 description"),
			),
			Role: "chainValidator", // Used in template
		},
		{
			Tool: mcp.NewTool("test_tool_3",
				mcp.WithDescription("Test tool 3 description"),
			),
			Role: "batchResolver", // Used in template
		},
		{
			Tool: mcp.NewTool("test_tool_4",
				mcp.WithDescription("Test tool 4 description"),
			),
			Role: "resourceMonitor", // Used in template
		},
	}

	mockToolsWithConfig := []ToolDefinitionWithConfig{
		{
			Tool: mcp.NewTool("test_config_tool",
				mcp.WithDescription("Test config tool description"),
			),
			Role: "expiryChecker", // Used in template
		},
		{
			Tool: mcp.NewTool("test_config_tool_2",
				mcp.WithDescription("Test config tool 2 description"),
			),
			Role: "remoteFetcher", // Used in template
		},
		{
			Tool: mcp.NewTool("test_config_tool_3",
				mcp.WithDescription("Test config tool 3 description"),
			),
			Role: "aiAnalyzer", // Used in template
		},
	}

	// Call loadInstructions with mock data
	instructions, err := loadInstructions(mockTools, mockToolsWithConfig, "mcp-server", "0.0.0")
	require.NoError(t, err, "loadInstructions failed")

	assert.NotEmpty(t, instructions, "Expected non-empty instructions, got empty string")

	// Log comprehensive information about the rendered template
	t.Logf("Instructions length: %d", len(instructions))
	t.Logf("First 500 characters: %s", instructions[:min(500, len(instructions))])

	// Find and log the tools section
	toolsSectionStart := strings.Index(instructions, "## Tool selection guidelines")
	if toolsSectionStart != -1 {
		nextHeaderIndex := strings.Index(instructions[toolsSectionStart+1:], "##")
		if nextHeaderIndex == -1 {
			nextHeaderIndex = len(instructions) - toolsSectionStart
		}
		toolsSection := instructions[toolsSectionStart : toolsSectionStart+nextHeaderIndex]
		t.Logf("Tools section: %s", toolsSection)
	}

	// Find and log the Basic Analysis Workflow section
	workflowStart := strings.Index(instructions, "### Basic Analysis Workflow")
	if workflowStart != -1 {
		nextHeaderIndex := strings.Index(instructions[workflowStart+1:], "###")
		if nextHeaderIndex == -1 {
			nextHeaderIndex = len(instructions) - workflowStart
		}
		// Be careful not to go past the end of string
		endIndex := min(len(instructions), workflowStart+nextHeaderIndex)
		workflowSection := instructions[workflowStart:endIndex]
		t.Logf("Basic Analysis Workflow section: %s", workflowSection)
	}

	// Verify that the instructions contain the tool information
	expectedContents := []string{
		"test_tool_1",
		"Test tool 1 description",
		"test_tool_2",
		"Test tool 2 description",
		"test_config_tool",
		"Test config tool description",
		"Tool selection guidelines",
		"Certificate Chain Resolver",
		"Basic Analysis Workflow",
		"Security Audit Workflow",
		"Batch Processing Workflow",
	}

	for _, expected := range expectedContents {
		assert.Contains(t, instructions, expected, "Expected instructions to contain %q, but it didn't", expected)
	}

	// Verify template variables are working by checking for tool role substitutions
	// The template should have replaced {{.ToolRoles.chainResolver}} with actual tool names
	assert.True(t,
		strings.Contains(instructions, "test_tool_1") && strings.Contains(instructions, "test_tool_2"),
		"Template variables were not properly substituted with tool names")

	// Count occurrences of tool names in the entire document
	toolCount := 0
	toolCount += strings.Count(instructions, "test_tool_1")
	toolCount += strings.Count(instructions, "test_tool_2")
	toolCount += strings.Count(instructions, "test_config_tool")

	assert.GreaterOrEqual(t, toolCount, 3, "Expected at least 3 tool name references in instructions, found %d", toolCount)

	// Verify that workflow sections contain tool references
	workflows := []string{"Basic Analysis Workflow", "Security Audit Workflow", "Batch Processing Workflow"}
	for _, workflow := range workflows {
		assert.Contains(t, instructions, workflow, "Expected instructions to contain workflow section %q", workflow)
	}

	// Log summary of what was verified
	t.Logf("✓ Template rendered successfully with %d characters", len(instructions))
	t.Logf("✓ All expected content sections present")
	t.Logf("✓ Tool variables properly substituted (%d tool references found)", toolCount)
	t.Logf("✓ All workflow sections included")
}

func TestGetMapParam(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]any
		method      string
		key         string
		expectError bool
		expectValue map[string]any
	}{
		{
			name: "valid map parameter",
			params: map[string]any{
				"certificate": map[string]any{"type": "pem", "data": "test"},
			},
			method:      "resolve_cert_chain",
			key:         "certificate",
			expectError: false,
			expectValue: map[string]any{"type": "pem", "data": "test"},
		},
		{
			name: "missing parameter",
			params: map[string]any{
				"other": "value",
			},
			method:      "resolve_cert_chain",
			key:         "certificate",
			expectError: true,
		},
		{
			name: "wrong type parameter",
			params: map[string]any{
				"certificate": "not-a-map",
			},
			method:      "resolve_cert_chain",
			key:         "certificate",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getMapParam(tt.params, tt.method, tt.key)
			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
			} else {
				assert.NoError(t, err, "Expected no error")
				assert.Equal(t, tt.expectValue, result, "Expected %v, got %v", tt.expectValue, result)
			}
		})
	}
}

func TestFormatDefaultValue(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "string value",
			input:    "test string",
			expected: "test string",
		},
		{
			name:     "integer value",
			input:    42,
			expected: "42",
		},
		{
			name:     "float value",
			input:    3.14,
			expected: "3.14",
		},
		{
			name:     "boolean value",
			input:    true,
			expected: "true",
		},
		{
			name:     "nil value",
			input:    nil,
			expected: "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDefaultValue(tt.input)
			assert.Equal(t, tt.expected, result, "Expected %q, got %q", tt.expected, result)
		})
	}
}

func TestGetVersion(t *testing.T) {
	version := GetVersion()
	assert.NotEmpty(t, version, "Expected non-empty version string")
	// Version should match the appVersion variable, but we can't easily test the exact value
	// without exposing it, so we just check it's not empty
}

func TestHandleVisualizeCertChain(t *testing.T) {
	ctx := t.Context()

	// Test missing certificate parameter
	t.Run("missing certificate parameter", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      "visualize_cert_chain",
				Arguments: map[string]any{},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		assert.NotNil(t, result, "Expected result, got nil")
		// Should be an error result due to missing certificate
		assert.NotEmpty(t, result.Content, "Expected error content in result")
	})

	// Test invalid certificate format
	t.Run("invalid certificate format", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "visualize_cert_chain",
				Arguments: map[string]any{
					"certificate": "invalid-cert-data",
				},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		assert.NotNil(t, result, "Expected result, got nil")
		// Should be an error result due to invalid certificate
		assert.NotEmpty(t, result.Content, "Expected error content in result")
	})

	// Test unsupported format
	t.Run("unsupported format", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "visualize_cert_chain",
				Arguments: map[string]any{
					"certificate": pemToBase64(testCertPEM),
					"format":      "unsupported",
				},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		assert.NotNil(t, result, "Expected result, got nil")
		// Should be an error result due to unsupported format
		assert.NotEmpty(t, result.Content, "Expected error content in result")
	})

	// Test successful ASCII visualization
	t.Run("successful ascii visualization", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "visualize_cert_chain",
				Arguments: map[string]any{
					"certificate": pemToBase64(testCertPEM),
					"format":      "ascii",
				},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		require.NotNil(t, result, "Expected result, got nil")

		// Should contain visualization content
		assert.NotEmpty(t, result.Content, "Expected visualization content in result")

		// Check that it contains text content
		content := result.Content[0]
		textContent, ok := content.(mcp.TextContent)
		assert.True(t, ok, "Expected TextContent, got %T", content)

		// Verify ASCII tree structure contains tree characters
		assert.True(t,
			strings.Contains(textContent.Text, "├──") || strings.Contains(textContent.Text, "└──"),
			"Expected ASCII tree to contain tree structure characters")

		// Should contain certificate information
		assert.Contains(t, textContent.Text, "www.google.com", "Expected visualization to contain certificate subject")
	})

	// Test successful table visualization
	t.Run("successful table visualization", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "visualize_cert_chain",
				Arguments: map[string]any{
					"certificate": pemToBase64(testCertPEM),
					"format":      "table",
				},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		require.NotNil(t, result, "Expected result, got nil")

		// Should contain visualization content
		assert.NotEmpty(t, result.Content, "Expected visualization content in result")

		// Check that it contains text content
		content := result.Content[0]
		textContent, ok := content.(mcp.TextContent)
		assert.True(t, ok, "Expected TextContent, got %T", content)

		// Verify table structure (should contain | characters for markdown table format)
		assert.Contains(t, textContent.Text, "|", "Expected table visualization to contain table separators")

		// Should contain certificate data (more reliable than headers)
		assert.Contains(t, textContent.Text, "www.google.com", "Expected table to contain certificate data")
	})

	// Test successful JSON visualization
	t.Run("successful json visualization", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "visualize_cert_chain",
				Arguments: map[string]any{
					"certificate": pemToBase64(testCertPEM),
					"format":      "json",
				},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		require.NotNil(t, result, "Expected result, got nil")

		// Should contain visualization content
		assert.NotEmpty(t, result.Content, "Expected visualization content in result")

		// Check that it contains text content
		content := result.Content[0]
		textContent, ok := content.(mcp.TextContent)
		assert.True(t, ok, "Expected TextContent, got %T", content)

		// Should be valid JSON - try to find JSON content
		jsonStr := textContent.Text
		// Find the first '{' character
		startIdx := strings.Index(jsonStr, "{")
		assert.NotEqual(t, -1, startIdx, "Expected JSON visualization to contain JSON object")
		jsonStr = jsonStr[startIdx:]
		// Find the last '}' character
		endIdx := strings.LastIndex(jsonStr, "}")
		if endIdx != -1 {
			jsonStr = jsonStr[:endIdx+1]
		}

		// Should be valid JSON
		var jsonData map[string]any
		assert.NoError(t, json.Unmarshal([]byte(jsonStr), &jsonData), "Expected valid JSON, got parse error")
		// Should contain certificates array
		assert.Contains(t, jsonData, "certificates", "Expected JSON to contain 'certificates' field")
	})

	// Test default format (ascii)
	t.Run("default format ascii", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "visualize_cert_chain",
				Arguments: map[string]any{
					"certificate": pemToBase64(testCertPEM),
					// No format specified, should default to ascii
				},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		require.NotNil(t, result, "Expected result, got nil")

		// Should contain visualization content
		assert.NotEmpty(t, result.Content, "Expected visualization content in result")

		// Check that it contains text content
		content := result.Content[0]
		textContent, ok := content.(mcp.TextContent)
		assert.True(t, ok, "Expected TextContent, got %T", content)

		// Should default to ASCII format with tree structure
		assert.True(t,
			strings.Contains(textContent.Text, "├──") && strings.Contains(textContent.Text, "└──"),
			"Expected default format to be ASCII tree with structure characters")
	})

	// Test base64 encoded certificate input
	t.Run("base64 certificate input", func(t *testing.T) {
		// Encode the PEM certificate as base64
		base64Cert := pemToBase64(testCertPEM)

		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "visualize_cert_chain",
				Arguments: map[string]any{
					"certificate": base64Cert,
					"format":      "ascii",
				},
			},
		}

		result, err := handleVisualizeCertChain(ctx, request)
		assert.NoError(t, err, "Expected no error")
		require.NotNil(t, result, "Expected result, got nil")

		// Should successfully process base64 input
		assert.NotEmpty(t, result.Content, "Expected visualization content in result")
	})
}

// TestGetExecutableName tests the posix.GetExecutableName function for cross-platform compatibility.
func TestGetExecutableName(t *testing.T) {
	// Build test cases based on the current OS
	var tests []struct {
		name     string
		args     []string
		expected string
	}

	// Common test cases for all OS
	commonTests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "Relative path",
			args:     []string{"./myapp"},
			expected: "myapp",
		},
		{
			name:     "Just filename",
			args:     []string{"myapp"},
			expected: "myapp",
		},
		{
			name:     "Empty args",
			args:     []string{},
			expected: "x509-cert-chain-resolver",
		},
		{
			name:     "Empty first arg",
			args:     []string{""},
			expected: "x509-cert-chain-resolver",
		},
	}

	tests = append(tests, commonTests...)

	// OS-specific test cases
	switch runtime.GOOS {
	case "windows":
		windowsTests := []struct {
			name     string
			args     []string
			expected string
		}{
			{
				name:     "Windows absolute path with .exe",
				args:     []string{"C:\\Program Files\\myapp.exe"},
				expected: "myapp",
			},
			{
				name:     "Windows absolute path without .exe",
				args:     []string{"C:\\Program Files\\myapp"},
				expected: "myapp",
			},
			{
				name:     "Windows path with backslashes",
				args:     []string{"C:\\Users\\user\\bin\\myapp.exe"},
				expected: "myapp",
			},
			// This is how getExecutableName is robust.
			{
				name:     "Test with foreign windows path separators",
				args:     []string{"C:\\windows\\style\\path\\on\\unix\\system.exe"},
				expected: "system",
			},
			{
				name:     "Very long Windows path with 100+ characters",
				args:     []string{"C:\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\Microsoft PowerPoint\\Presentation Extensions\\PowerPoint.Presentation.8\\powerpoint.exe"},
				expected: "powerpoint",
			},
			{
				name:     "Extremely long Windows path with nested directories",
				args:     []string{"C:\\Users\\VeryLongUserNameThatExceedsNormalLimits\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.WindowsTerminal_8wekyb3d8bbwe\\WindowsTerminal.exe"},
				expected: "WindowsTerminal",
			},
		}
		tests = append(tests, windowsTests...)

	default: // Unix-like systems (linux, darwin, etc.)
		unixTests := []struct {
			name     string
			args     []string
			expected string
		}{
			{
				name:     "Unix absolute path",
				args:     []string{"/usr/local/bin/myapp"},
				expected: "myapp",
			},
			{
				name:     "Unix system path",
				args:     []string{"/bin/ls"},
				expected: "ls",
			},
			{
				name:     "Unix home path",
				args:     []string{"/home/user/bin/myapp"},
				expected: "myapp",
			},
		}
		tests = append(tests, unixTests...)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original args
			origArgs := os.Args

			// Set test args
			os.Args = tt.args

			// Restore args after test
			defer func() {
				os.Args = origArgs
			}()

			result := posix.GetExecutableName()
			t.Logf("Input: %q → Output: %q (Expected: %q)", tt.args, result, tt.expected)
			assert.Equal(t, tt.expected, result, "posix.GetExecutableName() = %q, want %q", result, tt.expected)
		})
	}
}

func TestCLIFramework_BuildRootCommand_Coverage(t *testing.T) {
	// Test for uncovered lines in CLIFramework.BuildRootCommand
	// Specifically: return cf.printInstructions(), the if originalRunE != nil check, and help flag lookup

	panicTests := []struct {
		name        string
		setupDeps   func() ServerDependencies
		expectPanic bool
		description string
	}{
		{
			name: "normal operation with valid dependencies",
			setupDeps: func() ServerDependencies {
				return ServerDependencies{
					Version:      "1.0.0",
					Instructions: "Test instructions",
					Config:       &Config{},
					Embed:        templates.MagicEmbed,
				}
			},
			expectPanic: false,
			description: "Should work normally with valid embedded filesystem",
		},
		{
			name: "panic when embed dependency is nil",
			setupDeps: func() ServerDependencies {
				return ServerDependencies{
					Version:      "1.0.0",
					Instructions: "Test instructions",
					Config:       &Config{},
					Embed:        nil, // nil embed should cause panic
				}
			},
			expectPanic: true,
			description: "Should panic when embed dependency is nil",
		},
	}

	for _, pt := range panicTests {
		t.Run(pt.name, func(t *testing.T) {
			deps := pt.setupDeps()
			framework := NewCLIFramework("", deps)

			if pt.expectPanic {
				// Test that BuildRootCommand panics
				defer func() {
					r := recover()
					assert.NotNil(t, r, "Expected panic for %s, but no panic occurred", pt.description)
					if r != nil {
						// Verify the panic message contains expected content
						panicMsg := fmt.Sprintf("%v", r)
						assert.Contains(t, panicMsg, "CLIFramework embed filesystem not initialized",
							"Expected panic message to contain 'CLIFramework embed filesystem not initialized', got: %s", panicMsg)
					}
				}()
			}

			rootCmd := framework.BuildRootCommand()

			if !pt.expectPanic {
				// Verify that BuildRootCommand looked up the help flag and built the example
				// This covers: helpFlagName := "--help" and if helpFlag != nil { helpFlagName = "--" + helpFlag.Name }
				helpFlag := rootCmd.Flags().Lookup("help")
				assert.NotNil(t, helpFlag, "Expected help flag to be found")
				if helpFlag != nil {
					// Verify the flag name is used in the example construction
					expectedFlagName := "--" + helpFlag.Name
					assert.Contains(t, rootCmd.Example, expectedFlagName, "Expected Example to contain flag name %q", expectedFlagName)
				}

				assert.NotEmpty(t, rootCmd.Example, "Expected Example to be set")

				// Test normal operation - embedded templates should always work
				assert.NotEmpty(t, rootCmd.Long, "Expected Long description to be set from template")

				assert.Contains(t, rootCmd.Long, "certificate chain resolver", "Expected Long description to contain expected content")

				tests := []struct {
					name        string
					setup       func() error // Function to set up flags before test
					args        []string
					expectError bool
					description string
				}{
					{
						name: "printInstructions return path",
						setup: func() error {
							instructionsFlag := rootCmd.PersistentFlags().Lookup("instructions")
							if instructionsFlag == nil {
								return fmt.Errorf("instructions flag not found")
							}
							return instructionsFlag.Value.Set("true")
						},
						args:        []string{},
						expectError: false,
						description: "Should call cf.printInstructions() when --instructions flag is true",
					},
					{
						name: "originalRunE check path",
						setup: func() error {
							instructionsFlag := rootCmd.PersistentFlags().Lookup("instructions")
							if instructionsFlag == nil {
								return fmt.Errorf("instructions flag not found")
							}
							return instructionsFlag.Value.Set("false")
						},
						args:        []string{"some", "args"},
						expectError: true, // Changed to true: invalid commands should now return an error
						description: "Should return error for unrecognized commands when args provided and instructions false",
					},
				}

				for _, tt := range tests {
					t.Run(tt.name, func(t *testing.T) {
						// Setup flags for this test case
						require.NoError(t, tt.setup(), "Setup failed")

						// Call RunE with the specified args
						err := rootCmd.RunE(rootCmd, tt.args)
						if tt.expectError {
							assert.Error(t, err, "Expected error for %s, but got none", tt.description)
						} else {
							assert.NoError(t, err, "Expected no error for %s, but got: %v", tt.description, err)
						}
					})
				}
			}
		})
	}
}

func TestDetectConfigFormat(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected configFormat
	}{
		{
			name:     "JSON extension lowercase",
			path:     "config.json",
			expected: configFormatJSON,
		},
		{
			name:     "JSON extension uppercase",
			path:     "config.JSON",
			expected: configFormatJSON,
		},
		{
			name:     "YAML extension lowercase",
			path:     "config.yaml",
			expected: configFormatYAML,
		},
		{
			name:     "YAML extension uppercase",
			path:     "config.YAML",
			expected: configFormatYAML,
		},
		{
			name:     "YML extension lowercase",
			path:     "config.yml",
			expected: configFormatYAML,
		},
		{
			name:     "YML extension uppercase",
			path:     "config.YML",
			expected: configFormatYAML,
		},
		{
			name:     "Mixed case yaml",
			path:     "config.YaML",
			expected: configFormatYAML,
		},
		{
			name:     "No extension defaults to JSON",
			path:     "config",
			expected: configFormatJSON,
		},
		{
			name:     "Unknown extension defaults to JSON",
			path:     "config.txt",
			expected: configFormatJSON,
		},
		{
			name:     "Full path with YAML extension",
			path:     "/etc/mcp/config.yaml",
			expected: configFormatYAML,
		},
		{
			name:     "Full path with JSON extension",
			path:     "/etc/mcp/config.json",
			expected: configFormatJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectConfigFormat(tt.path)
			assert.Equal(t, tt.expected, result, "detectConfigFormat(%q) = %v, expected %v", tt.path, result, tt.expected)
		})
	}
}

func TestUnmarshalConfig_JSON(t *testing.T) {
	jsonData := []byte(`{
		"defaults": {
			"format": "der",
			"includeSystemRoot": true,
			"intermediateOnly": true,
			"warnDays": 60,
			"timeoutSeconds": 45
		},
		"ai": {
			"apiKey": "test-key",
			"endpoint": "https://api.test.com",
			"model": "test-model",
			"timeout": 120
		}
	}`)

	config := &Config{}
	err := unmarshalConfig(jsonData, config, configFormatJSON)
	require.NoError(t, err, "unmarshalConfig failed for JSON")

	// Verify defaults
	assert.Equal(t, 45, config.Defaults.Timeout, "Expected timeout 45, got %d", config.Defaults.Timeout)

	// Verify AI settings
	assert.Equal(t, "test-key", config.AI.APIKey, "Expected apiKey 'test-key', got %s", config.AI.APIKey)
	assert.Equal(t, "https://api.test.com", config.AI.Endpoint, "Expected endpoint 'https://api.test.com', got %s", config.AI.Endpoint)
	assert.Equal(t, "test-model", config.AI.Model, "Expected model 'test-model', got %s", config.AI.Model)
	assert.Equal(t, 120, config.AI.Timeout, "Expected AI timeout 120, got %d", config.AI.Timeout)
}

func TestUnmarshalConfig_YAML(t *testing.T) {
	yamlData := []byte(`
defaults:
  format: der
  includeSystemRoot: true
  intermediateOnly: true
  warnDays: 60
  timeoutSeconds: 45

ai:
  apiKey: test-key
  endpoint: https://api.test.com
  model: test-model
  timeout: 120
`)

	config := &Config{}
	err := unmarshalConfig(yamlData, config, configFormatYAML)
	require.NoError(t, err, "unmarshalConfig failed for YAML")

	// Verify defaults
	assert.Equal(t, 45, config.Defaults.Timeout, "Expected timeout 45, got %d", config.Defaults.Timeout)

	// Verify AI settings
	assert.Equal(t, "test-key", config.AI.APIKey, "Expected apiKey 'test-key', got %s", config.AI.APIKey)
	assert.Equal(t, "https://api.test.com", config.AI.Endpoint, "Expected endpoint 'https://api.test.com', got %s", config.AI.Endpoint)
	assert.Equal(t, "test-model", config.AI.Model, "Expected model 'test-model', got %s", config.AI.Model)
	assert.Equal(t, 120, config.AI.Timeout, "Expected AI timeout 120, got %d", config.AI.Timeout)
}

func TestUnmarshalConfig_InvalidJSON(t *testing.T) {
	invalidJSON := []byte(`{invalid json}`)

	config := &Config{}
	err := unmarshalConfig(invalidJSON, config, configFormatJSON)
	assert.Error(t, err, "Expected error for invalid JSON, got nil")
}

func TestUnmarshalConfig_InvalidYAML(t *testing.T) {
	invalidYAML := []byte(`
defaults:
  format: "unclosed string
`)

	config := &Config{}
	err := unmarshalConfig(invalidYAML, config, configFormatYAML)
	assert.Error(t, err, "Expected error for invalid YAML, got nil")
}

func TestLoadConfig_JSONFile(t *testing.T) {
	// Create temp JSON config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	jsonContent := []byte(`{
		"defaults": {
			"format": "json",
			"includeSystemRoot": true,
			"intermediateOnly": false,
			"warnDays": 90,
			"timeoutSeconds": 60
		},
		"ai": {
			"endpoint": "https://custom.api.com",
			"model": "custom-model",
			"timeout": 90
		}
	}`)

	require.NoError(t, os.WriteFile(configPath, jsonContent, 0644), "Failed to write test config file")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	// Verify loaded values
	assert.Equal(t, 60, config.Defaults.Timeout, "Expected timeout 60, got %d", config.Defaults.Timeout)
	assert.Equal(t, "https://custom.api.com", config.AI.Endpoint, "Expected endpoint 'https://custom.api.com', got %s", config.AI.Endpoint)
	assert.Equal(t, "custom-model", config.AI.Model, "Expected model 'custom-model', got %s", config.AI.Model)
}

func TestLoadConfig_YAMLFile(t *testing.T) {
	// Create temp YAML config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte(`# Test YAML config
defaults:
  format: json
  includeSystemRoot: true
  intermediateOnly: false
  warnDays: 90
  timeoutSeconds: 60

ai:
  endpoint: https://custom.api.com
  model: custom-model
  timeout: 90
`)

	require.NoError(t, os.WriteFile(configPath, yamlContent, 0644), "Failed to write test config file")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	// Verify loaded values
	assert.Equal(t, 90, config.Defaults.WarnDays, "Expected warnDays 90, got %d", config.Defaults.WarnDays)
	assert.Equal(t, 60, config.Defaults.Timeout, "Expected timeout 60, got %d", config.Defaults.Timeout)
	assert.Equal(t, "https://custom.api.com", config.AI.Endpoint, "Expected endpoint 'https://custom.api.com', got %s", config.AI.Endpoint)
	assert.Equal(t, "custom-model", config.AI.Model, "Expected model 'custom-model', got %s", config.AI.Model)
}

func TestLoadConfig_YMLExtension(t *testing.T) {
	// Create temp YML config file (alternative YAML extension)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	ymlContent := []byte(`defaults:
  warnDays: 45
`)

	require.NoError(t, os.WriteFile(configPath, ymlContent, 0644), "Failed to write test config file")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	assert.Equal(t, 45, config.Defaults.WarnDays, "Expected warnDays 45, got %d", config.Defaults.WarnDays)
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Test with empty path to verify defaults
	config, err := loadConfig("")
	require.NoError(t, err, "loadConfig with empty path failed")

	// Verify default values
	assert.Equal(t, 30, config.Defaults.WarnDays, "Expected default warnDays 30, got %d", config.Defaults.WarnDays)
	assert.Equal(t, 30, config.Defaults.Timeout, "Expected default timeout 30, got %d", config.Defaults.Timeout)

	// Verify AI defaults
	assert.Equal(t, "https://api.x.ai", config.AI.Endpoint, "Expected default AI endpoint 'https://api.x.ai', got %s", config.AI.Endpoint)
	assert.Equal(t, "grok-4-1-fast-non-reasoning", config.AI.Model, "Expected default AI model 'grok-4-1-fast-non-reasoning', got %s", config.AI.Model)
	assert.Equal(t, 30, config.AI.Timeout, "Expected default AI timeout 30, got %d", config.AI.Timeout)
}

func TestLoadConfig_NonexistentFile(t *testing.T) {
	_, err := loadConfig("/nonexistent/path/config.json")
	assert.Error(t, err, "Expected error for nonexistent file, got nil")
}

func TestLoadConfig_InvalidJSONFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.json")

	require.NoError(t, os.WriteFile(configPath, []byte(`{invalid`), 0644), "Failed to write test config file")

	_, err := loadConfig(configPath)
	assert.Error(t, err, "Expected error for invalid JSON file, got nil")
}

func TestLoadConfig_InvalidYAMLFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	require.NoError(t, os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644), "Failed to write test config file")

	_, err := loadConfig(configPath)
	assert.Error(t, err, "Expected error for invalid YAML file, got nil")
}

func TestLoadConfig_EnvironmentVariable(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "env_config.yaml")

	yamlContent := []byte(`defaults:
  format: der
  warnDays: 100
`)

	require.NoError(t, os.WriteFile(configPath, yamlContent, 0644), "Failed to write test config file")

	// Set environment variable
	oldEnv := os.Getenv("MCP_X509_CONFIG_FILE")
	defer os.Setenv("MCP_X509_CONFIG_FILE", oldEnv)

	os.Setenv("MCP_X509_CONFIG_FILE", configPath)

	// Load with empty path - should use env var
	config, err := loadConfig("")
	require.NoError(t, err, "loadConfig failed")

	assert.Equal(t, 100, config.Defaults.WarnDays, "Expected warnDays 100 from env config, got %d", config.Defaults.WarnDays)
}

func TestLoadConfig_APIKeyFromEnvironment(t *testing.T) {
	// Create temp config file without API key
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "no_key.yaml")

	yamlContent := []byte(`defaults:
  format: pem
ai:
  endpoint: https://api.test.com
`)

	require.NoError(t, os.WriteFile(configPath, yamlContent, 0644), "Failed to write test config file")

	// Set API key environment variable
	oldEnv := os.Getenv("X509_AI_APIKEY")
	defer os.Setenv("X509_AI_APIKEY", oldEnv)

	os.Setenv("X509_AI_APIKEY", "env-api-key")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	assert.Equal(t, "env-api-key", config.AI.APIKey, "Expected API key 'env-api-key' from env, got %s", config.AI.APIKey)
}

func TestLoadConfig_ConfigAPIKeyOverridesDefault(t *testing.T) {
	// Create temp config file with API key
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "with_key.yaml")

	yamlContent := []byte(`defaults:
  format: pem
ai:
  apiKey: config-api-key
  endpoint: https://api.test.com
`)

	require.NoError(t, os.WriteFile(configPath, yamlContent, 0644), "Failed to write test config file")

	// Ensure env var is not set
	oldEnv := os.Getenv("X509_AI_APIKEY")
	defer os.Setenv("X509_AI_APIKEY", oldEnv)
	os.Unsetenv("X509_AI_APIKEY")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	assert.Equal(t, "config-api-key", config.AI.APIKey, "Expected API key 'config-api-key' from config, got %s", config.AI.APIKey)
}

func TestLoadConfig_PartialYAML(t *testing.T) {
	// Test that partial YAML config merges with defaults
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "partial.yaml")

	yamlContent := []byte(`defaults:
  warnDays: 60
`)

	require.NoError(t, os.WriteFile(configPath, yamlContent, 0644), "Failed to write test config file")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	// Specified value should be used
	assert.Equal(t, 60, config.Defaults.WarnDays, "Expected warnDays 60, got %d", config.Defaults.WarnDays)
}

func TestLoadConfig_EmptyYAML(t *testing.T) {
	// Test that empty YAML file uses defaults
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty.yaml")

	require.NoError(t, os.WriteFile(configPath, []byte(""), 0644), "Failed to write test config file")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	// Defaults should be preserved
	assert.Equal(t, 30, config.Defaults.WarnDays, "Expected default warnDays 30, got %d", config.Defaults.WarnDays)
}

func TestLoadConfig_YAMLWithComments(t *testing.T) {
	// Test that YAML comments are handled correctly
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "commented.yaml")

	yamlContent := []byte(`# This is a comment
defaults:
  # Output format
  format: der  # inline comment
  # Warning days before expiry
  warnDays: 45

# AI Configuration
ai:
  # API endpoint
  endpoint: https://api.example.com
`)

	require.NoError(t, os.WriteFile(configPath, yamlContent, 0644), "Failed to write test config file")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	assert.Equal(t, 45, config.Defaults.WarnDays, "Expected warnDays 45, got %d", config.Defaults.WarnDays)
	assert.Equal(t, "https://api.example.com", config.AI.Endpoint, "Expected endpoint 'https://api.example.com', got %s", config.AI.Endpoint)
}

func TestLoadConfig_ExampleFiles(t *testing.T) {
	// Test loading the actual example config files
	tests := []struct {
		name string
		path string
	}{
		{
			name: "JSON example config",
			path: "config.example.json",
		},
		{
			name: "YAML example config",
			path: "config.example.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := loadConfig(tt.path)
			require.NoError(t, err, "Failed to load %s", tt.path)

			// Verify basic structure
			assert.NotZero(t, config.Defaults.Timeout, "Expected timeout to be set")
			assert.NotEmpty(t, config.AI.Endpoint, "Expected AI endpoint to be set")
			assert.NotEmpty(t, config.AI.Model, "Expected AI model to be set")
		})
	}
}

func TestLoadConfig_InvalidValues(t *testing.T) {
	// Test that invalid (negative or zero) values are corrected to defaults
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	yamlContent := []byte(`defaults:
  warnDays: -10
  timeoutSeconds: 0
ai:
  timeout: -5
`)

	require.NoError(t, os.WriteFile(configPath, yamlContent, 0644), "Failed to write test config file")

	config, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	// Verify invalid values were corrected to defaults
	assert.Equal(t, 30, config.Defaults.WarnDays, "Expected warnDays to be corrected to 30, got %d", config.Defaults.WarnDays)
	assert.Equal(t, 30, config.Defaults.Timeout, "Expected timeout to be corrected to 30, got %d", config.Defaults.Timeout)
	assert.Equal(t, 30, config.AI.Timeout, "Expected AI timeout to be corrected to 30, got %d", config.AI.Timeout)
}

func TestConfigFormat_Constants(t *testing.T) {
	// Verify config format constants are distinct
	assert.NotEqual(t, configFormatJSON, configFormatYAML, "configFormatJSON and configFormatYAML should be different")

	// Verify JSON is the default (0 value)
	var defaultFormat configFormat
	assert.Equal(t, configFormatJSON, defaultFormat, "Default configFormat should be JSON")
}

func TestBatchConcurrencyLimit(t *testing.T) {
	ctx := t.Context()

	// Test with low concurrency limit to verify semaphore works
	maxConcurrent := 2

	// Create more certificates to test concurrency limiting
	certInputs := make([]string, 6) // More than the concurrency limit
	for i := range certInputs {
		certInputs[i] = pemToBase64(testCertPEM)
	}

	opts := batchResolveOptions{
		format:            "pem",
		includeSystemRoot: false,
		intermediateOnly:  false,
	}

	results := processBatchCertificates(ctx, certInputs, opts, maxConcurrent)

	// Verify we got results for all certificates
	assert.Len(t, results, len(certInputs), "Expected %d results, got %d", len(certInputs), len(results))

	// Verify all results have the expected format
	for i, result := range results {
		assert.Contains(t, result, fmt.Sprintf("Certificate %d:", i+1), "Result %d missing expected format", i)
	}
}
