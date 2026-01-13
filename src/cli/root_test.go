// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package cli_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/cli"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const version = "1.3.3.7-testing"

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

func TestExecute_ErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		setupFile     func(t *testing.T) string
		expectedError error
	}{
		{
			name: "No Input File",
			setupFile: func(t *testing.T) string {
				return ""
			},
			expectedError: cli.ErrInputFileRequired,
		},
		{
			name: "Invalid Certificate File",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid.cer")
				require.NoError(t, os.WriteFile(tmpFile, []byte("invalid data"), 0644), "Failed to write test file")
				return tmpFile
			},
			expectedError: nil,
		},
		{
			name: "Non-Existent File",
			setupFile: func(t *testing.T) string {
				return "/tmp/nonexistent-file-12345.cer"
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			log := logger.NewMCPLogger(io.Discard, true)

			inputFile := tt.setupFile(t)
			if inputFile != "" {
				os.Args = []string{"cmd", "-f", inputFile}
			} else {
				os.Args = []string{"cmd"}
			}

			err := cli.Execute(ctx, version, log)

			if tt.expectedError != nil {
				assert.Error(t, err, "Expected error")
				assert.True(t, errors.Is(err, tt.expectedError), "expected error %v, got %v", tt.expectedError, err)
			} else {
				assert.Error(t, err, "expected error, got nil")
			}
		})
	}
}

func TestExecute_ValidCertificate(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		outputFileExt  string
		skipOnMacOS    bool
		validateOutput func(t *testing.T, outputData []byte)
		expectError    bool
	}{
		{
			name:          "PEM Output",
			args:          []string{},
			outputFileExt: ".pem",
			validateOutput: func(t *testing.T, outputData []byte) {
				assert.Contains(t, string(outputData), "BEGIN CERTIFICATE", "expected PEM format in output")
			},
		},
		{
			name:          "DER Output",
			args:          []string{"--der"},
			outputFileExt: ".der",
			validateOutput: func(t *testing.T, outputData []byte) {
				assert.NotEmpty(t, outputData, "expected non-empty DER output")
				assert.NotContains(t, string(outputData), "BEGIN CERTIFICATE", "expected DER format (binary), not PEM format")
			},
		},
		{
			name:          "JSON Output",
			args:          []string{"--json"},
			outputFileExt: ".json",
			validateOutput: func(t *testing.T, outputData []byte) {
				var jsonData map[string]any
				require.NoError(t, json.Unmarshal(outputData, &jsonData), "failed to parse JSON output")

				if title, ok := jsonData["title"].(string); !ok || title != "TLS Certificate Resolver" {
					assert.Equal(t, "TLS Certificate Resolver", title, "expected title 'TLS Certificate Resolver', got %v", jsonData["title"])
				}

				_, ok := jsonData["totalChained"].(float64)
				assert.True(t, ok, "expected totalChained field in JSON output")

				_, ok = jsonData["listCertificates"].([]any)
				assert.True(t, ok, "expected non-empty listCertificates array in JSON output")
			},
		},
		{
			name:          "Include System Root CA",
			args:          []string{"--include-system"},
			outputFileExt: ".pem",
			skipOnMacOS:   true,
			validateOutput: func(t *testing.T, outputData []byte) {
				assert.NotEmpty(t, outputData, "expected non-empty output")
			},
		},
		{
			name:          "Intermediate Only",
			args:          []string{"--intermediate-only"},
			outputFileExt: ".pem",
			validateOutput: func(t *testing.T, outputData []byte) {
				assert.NotEmpty(t, outputData, "expected non-empty output")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnMacOS && runtime.GOOS == "darwin" {
				t.Skip("Skipping on macOS: system certificate validation has stricter EKU constraints")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			log := logger.NewMCPLogger(io.Discard, true)

			tmpDir := t.TempDir()
			inputFile := filepath.Join(tmpDir, "google.cer")
			outputFile := filepath.Join(tmpDir, "output"+tt.outputFileExt)

			require.NoError(t, os.WriteFile(inputFile, []byte(testCertPEM), 0644), "Failed to write test certificate file")
			t.Cleanup(func() {
				os.Remove(inputFile)
				os.Remove(outputFile)
			})

			args := []string{"cmd", "-f", inputFile, "-o", outputFile}
			args = append(args, tt.args...)
			os.Args = args

			cli.OperationPerformed = false
			cli.OperationPerformedSuccessfully = false

			err := cli.Execute(ctx, version, log)

			if tt.expectError {
				assert.Error(t, err, "expected error, got nil")
				return
			}

			assert.NoError(t, err, "unexpected error")

			assert.True(t, cli.OperationPerformed, "expected OperationPerformed to be true")

			assert.True(t, cli.OperationPerformedSuccessfully, "expected OperationPerformedSuccessfully to be true")

			outputData, err := os.ReadFile(outputFile)
			require.NoError(t, err, "failed to read output file")

			if tt.validateOutput != nil {
				tt.validateOutput(t, outputData)
			}
		})
	}
}

func TestExecute_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	log := logger.NewMCPLogger(io.Discard, true)

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "google.cer")

	if err := os.WriteFile(inputFile, []byte(testCertPEM), 0644); err != nil {
		require.NoError(t, err, "Unexpected error")
	}
	t.Cleanup(func() {
		os.Remove(inputFile)
	})

	cancel()

	os.Args = []string{"cmd", "-f", inputFile}

	err := cli.Execute(ctx, version, log)
	assert.Error(t, err, "expected error due to context cancellation")
}

func TestExecute_StdoutOutput(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		validateStdout func(t *testing.T, output string)
	}{
		{
			name: "PEM to Stdout",
			args: []string{},
			validateStdout: func(t *testing.T, output string) {
				assert.Contains(t, output, "BEGIN CERTIFICATE", "expected PEM format in stdout")
				assert.Contains(t, output, "END CERTIFICATE", "expected complete PEM certificate in stdout")
			},
		},
		{
			name: "JSON to Stdout",
			args: []string{"--json"},
			validateStdout: func(t *testing.T, output string) {
				var jsonData map[string]any
				require.NoError(t, json.Unmarshal([]byte(output), &jsonData), "failed to parse JSON output from stdout")

				if title, ok := jsonData["title"].(string); !ok || title != "TLS Certificate Resolver" {
					assert.Equal(t, "TLS Certificate Resolver", title, "expected title 'TLS Certificate Resolver', got %v", jsonData["title"])
				}

				_, ok := jsonData["totalChained"].(float64)
				assert.True(t, ok, "expected totalChained field in JSON stdout output")

				_, ok = jsonData["listCertificates"].([]any)
				assert.True(t, ok, "expected non-empty listCertificates array in JSON stdout output")

				if title, ok := jsonData["title"].(string); !ok || title != "TLS Certificate Resolver" {
					assert.Equal(t, "TLS Certificate Resolver", title, "expected title 'TLS Certificate Resolver', got %v", jsonData["title"])
				}

				_, ok = jsonData["totalChained"].(float64)
				assert.True(t, ok, "expected totalChained field in JSON stdout output")

				if certs, ok := jsonData["listCertificates"].([]any); !ok || len(certs) == 0 {
					assert.True(t, ok && len(certs) > 0, "expected non-empty listCertificates array in JSON stdout output")
				}
			},
		},
		{
			name: "Intermediate Only to Stdout",
			args: []string{"--intermediate-only"},
			validateStdout: func(t *testing.T, output string) {
				assert.NotEmpty(t, output, "expected non-empty stdout output")
				assert.Contains(t, output, "BEGIN CERTIFICATE", "expected PEM format in stdout for intermediate certificates")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			log := logger.NewMCPLogger(io.Discard, true)

			tmpDir := t.TempDir()
			inputFile := filepath.Join(tmpDir, "google.cer")

			if err := os.WriteFile(inputFile, []byte(testCertPEM), 0644); err != nil {
				require.NoError(t, err, "Unexpected error")
			}
			t.Cleanup(func() {
				os.Remove(inputFile)
			})

			// Redirect stdout to capture output
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			require.NoError(t, err, "Unexpected error")
			os.Stdout = w

			// Build args without -o flag to write to stdout
			args := []string{"cmd", "-f", inputFile}
			args = append(args, tt.args...)
			os.Args = args

			cli.OperationPerformed = false
			cli.OperationPerformedSuccessfully = false

			// Capture stdout in goroutine
			outputChan := make(chan string, 1)
			go func() {
				var buf strings.Builder
				io.Copy(&buf, r)
				outputChan <- buf.String()
			}()

			// Execute command
			err = cli.Execute(ctx, version, log)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Get captured output
			output := <-outputChan
			r.Close()

			assert.NoError(t, err, "unexpected error")

			assert.True(t, cli.OperationPerformed, "expected OperationPerformed to be true")

			assert.True(t, cli.OperationPerformedSuccessfully, "expected OperationPerformedSuccessfully to be true")

			if tt.validateStdout != nil {
				tt.validateStdout(t, output)
			}
		})
	}
}

func TestExecute_WriteError(t *testing.T) {
	ctx := context.Background()
	log := logger.NewMCPLogger(io.Discard, true)

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "google.cer")

	// Create input file
	if err := os.WriteFile(inputFile, []byte(testCertPEM), 0644); err != nil {
		require.NoError(t, err, "Unexpected error")
	}

	// Use directory as output file to force write error
	outputFile := tmpDir

	os.Args = []string{"cmd", "-f", inputFile, "-o", outputFile}

	err := cli.Execute(ctx, version, log)

	assert.Error(t, err, "expected error writing to directory, got nil")

	assert.Contains(t, err.Error(), "error writing to output file", "expected 'error writing to output file' error, got: %v", err)
}
