// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
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
)

const version = "1.3.3.7-testing"

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
				if err := os.WriteFile(tmpFile, []byte("invalid data"), 0644); err != nil {
					t.Fatal(err)
				}
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
				if !errors.Is(err, tt.expectedError) {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				}
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
				if !strings.Contains(string(outputData), "BEGIN CERTIFICATE") {
					t.Error("expected PEM format in output")
				}
			},
		},
		{
			name:          "DER Output",
			args:          []string{"--der"},
			outputFileExt: ".der",
			validateOutput: func(t *testing.T, outputData []byte) {
				if len(outputData) == 0 {
					t.Error("expected non-empty DER output")
				}
				if strings.Contains(string(outputData), "BEGIN CERTIFICATE") {
					t.Error("expected DER format (binary), not PEM format")
				}
			},
		},
		{
			name:          "Intermediate Only",
			args:          []string{"--intermediate-only"},
			outputFileExt: ".pem",
			validateOutput: func(t *testing.T, outputData []byte) {
				if len(outputData) == 0 {
					t.Error("expected non-empty output")
				}
			},
		},
		{
			name:          "Include System Root CA",
			args:          []string{"--include-system"},
			outputFileExt: ".pem",
			skipOnMacOS:   true,
			validateOutput: func(t *testing.T, outputData []byte) {
				if len(outputData) == 0 {
					t.Error("expected non-empty output")
				}
			},
		},
		{
			name:          "JSON Output",
			args:          []string{"--json"},
			outputFileExt: ".json",
			validateOutput: func(t *testing.T, outputData []byte) {
				var jsonData map[string]any
				if err := json.Unmarshal(outputData, &jsonData); err != nil {
					t.Fatalf("failed to parse JSON output: %v", err)
				}

				if title, ok := jsonData["title"].(string); !ok || title != "TLS Certificate Resolver" {
					t.Errorf("expected title 'TLS Certificate Resolver', got %v", jsonData["title"])
				}

				if _, ok := jsonData["totalChained"].(float64); !ok {
					t.Error("expected totalChained field in JSON output")
				}

				if certs, ok := jsonData["listCertificates"].([]any); !ok || len(certs) == 0 {
					t.Error("expected non-empty listCertificates array in JSON output")
				}
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

			if err := os.WriteFile(inputFile, []byte(testCertPEM), 0644); err != nil {
				t.Fatal(err)
			}
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
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !cli.OperationPerformed {
				t.Error("expected OperationPerformed to be true")
			}

			if !cli.OperationPerformedSuccessfully {
				t.Error("expected OperationPerformedSuccessfully to be true")
			}

			outputData, err := os.ReadFile(outputFile)
			if err != nil {
				t.Fatalf("failed to read output file: %v", err)
			}

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
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Remove(inputFile)
	})

	cancel()

	os.Args = []string{"cmd", "-f", inputFile}

	err := cli.Execute(ctx, version, log)
	if err == nil {
		t.Error("expected error due to context cancellation")
	}
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
				if !strings.Contains(output, "BEGIN CERTIFICATE") {
					t.Error("expected PEM format in stdout")
				}
				if !strings.Contains(output, "END CERTIFICATE") {
					t.Error("expected complete PEM certificate in stdout")
				}
			},
		},
		{
			name: "JSON to Stdout",
			args: []string{"--json"},
			validateStdout: func(t *testing.T, output string) {
				var jsonData map[string]any
				if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
					t.Fatalf("failed to parse JSON output from stdout: %v", err)
				}

				if title, ok := jsonData["title"].(string); !ok || title != "TLS Certificate Resolver" {
					t.Errorf("expected title 'TLS Certificate Resolver', got %v", jsonData["title"])
				}

				if _, ok := jsonData["totalChained"].(float64); !ok {
					t.Error("expected totalChained field in JSON stdout output")
				}

				if certs, ok := jsonData["listCertificates"].([]any); !ok || len(certs) == 0 {
					t.Error("expected non-empty listCertificates array in JSON stdout output")
				}
			},
		},
		{
			name: "Intermediate Only to Stdout",
			args: []string{"--intermediate-only"},
			validateStdout: func(t *testing.T, output string) {
				if len(output) == 0 {
					t.Error("expected non-empty stdout output")
				}
				if !strings.Contains(output, "BEGIN CERTIFICATE") {
					t.Error("expected PEM format in stdout for intermediate certificates")
				}
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
				t.Fatal(err)
			}
			t.Cleanup(func() {
				os.Remove(inputFile)
			})

			// Redirect stdout to capture output
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
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

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !cli.OperationPerformed {
				t.Error("expected OperationPerformed to be true")
			}

			if !cli.OperationPerformedSuccessfully {
				t.Error("expected OperationPerformedSuccessfully to be true")
			}

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
		t.Fatal(err)
	}

	// Use directory as output file to force write error
	outputFile := tmpDir

	os.Args = []string{"cmd", "-f", inputFile, "-o", outputFile}

	err := cli.Execute(ctx, version, log)

	if err == nil {
		t.Error("expected error writing to directory, got nil")
	}

	if !strings.Contains(err.Error(), "error writing to output file") {
		t.Errorf("expected 'error writing to output file' error, got: %v", err)
	}
}
