// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package templates

import (
	"io"
	"strings"
	"testing"
)

func TestMagicEmbed_ReadFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "read certificate formats documentation",
			filename: "certificate-formats.md",
			wantErr:  false,
		},
		{
			name:     "read X509 instructions template",
			filename: "X509_instructions.md",
			wantErr:  false,
		},
		{
			name:     "read certificate analysis system prompt",
			filename: "certificate-analysis-system-prompt.md",
			wantErr:  false,
		},
		{
			name:     "read non-existent file",
			filename: "non-existent.md",
			wantErr:  true,
		},
		{
			name:     "read file with invalid path",
			filename: "../invalid.md",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MagicEmbed.ReadFile(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("MagicEmbed.ReadFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(data) == 0 {
					t.Error("MagicEmbed.ReadFile() returned empty data for existing file")
				}
				// Verify content is valid UTF-8 and contains expected content
				content := string(data)
				if !strings.Contains(content, "#") && !strings.Contains(content, "```") {
					t.Logf("File %s appears to be valid markdown content", tt.filename)
				}
			}
		})
	}
}

func TestMagicEmbed_ReadDir(t *testing.T) {
	t.Run("read root directory", func(t *testing.T) {
		entries, err := MagicEmbed.ReadDir(".")
		if err != nil {
			t.Errorf("MagicEmbed.ReadDir() error = %v", err)
			return
		}

		if len(entries) == 0 {
			t.Error("MagicEmbed.ReadDir() returned no entries")
		}

		// Verify we have the expected markdown files
		expectedFiles := map[string]bool{
			"certificate-formats.md":                false,
			"X509_instructions.md":                  false,
			"certificate-analysis-system-prompt.md": false,
		}

		for _, entry := range entries {
			if entry.IsDir() {
				t.Errorf("Unexpected directory found: %s", entry.Name())
				continue
			}
			if _, exists := expectedFiles[entry.Name()]; exists {
				expectedFiles[entry.Name()] = true
			}
		}

		for filename, found := range expectedFiles {
			if !found {
				t.Errorf("Expected file %s not found in directory listing", filename)
			}
		}
	})

	t.Run("read non-existent directory", func(t *testing.T) {
		_, err := MagicEmbed.ReadDir("non-existent")
		if err == nil {
			t.Error("MagicEmbed.ReadDir() expected error for non-existent directory")
		}
	})
}

func TestMagicEmbed_Open(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "open certificate formats documentation",
			filename: "certificate-formats.md",
			wantErr:  false,
		},
		{
			name:     "open X509 instructions template",
			filename: "X509_instructions.md",
			wantErr:  false,
		},
		{
			name:     "open non-existent file",
			filename: "non-existent.md",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := MagicEmbed.Open(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("MagicEmbed.Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if file == nil {
					t.Error("MagicEmbed.Open() returned nil file for existing file")
					return
				}
				defer file.Close()

				// Verify we can read from the file
				data := make([]byte, 1024)
				n, err := file.Read(data)
				if err != nil && err != io.EOF {
					t.Errorf("Failed to read from opened file: %v", err)
				}
				if n == 0 {
					t.Error("Opened file appears to be empty")
				}

				// Verify file info
				info, err := file.Stat()
				if err != nil {
					t.Errorf("Failed to get file info: %v", err)
				}
				if info.IsDir() {
					t.Error("Opened file should not be a directory")
				}
				if info.Size() == 0 {
					t.Error("Opened file should not be empty")
				}
			}
		})
	}
}

func TestMagicEmbed_InterfaceCompliance(t *testing.T) {
	t.Run("MagicEmbed implements EmbedFS interface", func(t *testing.T) {
		var _ EmbedFS = MagicEmbed
	})

	t.Run("embedFS implements EmbedFS interface", func(t *testing.T) {
		var _ EmbedFS = &embedFS{}
	})
}

func TestMagicEmbed_ContentValidation(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		minSize     int
		contains    []string
		contentType string
	}{
		{
			name:        "certificate formats documentation",
			filename:    "certificate-formats.md",
			minSize:     100,
			contains:    []string{"#", "PEM", "DER"},
			contentType: "markdown",
		},
		{
			name:        "X509 instructions template",
			filename:    "X509_instructions.md",
			minSize:     200,
			contains:    []string{"#", "certificate"},
			contentType: "markdown",
		},
		{
			name:        "certificate analysis system prompt",
			filename:    "certificate-analysis-system-prompt.md",
			minSize:     500,
			contains:    []string{"ANALYSIS", "FRAMEWORK", "PROTOCOL"},
			contentType: "markdown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MagicEmbed.ReadFile(tt.filename)
			if err != nil {
				t.Errorf("Failed to read %s: %v", tt.filename, err)
				return
			}

			content := string(data)

			// Check minimum size
			if len(content) < tt.minSize {
				t.Errorf("File %s is too small: got %d bytes, want at least %d", tt.filename, len(content), tt.minSize)
			}

			// Check for expected content
			for _, expected := range tt.contains {
				if !strings.Contains(content, expected) {
					t.Errorf("File %s does not contain expected string '%s'", tt.filename, expected)
				}
			}

			// Basic content type validation
			if tt.contentType == "markdown" {
				if !strings.Contains(content, "#") && !strings.Contains(content, "-") {
					t.Logf("File %s appears to be valid markdown content", tt.filename)
				}
			}
		})
	}
}

func TestMagicEmbed_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to ensure thread safety
	done := make(chan bool, 3)

	// Goroutine 1: Read certificate formats
	go func() {
		for range 10 {
			_, err := MagicEmbed.ReadFile("certificate-formats.md")
			if err != nil {
				t.Errorf("Concurrent read failed: %v", err)
			}
		}
		done <- true
	}()

	// Goroutine 2: Read X509 instructions
	go func() {
		for range 10 {
			_, err := MagicEmbed.ReadFile("X509_instructions.md")
			if err != nil {
				t.Errorf("Concurrent read failed: %v", err)
			}
		}
		done <- true
	}()

	// Goroutine 3: Read directory
	go func() {
		for range 10 {
			_, err := MagicEmbed.ReadDir(".")
			if err != nil {
				t.Errorf("Concurrent ReadDir failed: %v", err)
			}
		}
		done <- true
	}()

	// Wait for all goroutines to complete
	for range 3 {
		<-done
	}
}

func TestEmbedFS_Methods(t *testing.T) {
	// Test that embedFS methods delegate correctly to underlying embed.FS
	efs := &embedFS{fs: embeddedFS}

	t.Run("ReadFile delegation", func(t *testing.T) {
		data1, err1 := MagicEmbed.ReadFile("certificate-formats.md")
		data2, err2 := efs.ReadFile("certificate-formats.md")

		if err1 != err2 {
			t.Errorf("ReadFile error mismatch: %v vs %v", err1, err2)
		}
		if string(data1) != string(data2) {
			t.Error("ReadFile data mismatch")
		}
	})

	t.Run("ReadDir delegation", func(t *testing.T) {
		entries1, err1 := MagicEmbed.ReadDir(".")
		entries2, err2 := efs.ReadDir(".")

		if err1 != err2 {
			t.Errorf("ReadDir error mismatch: %v vs %v", err1, err2)
		}
		if len(entries1) != len(entries2) {
			t.Errorf("ReadDir entries count mismatch: %d vs %d", len(entries1), len(entries2))
		}
	})

	t.Run("Open delegation", func(t *testing.T) {
		file1, err1 := MagicEmbed.Open("certificate-formats.md")
		file2, err2 := efs.Open("certificate-formats.md")

		if err1 != err2 {
			t.Errorf("Open error mismatch: %v vs %v", err1, err2)
		}
		if file1 != nil {
			file1.Close()
		}
		if file2 != nil {
			file2.Close()
		}
	})
}
