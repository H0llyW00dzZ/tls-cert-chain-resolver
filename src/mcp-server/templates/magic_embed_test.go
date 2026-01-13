// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package templates

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			if tt.wantErr {
				assert.Error(t, err, "MagicEmbed.ReadFile() should return error for %s", tt.filename)
			} else {
				require.NoError(t, err, "MagicEmbed.ReadFile() should not return error for %s", tt.filename)
				assert.NotEmpty(t, data, "MagicEmbed.ReadFile() should return non-empty data for existing file")
				// Verify content is valid UTF-8 and contains expected content
				content := string(data)
				assert.True(t, strings.Contains(content, "#") || strings.Contains(content, ":") || strings.Contains(content, "```"),
					"File %s should contain structured content", tt.filename)
			}
		})
	}
}

func TestMagicEmbed_ReadDir(t *testing.T) {
	t.Run("read root directory", func(t *testing.T) {
		entries, err := MagicEmbed.ReadDir(".")
		require.NoError(t, err, "MagicEmbed.ReadDir() should not return error")
		assert.NotEmpty(t, entries, "MagicEmbed.ReadDir() should return entries")

		// Verify we have the expected markdown files
		expectedFiles := map[string]bool{
			"certificate-formats.md":                false,
			"X509_instructions.md":                  false,
			"certificate-analysis-system-prompt.md": false,
		}

		for _, entry := range entries {
			assert.False(t, entry.IsDir(), "Unexpected directory found: %s", entry.Name())
			if _, exists := expectedFiles[entry.Name()]; exists {
				expectedFiles[entry.Name()] = true
			}
		}

		for filename, found := range expectedFiles {
			assert.True(t, found, "Expected file %s not found in directory listing", filename)
		}
	})

	t.Run("read non-existent directory", func(t *testing.T) {
		_, err := MagicEmbed.ReadDir("non-existent")
		assert.Error(t, err, "MagicEmbed.ReadDir() should return error for non-existent directory")
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
			if tt.wantErr {
				assert.Error(t, err, "MagicEmbed.Open() should return error for %s", tt.filename)
				assert.Nil(t, file, "MagicEmbed.Open() should return nil file for %s", tt.filename)
			} else {
				require.NoError(t, err, "MagicEmbed.Open() should not return error for %s", tt.filename)
				require.NotNil(t, file, "MagicEmbed.Open() should return file for %s", tt.filename)
				defer file.Close()

				// Verify we can read from the file
				data := make([]byte, 1024)
				n, err := file.Read(data)
				if err != nil && err != io.EOF {
					assert.NoError(t, err, "Failed to read from opened file")
				}
				assert.Greater(t, n, 0, "Opened file should contain data")

				// Verify file info
				info, err := file.Stat()
				require.NoError(t, err, "Should be able to get file info")
				assert.False(t, info.IsDir(), "Opened file should not be a directory")
				assert.Greater(t, info.Size(), int64(0), "Opened file should not be empty")
			}
		})
	}
}

func TestMagicEmbed_InterfaceCompliance(t *testing.T) {
	t.Run("MagicEmbed implements EmbedFS interface", func(t *testing.T) {
		var _ EmbedFS = MagicEmbed
		assert.NotNil(t, MagicEmbed, "MagicEmbed should implement EmbedFS interface")
	})

	t.Run("embedFS implements EmbedFS interface", func(t *testing.T) {
		var _ EmbedFS = &embedFS{}
		efs := &embedFS{}
		assert.NotNil(t, efs, "embedFS should implement EmbedFS interface")
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
			require.NoError(t, err, "Failed to read %s", tt.filename)

			content := string(data)

			// Check minimum size
			assert.GreaterOrEqual(t, len(content), tt.minSize,
				"File %s should be at least %d bytes, got %d", tt.filename, tt.minSize, len(content))

			// Check for expected content
			for _, expected := range tt.contains {
				assert.Contains(t, content, expected,
					"File %s should contain expected string '%s'", tt.filename, expected)
			}

			// Basic content type validation
			if tt.contentType == "markdown" {
				assert.True(t, strings.Contains(content, "#") || strings.Contains(content, "-"),
					"File %s should contain markdown formatting", tt.filename)
			}
		})
	}
}

func TestMagicEmbed_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to ensure thread safety
	done := make(chan bool, 3)
	errors := make(chan error, 30) // Buffer for potential errors

	// Goroutine 1: Read certificate formats
	go func() {
		for range 10 {
			_, err := MagicEmbed.ReadFile("certificate-formats.md")
			if err != nil {
				errors <- err
			}
		}
		done <- true
	}()

	// Goroutine 2: Read X509 instructions
	go func() {
		for range 10 {
			_, err := MagicEmbed.ReadFile("X509_instructions.md")
			if err != nil {
				errors <- err
			}
		}
		done <- true
	}()

	// Goroutine 3: Read directory
	go func() {
		for range 10 {
			_, err := MagicEmbed.ReadDir(".")
			if err != nil {
				errors <- err
			}
		}
		done <- true
	}()

	// Wait for all goroutines to complete
	for range 3 {
		select {
		case <-done:
			// Goroutine completed
		case err := <-errors:
			assert.NoError(t, err, "Concurrent operation failed")
		}
	}

	// Check for any remaining errors
	close(errors)
	for err := range errors {
		assert.NoError(t, err, "Concurrent operation failed")
	}
}

func TestEmbedFS_Methods(t *testing.T) {
	// Test that embedFS methods delegate correctly to underlying embed.FS
	efs := &embedFS{fs: embeddedFS}

	t.Run("ReadFile delegation", func(t *testing.T) {
		data1, err1 := MagicEmbed.ReadFile("certificate-formats.md")
		data2, err2 := efs.ReadFile("certificate-formats.md")

		assert.Equal(t, err1, err2, "ReadFile error should match")
		assert.Equal(t, string(data1), string(data2), "ReadFile data should match")
	})

	t.Run("ReadDir delegation", func(t *testing.T) {
		entries1, err1 := MagicEmbed.ReadDir(".")
		entries2, err2 := efs.ReadDir(".")

		assert.Equal(t, err1, err2, "ReadDir error should match")
		assert.Len(t, entries2, len(entries1), "ReadDir entries count should match")
	})

	t.Run("Open delegation", func(t *testing.T) {
		file1, err1 := MagicEmbed.Open("certificate-formats.md")
		file2, err2 := efs.Open("certificate-formats.md")

		assert.Equal(t, err1, err2, "Open error should match")
		if file1 != nil {
			file1.Close()
		}
		if file2 != nil {
			file2.Close()
		}
	})
}
