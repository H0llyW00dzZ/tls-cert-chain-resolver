// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package templates

import (
	"embed"
	"io/fs"
)

//go:embed *.md
var embeddedFS embed.FS

// EmbedFS defines the interface for accessing embedded template files.
// It abstracts the [embed.FS] type to avoid direct dependencies
// and provides a consistent API for template file access throughout the application.
//
// The interface supports standard file system operations for reading embedded files.
// Implementations must ensure thread-safe access to embedded resources.
type EmbedFS interface {
	// ReadFile reads the named file and returns the contents.
	//
	// Parameters:
	//   - name: Path to the embedded file (relative to embed root)
	//
	// Returns:
	//   - []byte: File contents
	//   - error: Any error reading the file
	ReadFile(name string) ([]byte, error)

	// ReadDir reads the named directory and returns a list of directory entries.
	//
	// Parameters:
	//   - name: Path to the embedded directory (relative to embed root)
	//
	// Returns:
	//   - []fs.DirEntry: Directory entries
	//   - error: Any error reading the directory
	ReadDir(name string) ([]fs.DirEntry, error)

	// Open opens the named file for reading.
	//
	// Parameters:
	//   - name: Path to the embedded file (relative to embed root)
	//
	// Returns:
	//   - fs.File: Opened file handle
	//   - error: Any error opening the file
	Open(name string) (fs.File, error)
}

// embedFS wraps [embed.FS] to implement EmbedFS interface.
type embedFS struct{ fs embed.FS }

// ReadFile reads the named file and returns the contents.
func (e *embedFS) ReadFile(name string) ([]byte, error) { return e.fs.ReadFile(name) }

// ReadDir reads the named directory and returns a list of directory entries.
func (e *embedFS) ReadDir(name string) ([]fs.DirEntry, error) { return e.fs.ReadDir(name) }

// Open opens the named file for reading.
func (e *embedFS) Open(name string) (fs.File, error) { return e.fs.Open(name) }

// MagicEmbed is the embedded filesystem used for accessing template files.
// It provides magical access to embedded markdown templates for certificate analysis,
// documentation, and MCP server instructions.
//
// Example usage for reading certificate format documentation:
//
//	// Read certificate formats documentation
//	content, err := templates.MagicEmbed.ReadFile("certificate-formats.md")
//	if err != nil {
//		return fmt.Errorf("failed to read certificate formats: %w", err)
//	}
//
// Example usage for reading MCP server instructions:
//
//	// Read MCP server instructions template
//	templateBytes, err := templates.MagicEmbed.ReadFile("X509_instructions.md")
//	if err != nil {
//		return "", fmt.Errorf("failed to load instructions template: %w", err)
//	}
//
// Example usage for reading AI analysis system prompt:
//
//	// Read certificate analysis system prompt
//	prompt, err := templates.MagicEmbed.ReadFile("certificate-analysis-system-prompt.md")
//	if err != nil {
//		return "", fmt.Errorf("failed to read system prompt: %w", err)
//	}
//
// Note: This provides centralized access to all embedded template files,
// enabling efficient reuse across different MCP server components while
// maintaining clean separation of concerns and a touch of magic ✨.
var MagicEmbed EmbedFS = &embedFS{fs: embeddedFS}
