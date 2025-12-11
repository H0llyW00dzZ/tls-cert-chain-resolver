// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package templates provides embedded filesystem access for MCP server template files.
// It offers a reusable abstraction for accessing embedded markdown templates used
// throughout the MCP server, including certificate analysis documentation, system prompts,
// and server instructions.
//
// The package provides thread-safe access to embedded files through the [EmbedFS] interface,
// with [MagicEmbed] serving as the default implementation for convenient template access.
// This enables efficient reuse of template files across different MCP server components
// while maintaining clean separation of concerns and centralized template management.
//
// Key features:
//   - Thread-safe embedded file access
//   - Consistent interface abstraction over [embed.FS]
//   - Centralized template file management
//   - Support for certificate analysis, documentation, and server instructions
//
// Example usage:
//
//	import "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
//
//	// Read certificate format documentation
//	content, err := templates.MagicEmbed.ReadFile("certificate-formats.md")
//	if err != nil {
//		return fmt.Errorf("failed to read certificate formats: %w", err)
//	}
//
//	// List all available template files
//	entries, err := templates.MagicEmbed.ReadDir(".")
//	if err != nil {
//		return fmt.Errorf("failed to list templates: %w", err)
//	}
package templates
