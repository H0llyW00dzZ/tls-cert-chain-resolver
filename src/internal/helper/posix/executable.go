// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package posix

import (
	"os"
	"path/filepath"
	"strings"
)

// GetExecutableName returns the executable name without extension, cross-platform compatible.
// It extracts the base name from os.Args[0] and removes common executable extensions
// (.exe on Windows) to provide a clean name for CLI usage strings.
//
// This ensures consistent behavior across all operating systems:
//   - Linux/macOS: "myapp" from "/usr/local/bin/myapp"
//   - Windows: "myapp" from "C:\bin\myapp.exe"
//   - Fallback: Uses "x509-cert-chain-resolver" if os.Args[0] is unavailable
//
// Returns:
//   - string: Clean executable name suitable for CLI usage
func GetExecutableName() string {
	// This literally never happens. If it happens, then it's not an operating system.
	if len(os.Args) == 0 || os.Args[0] == "" {
		return "x509-cert-chain-resolver" // fallback name
	}

	// First try filepath.Base which handles the current OS correctly
	name := filepath.Base(os.Args[0])

	// If that didn't extract a proper base name (e.g., Windows path on Unix),
	// try to extract the last component manually by splitting on path separators
	if strings.Contains(name, "\\") || (strings.Contains(name, "/") && !strings.Contains(name, string(filepath.Separator))) {
		// Split on both possible separators and take the last non-empty part
		parts := strings.FieldsFunc(name, func(r rune) bool {
			return r == '/' || r == '\\'
		})
		for i := len(parts) - 1; i >= 0; i-- {
			if parts[i] != "" {
				name = parts[i]
				break
			}
		}
	}

	// Remove common executable extensions for clean CLI display
	// This handles .exe on Windows while preserving other extensions
	name = strings.TrimSuffix(name, ".exe")

	return name
}
