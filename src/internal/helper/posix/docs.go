// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package posix provides [POSIX]-compliant helper functions for cross-platform compatibility.
//
// This package contains utility functions that ensure [POSIX]-compliant behavior
// across different operating systems, particularly for executable name handling,
// path operations, and system-level interactions that need to work consistently
// on [Unix-like] systems.
//
// The functions in this package are designed to be:
//   - [POSIX]-compliant: Using only standard library functions that work on [POSIX] systems
//   - Cross-platform safe: Handling differences between operating systems gracefully
//   - Error-resistant: Providing sensible fallbacks for edge cases
//
// Key functions:
//   - GetExecutableName: Returns the executable name without extension for CLI usage
//
// [POSIX]: https://grokipedia.com/page/POSIX
// [Unix-like]: https://grokipedia.com/page/Unix-like
package posix
