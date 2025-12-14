// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package logger provides abstraction and implementation for logging operations.
// It defines the Logger interface and provides two implementations: CLILogger for
// human-readable command-line output and MCPLogger for structured JSON logging
// in MCP server environments. Both implementations are thread-safe and use
// buffer pooling for efficient memory usage under high concurrency.
package logger
