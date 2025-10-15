// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// Logger defines the interface for logging operations.
// It provides methods for different log levels and formatted output.
//
// This interface supports both CLI and [MCP] server modes, allowing seamless
// switching between human-readable output and structured logging.
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type Logger interface {
	// Printf formats and prints a log message.
	Printf(format string, v ...any)
	// Println prints a log message with a newline.
	Println(v ...any)
	// SetOutput sets the output destination for the logger.
	SetOutput(w io.Writer)
}

// CLILogger implements Logger using the standard log package.
// It's designed for command-line interface output with human-readable formatting.
type CLILogger struct{ logger *log.Logger }

// NewCLILogger creates a new CLI logger with timestamps disabled.
// This is suitable for user-facing CLI output.
func NewCLILogger() *CLILogger {
	l := log.New(os.Stdout, "", 0)
	return &CLILogger{logger: l}
}

// Printf formats and prints a log message using fmt.Printf semantics.
func (c *CLILogger) Printf(format string, v ...any) { c.logger.Printf(format, v...) }

// Println prints a log message with a newline.
func (c *CLILogger) Println(v ...any) { c.logger.Println(v...) }

// SetOutput sets the output destination for the CLI logger.
func (c *CLILogger) SetOutput(w io.Writer) { c.logger.SetOutput(w) }

// MCPLogger implements Logger for [MCP] server mode.
// It suppresses output by default since MCP communication happens over stdio,
// but can be configured to write structured logs to a separate destination.
//
// MCPLogger is safe for concurrent use by multiple goroutines.
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
type MCPLogger struct {
	mu     sync.Mutex
	writer io.Writer
	silent bool
}

// NewMCPLogger creates a new [MCP] logger.
// By default, it's silent (output suppressed) to avoid interfering with [MCP] stdio protocol.
// Set silent=false and provide a writer to enable structured logging to a file or stderr.
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
func NewMCPLogger(writer io.Writer, silent bool) *MCPLogger {
	if writer == nil {
		writer = io.Discard
	}
	return &MCPLogger{
		writer: writer,
		silent: silent,
	}
}

// Printf formats and logs a structured message in JSON format.
// Output is suppressed if silent mode is enabled.
//
// The JSON format is compatible with [MCP] protocol logging requirements.
//
// Printf is safe for concurrent use by multiple goroutines.
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
func (m *MCPLogger) Printf(format string, v ...any) {
	if m.silent {
		return
	}

	msg := fmt.Sprintf(format, v...)
	logEntry := map[string]any{
		"level":   "info",
		"message": msg,
	}

	data, _ := json.Marshal(logEntry)

	m.mu.Lock()
	fmt.Fprintln(m.writer, string(data))
	m.mu.Unlock()
}

// Println logs a structured message in JSON format.
// Output is suppressed if silent mode is enabled.
//
// The JSON format is compatible with [MCP] protocol logging requirements.
//
// Println is safe for concurrent use by multiple goroutines.
//
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
func (m *MCPLogger) Println(v ...any) {
	if m.silent {
		return
	}

	msg := fmt.Sprint(v...)
	logEntry := map[string]any{
		"level":   "info",
		"message": msg,
	}

	data, _ := json.Marshal(logEntry)

	m.mu.Lock()
	fmt.Fprintln(m.writer, string(data))
	m.mu.Unlock()
}

// SetOutput sets the output destination for the MCP logger.
//
// SetOutput is safe for concurrent use by multiple goroutines.
func (m *MCPLogger) SetOutput(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if w == nil {
		m.writer = io.Discard
	} else {
		m.writer = w
	}
}
