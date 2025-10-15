// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package logger_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
)

func TestCLILogger_Printf(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewCLILogger()
	log.SetOutput(&buf)

	log.Printf("test message: %s", "hello")

	output := buf.String()
	if !strings.Contains(output, "test message: hello") {
		t.Errorf("expected output to contain 'test message: hello', got %q", output)
	}
}

func TestCLILogger_Println(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewCLILogger()
	log.SetOutput(&buf)

	log.Println("test", "message")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected output to contain 'test message', got %q", output)
	}
}

func TestCLILogger_SetOutput(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	log := logger.NewCLILogger()

	log.SetOutput(&buf1)
	log.Println("first")

	log.SetOutput(&buf2)
	log.Println("second")

	if !strings.Contains(buf1.String(), "first") {
		t.Errorf("expected buf1 to contain 'first', got %q", buf1.String())
	}

	if !strings.Contains(buf2.String(), "second") {
		t.Errorf("expected buf2 to contain 'second', got %q", buf2.String())
	}

	if strings.Contains(buf1.String(), "second") {
		t.Errorf("buf1 should not contain 'second', got %q", buf1.String())
	}
}

func TestMCPLogger_Silent(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, true)

	log.Printf("test message: %s", "hello")
	log.Println("another message")

	if buf.Len() != 0 {
		t.Errorf("expected no output in silent mode, got %q", buf.String())
	}
}

func TestMCPLogger_Printf_JSON(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	log.Printf("test message: %s", "hello")

	output := buf.String()
	if output == "" {
		t.Fatal("expected output, got empty string")
	}

	var logEntry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if logEntry["level"] != "info" {
		t.Errorf("expected level 'info', got %v", logEntry["level"])
	}

	if logEntry["message"] != "test message: hello" {
		t.Errorf("expected message 'test message: hello', got %v", logEntry["message"])
	}
}

func TestMCPLogger_Println_JSON(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	log.Println("test message")

	output := buf.String()
	if output == "" {
		t.Fatal("expected output, got empty string")
	}

	var logEntry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if logEntry["level"] != "info" {
		t.Errorf("expected level 'info', got %v", logEntry["level"])
	}

	if logEntry["message"] != "test message" {
		t.Errorf("expected message 'test message', got %v", logEntry["message"])
	}
}

func TestMCPLogger_SetOutput(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	log := logger.NewMCPLogger(&buf1, false)

	log.Println("first")

	log.SetOutput(&buf2)
	log.Println("second")

	if buf1.Len() == 0 {
		t.Error("expected buf1 to have content")
	}

	if buf2.Len() == 0 {
		t.Error("expected buf2 to have content")
	}

	if strings.Contains(buf1.String(), "second") {
		t.Errorf("buf1 should not contain 'second', got %q", buf1.String())
	}

	if strings.Contains(buf2.String(), "first") {
		t.Errorf("buf2 should not contain 'first', got %q", buf2.String())
	}
}

func TestMCPLogger_SetOutput_Nil(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	log.Println("before")

	log.SetOutput(nil)
	log.Println("after")

	output := buf.String()
	if !strings.Contains(output, "before") {
		t.Error("expected 'before' in output")
	}

	if strings.Contains(output, "after") {
		t.Error("should not contain 'after' after setting nil output")
	}
}

func TestNewMCPLogger_NilWriter(t *testing.T) {
	log := logger.NewMCPLogger(nil, false)

	log.Printf("test")
	log.Println("test")
}

func TestMCPLogger_MultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	log.Printf("message 1: %d", 1)
	log.Printf("message 2: %d", 2)
	log.Println("message 3")

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}

	for i, line := range lines {
		var logEntry map[string]any
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			t.Errorf("line %d: failed to parse JSON: %v", i+1, err)
		}
	}
}

func TestCLILogger_NewDefault(t *testing.T) {
	log := logger.NewCLILogger()
	if log == nil {
		t.Error("NewCLILogger() returned nil")
	}
}

func TestMCPLogger_SilentMode_NoSideEffects(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, true)

	for i := range 100 {
		log.Printf("message %d", i)
		log.Println("message", i)
	}

	if buf.Len() != 0 {
		t.Errorf("expected no output in silent mode after 200 calls, got %d bytes", buf.Len())
	}
}
