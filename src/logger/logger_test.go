// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package logger_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
)

func TestCLILogger(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "Printf",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewCLILogger()
				log.SetOutput(&buf)

				log.Printf("test message: %s", "hello")

				output := buf.String()
				if !strings.Contains(output, "test message: hello") {
					t.Errorf("expected output to contain 'test message: hello', got %q", output)
				}
			},
		},
		{
			name: "Println",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewCLILogger()
				log.SetOutput(&buf)

				log.Println("test", "message")

				output := buf.String()
				if !strings.Contains(output, "test message") {
					t.Errorf("expected output to contain 'test message', got %q", output)
				}
			},
		},
		{
			name: "SetOutput",
			testFunc: func(t *testing.T) {
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
			},
		},
		{
			name: "NewDefault",
			testFunc: func(t *testing.T) {
				log := logger.NewCLILogger()
				if log == nil {
					t.Error("NewCLILogger() returned nil")
				}
			},
		},
		{
			name: "ConcurrentUsage",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewCLILogger()
				log.SetOutput(&buf)

				const numGoroutines = 100
				const messagesPerGoroutine = 10

				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := range numGoroutines {
					go func(id int) {
						defer wg.Done()
						for j := range messagesPerGoroutine {
							log.Printf("goroutine %d message %d", id, j)
						}
					}(i)
				}

				wg.Wait()

				output := buf.String()
				lines := strings.Split(strings.TrimSpace(output), "\n")

				expectedLines := numGoroutines * messagesPerGoroutine
				if len(lines) != expectedLines {
					t.Errorf("expected %d log lines, got %d", expectedLines, len(lines))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}

func TestMCPLogger(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "Silent",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, true)

				log.Printf("test message: %s", "hello")
				log.Println("another message")

				if buf.Len() != 0 {
					t.Errorf("expected no output in silent mode, got %q", buf.String())
				}
			},
		},
		{
			name: "Printf_JSON",
			testFunc: func(t *testing.T) {
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
			},
		},
		{
			name: "Println_JSON",
			testFunc: func(t *testing.T) {
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
			},
		},
		{
			name: "SetOutput",
			testFunc: func(t *testing.T) {
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
			},
		},
		{
			name: "SetOutput_Nil",
			testFunc: func(t *testing.T) {
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
			},
		},
		{
			name: "NilWriter",
			testFunc: func(t *testing.T) {
				log := logger.NewMCPLogger(nil, false)

				log.Printf("test")
				log.Println("test")
			},
		},
		{
			name: "MultipleMessages",
			testFunc: func(t *testing.T) {
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
			},
		},
		{
			name: "SilentMode_NoSideEffects",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, true)

				for i := range 100 {
					log.Printf("message %d", i)
					log.Println("message", i)
				}

				if buf.Len() != 0 {
					t.Errorf("expected no output in silent mode after 200 calls, got %d bytes", buf.Len())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}

func TestMCPLogger_Concurrent(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "Printf",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, false)

				const numGoroutines = 100
				const messagesPerGoroutine = 10

				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := range numGoroutines {
					go func(id int) {
						defer wg.Done()
						for j := range messagesPerGoroutine {
							log.Printf("goroutine %d message %d", id, j)
						}
					}(i)
				}

				wg.Wait()

				output := buf.String()
				lines := strings.Split(strings.TrimSpace(output), "\n")

				expectedLines := numGoroutines * messagesPerGoroutine
				if len(lines) != expectedLines {
					t.Errorf("expected %d log lines, got %d", expectedLines, len(lines))
				}

				for i, line := range lines {
					var logEntry map[string]any
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Errorf("line %d: failed to parse JSON: %v\nLine content: %s", i+1, err, line)
					}

					if logEntry["level"] != "info" {
						t.Errorf("line %d: expected level 'info', got %v", i+1, logEntry["level"])
					}

					msg, ok := logEntry["message"].(string)
					if !ok {
						t.Errorf("line %d: message is not a string", i+1)
						continue
					}

					if !strings.Contains(msg, "goroutine") || !strings.Contains(msg, "message") {
						t.Errorf("line %d: unexpected message format: %s", i+1, msg)
					}
				}
			},
		},
		{
			name: "Println",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, false)

				const numGoroutines = 100
				const messagesPerGoroutine = 10

				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := range numGoroutines {
					go func(id int) {
						defer wg.Done()
						for j := range messagesPerGoroutine {
							log.Println("goroutine", id, "message", j)
						}
					}(i)
				}

				wg.Wait()

				output := buf.String()
				lines := strings.Split(strings.TrimSpace(output), "\n")

				expectedLines := numGoroutines * messagesPerGoroutine
				if len(lines) != expectedLines {
					t.Errorf("expected %d log lines, got %d", expectedLines, len(lines))
				}

				for i, line := range lines {
					var logEntry map[string]any
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Errorf("line %d: failed to parse JSON: %v\nLine content: %s", i+1, err, line)
					}
				}
			},
		},
		{
			name: "Mixed",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, false)

				const numGoroutines = 50
				const messagesPerGoroutine = 10

				var wg sync.WaitGroup
				wg.Add(numGoroutines * 2)

				for i := range numGoroutines {
					go func(id int) {
						defer wg.Done()
						for j := range messagesPerGoroutine {
							log.Printf("Printf goroutine %d message %d", id, j)
						}
					}(i)

					go func(id int) {
						defer wg.Done()
						for j := range messagesPerGoroutine {
							log.Println("Println goroutine", id, "message", j)
						}
					}(i)
				}

				wg.Wait()

				output := buf.String()
				lines := strings.Split(strings.TrimSpace(output), "\n")

				expectedLines := numGoroutines * 2 * messagesPerGoroutine
				if len(lines) != expectedLines {
					t.Errorf("expected %d log lines, got %d", expectedLines, len(lines))
				}

				printfCount := 0
				printlnCount := 0

				for i, line := range lines {
					var logEntry map[string]any
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Errorf("line %d: failed to parse JSON: %v", i+1, err)
						continue
					}

					msg, ok := logEntry["message"].(string)
					if !ok {
						t.Errorf("line %d: message is not a string", i+1)
						continue
					}

					if strings.HasPrefix(msg, "Printf") {
						printfCount++
					} else if strings.HasPrefix(msg, "Println") {
						printlnCount++
					}
				}

				expectedPrintfCount := numGoroutines * messagesPerGoroutine
				expectedPrintlnCount := numGoroutines * messagesPerGoroutine

				if printfCount != expectedPrintfCount {
					t.Errorf("expected %d Printf messages, got %d", expectedPrintfCount, printfCount)
				}

				if printlnCount != expectedPrintlnCount {
					t.Errorf("expected %d Println messages, got %d", expectedPrintlnCount, printlnCount)
				}
			},
		},
		{
			name: "SetOutput",
			testFunc: func(t *testing.T) {
				var buf1, buf2 bytes.Buffer
				log := logger.NewMCPLogger(&buf1, false)

				const numGoroutines = 10
				var wg sync.WaitGroup
				wg.Add(numGoroutines * 2)

				for i := range numGoroutines {
					go func(id int) {
						defer wg.Done()
						log.Printf("writer1 message %d", id)
					}(i)

					go func(id int) {
						defer wg.Done()
						if id == 5 {
							log.SetOutput(&buf2)
						}
					}(i)
				}

				wg.Wait()

				totalOutput := buf1.Len() + buf2.Len()
				if totalOutput == 0 {
					t.Error("expected some output across both buffers")
				}
			},
		},
		{
			name: "SilentMode",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, true)

				const numGoroutines = 50
				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := range numGoroutines {
					go func(id int) {
						defer wg.Done()
						log.Printf("message %d", id)
						log.Println("message", id)
					}(i)
				}

				wg.Wait()

				if buf.Len() != 0 {
					t.Errorf("expected no output in silent mode, got %d bytes", buf.Len())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}

func TestMCPLogger_WriteToFile(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "Sequential",
			testFunc: func(t *testing.T) {
				tmpFile := t.TempDir() + "/mcp-test.log"

				file, err := os.Create(tmpFile)
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				t.Cleanup(func() {
					file.Close()
					os.Remove(tmpFile)
				})

				log := logger.NewMCPLogger(file, false)

				log.Printf("test message 1: %s", "hello")
				log.Println("test message 2")
				log.Printf("test message 3: %d", 42)

				if err := file.Sync(); err != nil {
					t.Fatalf("failed to sync file: %v", err)
				}

				content, err := os.ReadFile(tmpFile)
				if err != nil {
					t.Fatalf("failed to read temp file: %v", err)
				}

				output := string(content)
				lines := strings.Split(strings.TrimSpace(output), "\n")

				if len(lines) != 3 {
					t.Errorf("expected 3 lines in file, got %d", len(lines))
				}

				for i, line := range lines {
					var logEntry map[string]any
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Errorf("line %d: failed to parse JSON: %v", i+1, err)
						continue
					}

					if logEntry["level"] != "info" {
						t.Errorf("line %d: expected level 'info', got %v", i+1, logEntry["level"])
					}
				}

				var firstEntry map[string]any
				if err := json.Unmarshal([]byte(lines[0]), &firstEntry); err != nil {
					t.Fatalf("failed to parse first log entry: %v", err)
				}

				if firstEntry["message"] != "test message 1: hello" {
					t.Errorf("expected message 'test message 1: hello', got %v", firstEntry["message"])
				}

				var secondEntry map[string]any
				if err := json.Unmarshal([]byte(lines[1]), &secondEntry); err != nil {
					t.Fatalf("failed to parse second log entry: %v", err)
				}

				if secondEntry["message"] != "test message 2" {
					t.Errorf("expected message 'test message 2', got %v", secondEntry["message"])
				}

				var thirdEntry map[string]any
				if err := json.Unmarshal([]byte(lines[2]), &thirdEntry); err != nil {
					t.Fatalf("failed to parse third log entry: %v", err)
				}

				if thirdEntry["message"] != "test message 3: 42" {
					t.Errorf("expected message 'test message 3: 42', got %v", thirdEntry["message"])
				}
			},
		},
		{
			name: "Concurrent",
			testFunc: func(t *testing.T) {
				tmpFile := t.TempDir() + "/mcp-concurrent-test.log"

				file, err := os.Create(tmpFile)
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				t.Cleanup(func() {
					file.Close()
					os.Remove(tmpFile)
				})

				log := logger.NewMCPLogger(file, false)

				const numGoroutines = 50
				const messagesPerGoroutine = 10

				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := range numGoroutines {
					go func(id int) {
						defer wg.Done()
						for j := range messagesPerGoroutine {
							log.Printf("goroutine %d message %d", id, j)
						}
					}(i)
				}

				wg.Wait()

				if err := file.Sync(); err != nil {
					t.Fatalf("failed to sync file: %v", err)
				}

				content, err := os.ReadFile(tmpFile)
				if err != nil {
					t.Fatalf("failed to read temp file: %v", err)
				}

				output := string(content)
				lines := strings.Split(strings.TrimSpace(output), "\n")

				expectedLines := numGoroutines * messagesPerGoroutine
				if len(lines) != expectedLines {
					t.Errorf("expected %d log lines, got %d", expectedLines, len(lines))
				}

				for i, line := range lines {
					var logEntry map[string]any
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Errorf("line %d: failed to parse JSON: %v\nLine content: %s", i+1, err, line)
					}

					if logEntry["level"] != "info" {
						t.Errorf("line %d: expected level 'info', got %v", i+1, logEntry["level"])
					}

					msg, ok := logEntry["message"].(string)
					if !ok {
						t.Errorf("line %d: message is not a string", i+1)
						continue
					}

					if !strings.Contains(msg, "goroutine") || !strings.Contains(msg, "message") {
						t.Errorf("line %d: unexpected message format: %s", i+1, msg)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}
