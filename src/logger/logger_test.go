// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				assert.Contains(t, output, "test message: hello", "expected output to contain 'test message: hello'")
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
				assert.Contains(t, output, "test message", "expected output to contain 'test message'")
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

				assert.Contains(t, buf1.String(), "first", "expected buf1 to contain 'first'")
				assert.Contains(t, buf2.String(), "second", "expected buf2 to contain 'second'")
				assert.NotContains(t, buf1.String(), "second", "buf1 should not contain 'second'")
			},
		},
		{
			name: "NewDefault",
			testFunc: func(t *testing.T) {
				log := logger.NewCLILogger()
				assert.NotNil(t, log, "NewCLILogger() returned nil")
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
				assert.Equal(t, expectedLines, len(lines), "expected %d log lines")
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

				assert.Equal(t, 0, buf.Len(), "expected no output in silent mode")
			},
		},
		{
			name: "Printf_JSON",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, false)

				log.Printf("test message: %s", "hello")

				output := buf.String()
				assert.Contains(t, output, "test message: hello", "expected output to contain 'test message: hello'")

				var logEntry map[string]any
				require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry), "failed to parse JSON output")

				assert.Equal(t, "info", logEntry["level"], "expected level 'info'")
				assert.Equal(t, "test message: hello", logEntry["message"], "expected message 'test message: hello'")
			},
		},
		{
			name: "Println_JSON",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, false)

				log.Println("test message")

				output := buf.String()
				require.NotEmpty(t, output, "expected output, got empty string")

				var logEntry map[string]any
				require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry), "failed to parse JSON output")

				assert.Equal(t, "info", logEntry["level"], "expected level 'info'")
				assert.Equal(t, "test message", logEntry["message"], "expected message 'test message'")
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

				assert.NotZero(t, buf1.Len(), "expected buf1 to have content")
				assert.NotZero(t, buf2.Len(), "expected buf2 to have content")
				assert.NotContains(t, buf1.String(), "second", "buf1 should not contain 'second'")
				assert.NotContains(t, buf2.String(), "first", "buf2 should not contain 'first'")
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
				assert.Contains(t, output, "before", "expected 'before' in output")
				assert.NotContains(t, output, "after", "should not contain 'after' after setting nil output")
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

				assert.Len(t, lines, 3, "expected 3 lines")

				for i, line := range lines {
					var logEntry map[string]any
					assert.NoError(t, json.Unmarshal([]byte(line), &logEntry), "line %d: failed to parse JSON", i+1)
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

				assert.Equal(t, 0, buf.Len(), "expected no output in silent mode after 200 calls")
			},
		},
		{
			name: "JSONEscaping_SpecialChars",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, false)

				// Test all JSON escape characters
				testCases := []struct {
					input           string
					expectedMessage string
				}{
					{`test"quote`, `test"quote`},
					{`test\backslash`, `test\backslash`},
					{"test\nnewline", "test\nnewline"},
					{"test\rcarriage", "test\rcarriage"},
					{"test\ttab", "test\ttab"},
					{"test\bbackspace", "test\bbackspace"},
					{"test\fformfeed", "test\fformfeed"},
					{"test\x01control", "test\x01control"},
					{"test\x1fcontrol", "test\x1fcontrol"},
					{`mixed"test\with` + "\nspecial\tchars", `mixed"test\with` + "\nspecial\tchars"},
				}

				for _, tc := range testCases {
					buf.Reset()
					log.Printf("%s", tc.input)

					output := buf.String()
					var logEntry map[string]any
					require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry),
						"input %q: failed to parse JSON\nOutput: %s", tc.input, output)

					msg, ok := logEntry["message"].(string)
					require.True(t, ok, "input %q: message is not a string", tc.input)

					assert.Equal(t, tc.expectedMessage, msg, "input %q: expected message %q", tc.input, tc.expectedMessage)
				}
			},
		},
		{
			name: "JSONEscaping_Println",
			testFunc: func(t *testing.T) {
				var buf bytes.Buffer
				log := logger.NewMCPLogger(&buf, false)

				// Test escape characters with Println
				testCases := []struct {
					input           string
					expectedMessage string
				}{
					{`quote"test`, `quote"test`},
					{"newline\ntest", "newline\ntest"},
					{"tab\ttest", "tab\ttest"},
					{"control\x01test", "control\x01test"},
				}

				for _, tc := range testCases {
					buf.Reset()
					log.Println(tc.input)

					output := buf.String()
					var logEntry map[string]any
					require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry),
						"input %q: failed to parse JSON\nOutput: %s", tc.input, output)

					msg, ok := logEntry["message"].(string)
					require.True(t, ok, "input %q: message is not a string", tc.input)

					assert.Equal(t, tc.expectedMessage, msg, "input %q: expected message %q", tc.input, tc.expectedMessage)
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
				assert.Equal(t, expectedLines, len(lines), "expected %d log lines")

				for i, line := range lines {
					var logEntry map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &logEntry),
						"line %d: failed to parse JSON\nLine content: %s", i+1, line)

					assert.Equal(t, "info", logEntry["level"], "line %d: expected level 'info'", i+1)

					msg, ok := logEntry["message"].(string)
					require.True(t, ok, "line %d: message is not a string", i+1)

					assert.Contains(t, msg, "goroutine", "line %d: expected message to contain 'goroutine'", i+1)
					assert.Contains(t, msg, "message", "line %d: expected message to contain 'message'", i+1)
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
				assert.Equal(t, expectedLines, len(lines), "expected %d log lines")

				for i, line := range lines {
					var logEntry map[string]any
					assert.NoError(t, json.Unmarshal([]byte(line), &logEntry),
						"line %d: failed to parse JSON\nLine content: %s", i+1, line)
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
				assert.Equal(t, expectedLines, len(lines), "expected %d log lines")

				printfCount := 0
				printlnCount := 0

				for i, line := range lines {
					var logEntry map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &logEntry),
						"line %d: failed to parse JSON", i+1)

					msg, ok := logEntry["message"].(string)
					require.True(t, ok, "line %d: message is not a string", i+1)

					if strings.HasPrefix(msg, "Printf") {
						printfCount++
					} else if strings.HasPrefix(msg, "Println") {
						printlnCount++
					}
				}

				expectedPrintfCount := numGoroutines * messagesPerGoroutine
				expectedPrintlnCount := numGoroutines * messagesPerGoroutine

				assert.Equal(t, expectedPrintfCount, printfCount, "expected %d Printf messages", expectedPrintfCount)
				assert.Equal(t, expectedPrintlnCount, printlnCount, "expected %d Println messages", expectedPrintlnCount)
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
				assert.NotZero(t, totalOutput, "expected some output across both buffers")
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

				assert.Equal(t, 0, buf.Len(), "expected no output in silent mode")
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
				require.NoError(t, err, "failed to create temp file")
				t.Cleanup(func() {
					file.Close()
					os.Remove(tmpFile)
				})

				log := logger.NewMCPLogger(file, false)

				log.Printf("test message 1: %s", "hello")
				log.Println("test message 2")
				log.Printf("test message 3: %d", 42)

				require.NoError(t, file.Sync(), "failed to sync file")

				content, err := os.ReadFile(tmpFile)
				require.NoError(t, err, "failed to read temp file")

				output := string(content)
				lines := strings.Split(strings.TrimSpace(output), "\n")

				assert.Len(t, lines, 3, "expected 3 lines in file")

				for i, line := range lines {
					var logEntry map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &logEntry),
						"line %d: failed to parse JSON", i+1)

					assert.Equal(t, "info", logEntry["level"], "line %d: expected level 'info'", i+1)
				}

				var firstEntry map[string]any
				require.NoError(t, json.Unmarshal([]byte(lines[0]), &firstEntry), "failed to parse first log entry")

				assert.Equal(t, "test message 1: hello", firstEntry["message"], "expected message 'test message 1: hello'")

				var secondEntry map[string]any
				require.NoError(t, json.Unmarshal([]byte(lines[1]), &secondEntry), "failed to parse second log entry")

				assert.Equal(t, "test message 2", secondEntry["message"], "expected message 'test message 2'")

				var thirdEntry map[string]any
				require.NoError(t, json.Unmarshal([]byte(lines[2]), &thirdEntry), "failed to parse third log entry")

				assert.Equal(t, "test message 3: 42", thirdEntry["message"], "expected message 'test message 3: 42'")
			},
		},
		{
			name: "Concurrent",
			testFunc: func(t *testing.T) {
				tmpFile := t.TempDir() + "/mcp-concurrent-test.log"

				file, err := os.Create(tmpFile)
				require.NoError(t, err, "failed to create temp file")
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

				require.NoError(t, file.Sync(), "failed to sync file")

				content, err := os.ReadFile(tmpFile)
				require.NoError(t, err, "failed to read temp file")

				output := string(content)
				lines := strings.Split(strings.TrimSpace(output), "\n")

				expectedLines := numGoroutines * messagesPerGoroutine
				assert.Equal(t, expectedLines, len(lines), "expected %d log lines")

				for i, line := range lines {
					var logEntry map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &logEntry),
						"line %d: failed to parse JSON\nLine content: %s", i+1, line)

					assert.Equal(t, "info", logEntry["level"], "line %d: expected level 'info'", i+1)

					msg, ok := logEntry["message"].(string)
					require.True(t, ok, "line %d: message is not a string", i+1)

					assert.Contains(t, msg, "goroutine", "line %d: expected message to contain 'goroutine'", i+1)
					assert.Contains(t, msg, "message", "line %d: expected message to contain 'message'", i+1)
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
