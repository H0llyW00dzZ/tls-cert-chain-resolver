// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or use this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package gc

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBufferInterface verifies that bytebufferpool.ByteBuffer satisfies Buffer interface
func TestBufferInterface(t *testing.T) {
	tests := []struct {
		name  string
		setup func(buf Buffer)
		check func(t *testing.T, buf Buffer)
	}{
		{
			name: "Write byte slice",
			setup: func(buf Buffer) {
				buf.Write([]byte("hello"))
			},
			check: func(t *testing.T, buf Buffer) {
				assert.Equal(t, "hello", buf.String())
				assert.Equal(t, 5, buf.Len())
			},
		},
		{
			name: "WriteString",
			setup: func(buf Buffer) {
				buf.WriteString("test string")
			},
			check: func(t *testing.T, buf Buffer) {
				assert.Equal(t, "test string", buf.String())
			},
		},
		{
			name: "WriteByte",
			setup: func(buf Buffer) {
				buf.WriteByte('A')
			},
			check: func(t *testing.T, buf Buffer) {
				assert.Equal(t, "A", buf.String())
			},
		},
		{
			name: "Multiple operations",
			setup: func(buf Buffer) {
				buf.Write([]byte("hello"))
				buf.WriteString(" test")
				buf.WriteByte('!')
			},
			check: func(t *testing.T, buf Buffer) {
				expected := "hello test!"
				assert.Equal(t, expected, buf.String())
				assert.Equal(t, []byte(expected), buf.Bytes())
				assert.Equal(t, len(expected), buf.Len())
			},
		},
		{
			name: "Set byte slice",
			setup: func(buf Buffer) {
				buf.WriteString("initial")
				buf.Set([]byte("replaced"))
			},
			check: func(t *testing.T, buf Buffer) {
				assert.Equal(t, "replaced", buf.String())
			},
		},
		{
			name: "SetString",
			setup: func(buf Buffer) {
				buf.WriteString("initial")
				buf.SetString("new content")
			},
			check: func(t *testing.T, buf Buffer) {
				assert.Equal(t, "new content", buf.String())
			},
		},
		{
			name: "Reset clears buffer",
			setup: func(buf Buffer) {
				buf.WriteString("data to clear")
				buf.Reset()
			},
			check: func(t *testing.T, buf Buffer) {
				assert.Equal(t, 0, buf.Len(), "Reset() failed, buffer still contains data: %q", buf.Bytes())
			},
		},
		{
			name:  "Empty buffer",
			setup: func(buf Buffer) {},
			check: func(t *testing.T, buf Buffer) {
				assert.Equal(t, 0, buf.Len())
				assert.Equal(t, "", buf.String())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Default.Get()
			defer func() {
				buf.Reset()
				Default.Put(buf)
			}()

			tt.setup(buf)
			tt.check(t, buf)
		})
	}
}

// TestBufferReadFrom verifies ReadFrom functionality
func TestBufferReadFrom(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantLen  int64
		wantData string
		wantErr  bool
	}{
		{
			name:     "Small data",
			data:     "Hello, World!",
			wantLen:  13,
			wantData: "Hello, World!",
		},
		{
			name:     "Medium data",
			data:     "Hello, World! This is a test.",
			wantLen:  29,
			wantData: "Hello, World! This is a test.",
		},
		{
			name:     "Empty reader",
			data:     "",
			wantLen:  0,
			wantData: "",
		},
		{
			name:     "Large data (10KB)",
			data:     strings.Repeat("0123456789", 1024),
			wantLen:  10240,
			wantData: strings.Repeat("0123456789", 1024),
		},
		{
			name:     "Multiline data",
			data:     "Line 1\nLine 2\nLine 3\n",
			wantLen:  21,
			wantData: "Line 1\nLine 2\nLine 3\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Default.Get()
			defer func() {
				buf.Reset()
				Default.Put(buf)
			}()

			reader := strings.NewReader(tt.data)
			n, err := buf.ReadFrom(reader)

			if tt.wantErr {
				assert.Error(t, err, "ReadFrom() should return error")
			} else {
				assert.NoError(t, err, "ReadFrom() should not return error")
			}

			assert.Equal(t, tt.wantLen, n, "ReadFrom() read bytes")

			result := buf.String()
			assert.Equal(t, tt.wantData, result, "ReadFrom() result")
		})
	}
}

// TestPoolGetPut verifies pool Get/Put operations
func TestPoolGetPut(t *testing.T) {
	// Test 1: Get returns non-nil buffer
	buf1 := Default.Get()
	if buf1 == nil {
		require.Fail(t, "Get() returned nil buffer")
	}

	// Test 2: Buffer can be written to and reset
	buf1.WriteString("test data")
	assert.Equal(t, 9, buf1.Len(), "WriteString() length")
	buf1.Reset()
	assert.Equal(t, 0, buf1.Len(), "Reset() failed")

	// Return to pool (buf1 must not be accessed after this)
	Default.Put(buf1)

	// Test 3: Pool can provide another buffer after Put
	buf2 := Default.Get()
	if buf2 == nil {
		require.Fail(t, "Get() returned nil buffer after Put()")
	}

	// Test 4: New buffer from pool should be empty (Reset called before Put)
	assert.Equal(t, 0, buf2.Len(), "Buffer from pool should be empty")

	buf2.Reset()
	Default.Put(buf2)
}

// TestGoroutineCooking verifies the pool is safe for concurrent use (with 100 goroutines sizzling!)
func TestGoroutineCooking(t *testing.T) {
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			for range iterations {
				buf := Default.Get()

				buf.WriteString("goroutine #")
				buf.WriteByte(byte('0' + (id % 10)))
				buf.WriteString(" is sizzling on the CPU like a perfectly grilled steak 🥩")

				assert.GreaterOrEqual(t, len(buf.Bytes()), 10, "Buffer should be large enough")

				buf.Reset()
				Default.Put(buf)
			}
		}(i)
	}

	wg.Wait()
}

// TestPoolPutNonByteBuffer verifies Put handles non-ByteBuffer types gracefully
func TestPoolPutNonByteBuffer(t *testing.T) {
	mockBuf := &mockBuffer{buf: bytes.NewBuffer(nil)}
	Default.Put(mockBuf)
}

// TestBufferOperationsSequence verifies a sequence of buffer operations
func TestBufferOperationsSequence(t *testing.T) {
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	buf.WriteString("Line 1\n")
	buf.WriteString("Line 2\n")
	buf.WriteByte('\n')

	reader := strings.NewReader("Line 3\n")
	buf.ReadFrom(reader)

	expected := "Line 1\nLine 2\n\nLine 3\n"
	result := string(buf.Bytes())

	assert.Equal(t, expected, result, "Buffer sequence result")

	if len(buf.Bytes()) != len(expected) {
		assert.Equal(t, len(expected), len(buf.Bytes()))
	}
}

// TestMultipleGetPutCycles verifies multiple Get/Put cycles work correctly
func TestMultipleGetPutCycles(t *testing.T) {
	for i := range 10 {
		buf := Default.Get()

		buf.WriteString("cycle ")
		for range i {
			buf.WriteByte('*')
		}

		expected := "cycle " + strings.Repeat("*", i)
		assert.Equal(t, expected, string(buf.Bytes()), "Cycle %d", i)

		buf.Reset()
		Default.Put(buf)
	}
}

// TestBufferWriteMethods verifies various write operations
func TestBufferWriteMethods(t *testing.T) {
	tests := []struct {
		name       string
		operation  func(buf Buffer) (int, error)
		wantLen    int
		wantResult string
	}{
		{
			name: "WriteString empty",
			operation: func(buf Buffer) (int, error) {
				return buf.WriteString("")
			},
			wantLen:    0,
			wantResult: "",
		},
		{
			name: "WriteString normal",
			operation: func(buf Buffer) (int, error) {
				return buf.WriteString("test")
			},
			wantLen:    4,
			wantResult: "test",
		},
		{
			name: "Write empty slice",
			operation: func(buf Buffer) (int, error) {
				return buf.Write([]byte{})
			},
			wantLen:    0,
			wantResult: "",
		},
		{
			name: "Write normal slice",
			operation: func(buf Buffer) (int, error) {
				return buf.Write([]byte("hello"))
			},
			wantLen:    5,
			wantResult: "hello",
		},
		{
			name: "WriteByte",
			operation: func(buf Buffer) (int, error) {
				err := buf.WriteByte('X')
				return 1, err
			},
			wantLen:    1,
			wantResult: "X",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Default.Get()
			defer func() {
				buf.Reset()
				Default.Put(buf)
			}()

			n, err := tt.operation(buf)
			require.NoError(t, err, "%s failed", tt.name)

			if n != tt.wantLen {
				assert.Equal(t, tt.wantLen, n, "%s return value", tt.name)
			}

			if buf.String() != tt.wantResult {
				assert.Equal(t, tt.wantResult, buf.String(), "%s result", tt.name)
			}
		})
	}
}

// TestBufferResetBehavior verifies Reset behavior in various scenarios
func TestBufferResetBehavior(t *testing.T) {
	tests := []struct {
		name       string
		operations func(buf Buffer)
		wantLen    int
	}{
		{
			name: "Reset after WriteString",
			operations: func(buf Buffer) {
				buf.WriteString("test")
				buf.Reset()
			},
			wantLen: 0,
		},
		{
			name: "Reset after Write",
			operations: func(buf Buffer) {
				buf.Write([]byte("data"))
				buf.Reset()
			},
			wantLen: 0,
		},
		{
			name: "Multiple Reset calls",
			operations: func(buf Buffer) {
				for range 5 {
					buf.WriteString("test")
					buf.Reset()
				}
			},
			wantLen: 0,
		},
		{
			name: "Reset empty buffer",
			operations: func(buf Buffer) {
				buf.Reset()
			},
			wantLen: 0,
		},
		{
			name: "Reset after large write",
			operations: func(buf Buffer) {
				buf.WriteString(strings.Repeat("x", 10000))
				buf.Reset()
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Default.Get()
			defer func() {
				buf.Reset()
				Default.Put(buf)
			}()

			tt.operations(buf)

			assert.Equal(t, tt.wantLen, buf.Len(), "After operations Len() (buffer: %q)", buf.Bytes())
			assert.Equal(t, "", buf.String(), "After operations String()")
		})
	}
}

// TestPoolInterfaceImplementation verifies pool type implements Pool interface
func TestPoolInterfaceImplementation(t *testing.T) {
	var _ Pool = &pool{}
	var _ Pool = Default
}

// TestBufferReadFromError verifies ReadFrom handles read errors
func TestBufferReadFromError(t *testing.T) {
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	errReader := &errorReader{err: io.ErrUnexpectedEOF}

	_, err := buf.ReadFrom(errReader)
	if err == nil {
		assert.Fail(t, "ReadFrom should return error from reader")
	}
	assert.Equal(t, io.ErrUnexpectedEOF, err, "ReadFrom error")
}

// TestBufferWriteTo verifies WriteTo functionality
func TestBufferWriteTo(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantLen int64
	}{
		{
			name:    "Small data",
			data:    "Hello",
			wantLen: 5,
		},
		{
			name:    "Medium data",
			data:    "Hello, World! Testing WriteTo.",
			wantLen: 30,
		},
		{
			name:    "Empty buffer",
			data:    "",
			wantLen: 0,
		},
		{
			name:    "Large data",
			data:    strings.Repeat("test", 100),
			wantLen: 400,
		},
		{
			name:    "Multiline data",
			data:    "Line 1\nLine 2\nLine 3",
			wantLen: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Default.Get()

			buf.WriteString(tt.data)

			var output bytes.Buffer
			n, err := buf.WriteTo(&output)
			assert.NoError(t, err, "WriteTo() error")

			assert.Equal(t, tt.wantLen, n, "WriteTo() wrote bytes")

			assert.Equal(t, tt.data, output.String(), "WriteTo() output")

			// Return to pool only after all assertions complete
			buf.Reset()
			Default.Put(buf)
		})
	}
}

// TestBufferSetMethods verifies Set and SetString functionality
func TestBufferSetMethods(t *testing.T) {
	tests := []struct {
		name        string
		initialData string
		operation   func(buf Buffer)
		wantData    string
		wantLen     int
	}{
		{
			name:        "Set byte slice",
			initialData: "initial data",
			operation: func(buf Buffer) {
				buf.Set([]byte("replaced with Set"))
			},
			wantData: "replaced with Set",
			wantLen:  17,
		},
		{
			name:        "SetString",
			initialData: "initial data",
			operation: func(buf Buffer) {
				buf.SetString("replaced with SetString")
			},
			wantData: "replaced with SetString",
			wantLen:  23,
		},
		{
			name:        "Set empty slice",
			initialData: "some data",
			operation: func(buf Buffer) {
				buf.Set([]byte{})
			},
			wantData: "",
			wantLen:  0,
		},
		{
			name:        "SetString empty",
			initialData: "some data",
			operation: func(buf Buffer) {
				buf.SetString("")
			},
			wantData: "",
			wantLen:  0,
		},
		{
			name:        "Set on empty buffer",
			initialData: "",
			operation: func(buf Buffer) {
				buf.Set([]byte("new data"))
			},
			wantData: "new data",
			wantLen:  8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Default.Get()
			defer func() {
				buf.Reset()
				Default.Put(buf)
			}()

			buf.WriteString(tt.initialData)
			tt.operation(buf)

			assert.Equal(t, tt.wantData, buf.String(), "operation result")
			assert.Equal(t, tt.wantLen, buf.Len(), "operation length")
		})
	}
}

// TestBufferLenMethod verifies Len returns correct length
func TestBufferLenMethod(t *testing.T) {
	tests := []struct {
		name       string
		operations func(buf Buffer)
		wantLen    int
	}{
		{
			name:       "Empty buffer",
			operations: func(buf Buffer) {},
			wantLen:    0,
		},
		{
			name: "After WriteString",
			operations: func(buf Buffer) {
				buf.WriteString("test data")
			},
			wantLen: 9,
		},
		{
			name: "After multiple writes",
			operations: func(buf Buffer) {
				buf.WriteString("test")
				buf.WriteString(" more")
			},
			wantLen: 9,
		},
		{
			name: "After Write byte slice",
			operations: func(buf Buffer) {
				buf.Write([]byte("hello world"))
			},
			wantLen: 11,
		},
		{
			name: "After WriteByte",
			operations: func(buf Buffer) {
				buf.WriteByte('A')
				buf.WriteByte('B')
				buf.WriteByte('C')
			},
			wantLen: 3,
		},
		{
			name: "After Set",
			operations: func(buf Buffer) {
				buf.WriteString("initial")
				buf.Set([]byte("replaced"))
			},
			wantLen: 8,
		},
		{
			name: "After Reset",
			operations: func(buf Buffer) {
				buf.WriteString("data")
				buf.Reset()
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Default.Get()
			defer func() {
				buf.Reset()
				Default.Put(buf)
			}()

			tt.operations(buf)

			if buf.Len() != tt.wantLen {
				assert.Equal(t, tt.wantLen, buf.Len())
			}
		})
	}
}
