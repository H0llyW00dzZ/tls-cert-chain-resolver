// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
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
				if buf.String() != "hello" {
					t.Errorf("Write() result = %q, want %q", buf.String(), "hello")
				}
				if buf.Len() != 5 {
					t.Errorf("Write() length = %d, want 5", buf.Len())
				}
			},
		},
		{
			name: "WriteString",
			setup: func(buf Buffer) {
				buf.WriteString("test string")
			},
			check: func(t *testing.T, buf Buffer) {
				if buf.String() != "test string" {
					t.Errorf("WriteString() result = %q, want %q", buf.String(), "test string")
				}
			},
		},
		{
			name: "WriteByte",
			setup: func(buf Buffer) {
				buf.WriteByte('A')
			},
			check: func(t *testing.T, buf Buffer) {
				if buf.String() != "A" {
					t.Errorf("WriteByte() result = %q, want %q", buf.String(), "A")
				}
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
				if buf.String() != expected {
					t.Errorf("String() = %q, want %q", buf.String(), expected)
				}
				if !bytes.Equal(buf.Bytes(), []byte(expected)) {
					t.Errorf("Bytes() = %q, want %q", buf.Bytes(), expected)
				}
				if buf.Len() != len(expected) {
					t.Errorf("Len() = %d, want %d", buf.Len(), len(expected))
				}
			},
		},
		{
			name: "Set byte slice",
			setup: func(buf Buffer) {
				buf.WriteString("initial")
				buf.Set([]byte("replaced"))
			},
			check: func(t *testing.T, buf Buffer) {
				if buf.String() != "replaced" {
					t.Errorf("Set() result = %q, want %q", buf.String(), "replaced")
				}
			},
		},
		{
			name: "SetString",
			setup: func(buf Buffer) {
				buf.WriteString("initial")
				buf.SetString("new content")
			},
			check: func(t *testing.T, buf Buffer) {
				if buf.String() != "new content" {
					t.Errorf("SetString() result = %q, want %q", buf.String(), "new content")
				}
			},
		},
		{
			name: "Reset clears buffer",
			setup: func(buf Buffer) {
				buf.WriteString("data to clear")
				buf.Reset()
			},
			check: func(t *testing.T, buf Buffer) {
				if buf.Len() != 0 {
					t.Errorf("Reset() failed, buffer still contains data: %q", buf.Bytes())
				}
			},
		},
		{
			name:  "Empty buffer",
			setup: func(buf Buffer) {},
			check: func(t *testing.T, buf Buffer) {
				if buf.Len() != 0 {
					t.Errorf("Empty buffer Len() = %d, want 0", buf.Len())
				}
				if buf.String() != "" {
					t.Errorf("Empty buffer String() = %q, want empty", buf.String())
				}
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

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFrom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if n != tt.wantLen {
				t.Errorf("ReadFrom() read %d bytes, want %d", n, tt.wantLen)
			}

			result := buf.String()
			if result != tt.wantData {
				if len(result) != len(tt.wantData) {
					t.Errorf("ReadFrom() length mismatch: got %d, want %d", len(result), len(tt.wantData))
				} else {
					t.Errorf("ReadFrom() = %q, want %q", result, tt.wantData)
				}
			}
		})
	}
}

// TestPoolGetPut verifies pool Get/Put operations
func TestPoolGetPut(t *testing.T) {
	buf1 := Default.Get()
	if buf1 == nil {
		t.Fatal("Get() returned nil buffer")
	}

	buf1.WriteString("test data")
	buf1.Reset()
	Default.Put(buf1)

	buf2 := Default.Get()
	if buf2 == nil {
		t.Fatal("Get() returned nil buffer after Put()")
	}

	if len(buf2.Bytes()) != 0 {
		t.Errorf("Buffer from pool not empty: %q", buf2.Bytes())
	}

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

				if len(buf.Bytes()) < 10 {
					t.Errorf("Buffer too small: %d bytes", len(buf.Bytes()))
				}

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

	if result != expected {
		t.Errorf("Buffer sequence result = %q, want %q", result, expected)
	}

	if len(buf.Bytes()) != len(expected) {
		t.Errorf("Buffer length = %d, want %d", len(buf.Bytes()), len(expected))
	}
}

// TestMultipleGetPutCycles verifies multiple Get/Put cycles work correctly
func TestMultipleGetPutCycles(t *testing.T) {
	for i := range 10 {
		buf := Default.Get()

		buf.WriteString("cycle ")
		for j := 0; j < i; j++ {
			buf.WriteByte('*')
		}

		expected := "cycle " + strings.Repeat("*", i)
		if string(buf.Bytes()) != expected {
			t.Errorf("Cycle %d: got %q, want %q", i, buf.Bytes(), expected)
		}

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
			if err != nil {
				t.Errorf("%s failed: %v", tt.name, err)
			}

			if n != tt.wantLen {
				t.Errorf("%s returned %d, want %d", tt.name, n, tt.wantLen)
			}

			if buf.String() != tt.wantResult {
				t.Errorf("%s result = %q, want %q", tt.name, buf.String(), tt.wantResult)
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

			if buf.Len() != tt.wantLen {
				t.Errorf("After operations Len() = %d, want %d (buffer: %q)", buf.Len(), tt.wantLen, buf.Bytes())
			}

			if buf.String() != "" {
				t.Errorf("After operations String() = %q, want empty", buf.String())
			}
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
		t.Error("ReadFrom should return error from reader")
	}
	if err != io.ErrUnexpectedEOF {
		t.Errorf("ReadFrom error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
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
			defer func() {
				buf.Reset()
				Default.Put(buf)
			}()

			buf.WriteString(tt.data)

			var output bytes.Buffer
			n, err := buf.WriteTo(&output)
			if err != nil {
				t.Errorf("WriteTo() error = %v", err)
			}

			if n != tt.wantLen {
				t.Errorf("WriteTo() wrote %d bytes, want %d", n, tt.wantLen)
			}

			if output.String() != tt.data {
				t.Errorf("WriteTo() output = %q, want %q", output.String(), tt.data)
			}
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

			if buf.String() != tt.wantData {
				t.Errorf("operation result = %q, want %q", buf.String(), tt.wantData)
			}

			if buf.Len() != tt.wantLen {
				t.Errorf("operation length = %d, want %d", buf.Len(), tt.wantLen)
			}
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
				t.Errorf("Len() = %d, want %d", buf.Len(), tt.wantLen)
			}
		})
	}
}
