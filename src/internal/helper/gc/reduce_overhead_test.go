// Copyright (c) 2024 H0llyW00dzZ All rights reserved.
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
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	// Test WriteString
	n, err := buf.WriteString("test")
	if err != nil {
		t.Errorf("WriteString failed: %v", err)
	}
	if n != 4 {
		t.Errorf("WriteString returned %d, want 4", n)
	}

	// Test WriteByte
	err = buf.WriteByte('!')
	if err != nil {
		t.Errorf("WriteByte failed: %v", err)
	}

	// Test Bytes
	result := buf.Bytes()
	expected := []byte("test!")
	if !bytes.Equal(result, expected) {
		t.Errorf("Bytes() = %q, want %q", result, expected)
	}

	// Test Reset
	buf.Reset()
	if len(buf.Bytes()) != 0 {
		t.Errorf("Reset() failed, buffer still contains data: %q", buf.Bytes())
	}
}

// TestBufferReadFrom verifies ReadFrom functionality
func TestBufferReadFrom(t *testing.T) {
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	testData := "Hello, World! This is a test."
	reader := strings.NewReader(testData)

	n, err := buf.ReadFrom(reader)
	if err != nil {
		t.Errorf("ReadFrom failed: %v", err)
	}

	if n != int64(len(testData)) {
		t.Errorf("ReadFrom read %d bytes, want %d", n, len(testData))
	}

	result := string(buf.Bytes())
	if result != testData {
		t.Errorf("ReadFrom result = %q, want %q", result, testData)
	}
}

// TestPoolGetPut verifies pool Get/Put operations
func TestPoolGetPut(t *testing.T) {
	// Get a buffer
	buf1 := Default.Get()
	if buf1 == nil {
		t.Fatal("Get() returned nil buffer")
	}

	// Write some data
	buf1.WriteString("test data")

	// Reset and return to pool
	buf1.Reset()
	Default.Put(buf1)

	// Get another buffer (might be the same one from pool)
	buf2 := Default.Get()
	if buf2 == nil {
		t.Fatal("Get() returned nil buffer after Put()")
	}

	// Should be empty (Reset was called)
	if len(buf2.Bytes()) != 0 {
		t.Errorf("Buffer from pool not empty: %q", buf2.Bytes())
	}

	buf2.Reset()
	Default.Put(buf2)
}

// TestPoolConcurrency verifies pool is safe for concurrent use
func TestPoolConcurrency(t *testing.T) {
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				buf := Default.Get()

				// Write some data
				buf.WriteString("goroutine ")
				buf.WriteByte(byte('0' + (id % 10)))

				// Verify data
				if len(buf.Bytes()) < 10 {
					t.Errorf("Buffer too small: %d bytes", len(buf.Bytes()))
				}

				// Reset and return
				buf.Reset()
				Default.Put(buf)
			}
		}(i)
	}

	wg.Wait()
}

// TestPoolPutNonByteBuffer verifies Put handles non-ByteBuffer types gracefully
func TestPoolPutNonByteBuffer(t *testing.T) {
	// Create a mock buffer that implements Buffer interface but isn't *bytebufferpool.ByteBuffer
	mockBuf := &mockBuffer{buf: bytes.NewBuffer(nil)}

	// This should not panic
	Default.Put(mockBuf)
}

// TestBufferOperationsSequence verifies a sequence of buffer operations
func TestBufferOperationsSequence(t *testing.T) {
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	// Sequence of operations
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

	// Verify length matches
	if len(buf.Bytes()) != len(expected) {
		t.Errorf("Buffer length = %d, want %d", len(buf.Bytes()), len(expected))
	}
}

// TestMultipleGetPutCycles verifies multiple Get/Put cycles work correctly
func TestMultipleGetPutCycles(t *testing.T) {
	for i := 0; i < 10; i++ {
		buf := Default.Get()

		// Write unique data
		buf.WriteString("cycle ")
		for j := 0; j < i; j++ {
			buf.WriteByte('*')
		}

		// Verify data
		expected := "cycle " + strings.Repeat("*", i)
		if string(buf.Bytes()) != expected {
			t.Errorf("Cycle %d: got %q, want %q", i, buf.Bytes(), expected)
		}

		// Reset and return
		buf.Reset()
		Default.Put(buf)
	}
}

// TestBufferReadFromLargeData verifies ReadFrom with larger data
func TestBufferReadFromLargeData(t *testing.T) {
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	// Create large test data (10KB)
	largeData := strings.Repeat("0123456789", 1024)
	reader := strings.NewReader(largeData)

	n, err := buf.ReadFrom(reader)
	if err != nil {
		t.Errorf("ReadFrom large data failed: %v", err)
	}

	if n != int64(len(largeData)) {
		t.Errorf("ReadFrom read %d bytes, want %d", n, len(largeData))
	}

	if string(buf.Bytes()) != largeData {
		t.Errorf("Large data mismatch (length: got %d, want %d)", len(buf.Bytes()), len(largeData))
	}
}

// TestBufferWriteStringEmpty verifies WriteString with empty string
func TestBufferWriteStringEmpty(t *testing.T) {
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	n, err := buf.WriteString("")
	if err != nil {
		t.Errorf("WriteString empty failed: %v", err)
	}
	if n != 0 {
		t.Errorf("WriteString empty returned %d, want 0", n)
	}
	if len(buf.Bytes()) != 0 {
		t.Errorf("Buffer not empty after WriteString empty: %q", buf.Bytes())
	}
}

// TestBufferResetMultipleTimes verifies Reset can be called multiple times
func TestBufferResetMultipleTimes(t *testing.T) {
	buf := Default.Get()
	defer func() {
		buf.Reset()
		Default.Put(buf)
	}()

	for i := 0; i < 5; i++ {
		buf.WriteString("test")
		buf.Reset()
		if len(buf.Bytes()) != 0 {
			t.Errorf("Reset %d failed, buffer contains: %q", i, buf.Bytes())
		}
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

	// Create a reader that returns an error
	errReader := &errorReader{err: io.ErrUnexpectedEOF}

	_, err := buf.ReadFrom(errReader)
	if err == nil {
		t.Error("ReadFrom should return error from reader")
	}
	if err != io.ErrUnexpectedEOF {
		t.Errorf("ReadFrom error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

// mockBuffer is a mock implementation of Buffer interface for testing
type mockBuffer struct {
	buf *bytes.Buffer
}

func (m *mockBuffer) WriteString(s string) (int, error) {
	return m.buf.WriteString(s)
}

func (m *mockBuffer) WriteByte(c byte) error {
	return m.buf.WriteByte(c)
}

func (m *mockBuffer) Bytes() []byte {
	return m.buf.Bytes()
}

func (m *mockBuffer) Reset() {
	m.buf.Reset()
}

func (m *mockBuffer) ReadFrom(r io.Reader) (int64, error) {
	return m.buf.ReadFrom(r)
}

// errorReader is a mock io.Reader that always returns an error
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}
