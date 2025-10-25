// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or use this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package gc

import (
	"bytes"
	"io"
)

// mockBuffer is a mock implementation of Buffer interface for testing
type mockBuffer struct {
	buf *bytes.Buffer
}

func (m *mockBuffer) Write(p []byte) (int, error) {
	return m.buf.Write(p)
}

func (m *mockBuffer) WriteString(s string) (int, error) {
	return m.buf.WriteString(s)
}

func (m *mockBuffer) WriteByte(c byte) error {
	return m.buf.WriteByte(c)
}

func (m *mockBuffer) WriteTo(w io.Writer) (int64, error) {
	return m.buf.WriteTo(w)
}

func (m *mockBuffer) ReadFrom(r io.Reader) (int64, error) {
	return m.buf.ReadFrom(r)
}

func (m *mockBuffer) Bytes() []byte {
	return m.buf.Bytes()
}

func (m *mockBuffer) String() string {
	return m.buf.String()
}

func (m *mockBuffer) Len() int {
	return m.buf.Len()
}

func (m *mockBuffer) Set(p []byte) {
	m.buf.Reset()
	m.buf.Write(p)
}

func (m *mockBuffer) SetString(s string) {
	m.buf.Reset()
	m.buf.WriteString(s)
}

func (m *mockBuffer) Reset() {
	m.buf.Reset()
}

// errorReader is a mock io.Reader that always returns an error
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}
