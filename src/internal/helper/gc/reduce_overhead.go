// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package gc

import (
	"io"

	"github.com/valyala/bytebufferpool"
)

// Buffer defines the interface for a reusable byte buffer.
// It abstracts the [bytebufferpool.ByteBuffer] type to avoid direct dependencies
// and provides a consistent API for buffer manipulation throughout the application.
//
// The interface supports standard I/O operations (ReadFrom, WriteTo) as well as
// efficient string and byte manipulation methods. Implementations must ensure
// that the underlying storage can be reused after Reset() is called.
type Buffer interface {
	// Write appends the contents of p to the buffer.
	//
	// It implements the io.Writer interface, allowing the buffer to be used
	// as a destination for standard library I/O operations.
	//
	// Parameters:
	//   - p: Byte slice containing data to append
	//
	// Returns:
	//   - n: Number of bytes written (always len(p))
	//   - err: Always nil
	Write(p []byte) (int, error)

	// WriteString appends the string s to the buffer.
	//
	// This method is optimized for string appending without unnecessary allocations.
	//
	// Parameters:
	//   - s: String to append
	//
	// Returns:
	//   - n: Number of bytes written (len(s))
	//   - err: Always nil
	WriteString(s string) (int, error)

	// WriteByte appends the byte c to the buffer.
	//
	// Parameters:
	//   - c: Byte to append
	//
	// Returns:
	//   - err: Always nil
	WriteByte(c byte) error

	// WriteTo writes data to w until the buffer is drained or an error occurs.
	//
	// It implements the io.WriterTo interface, allowing efficient data transfer
	// from the buffer to another writer.
	//
	// Parameters:
	//   - w: Destination writer
	//
	// Returns:
	//   - n: Number of bytes written
	//   - err: Any error returned by w.Write
	WriteTo(w io.Writer) (int64, error)

	// ReadFrom reads data from r until EOF and appends it to the buffer.
	//
	// It implements the io.ReaderFrom interface, allowing the buffer to efficiently
	// consume data from a reader.
	//
	// Parameters:
	//   - r: Source reader
	//
	// Returns:
	//   - n: Number of bytes read
	//   - err: Any error returned by r.Read
	ReadFrom(r io.Reader) (int64, error)

	// Bytes returns the accumulated bytes in the buffer.
	//
	// The returned slice is valid only until the next buffer modification.
	//
	// Returns:
	//   - []byte: Slice containing the buffer contents
	Bytes() []byte

	// String returns the accumulated string in the buffer.
	//
	// Returns:
	//   - string: String representation of buffer contents
	String() string

	// Len returns the number of bytes in the buffer.
	//
	// Returns:
	//   - int: Current length of buffer data
	Len() int

	// Set replaces the buffer contents with p.
	//
	// This is equivalent to Reset() followed by Write(p), but more efficient.
	//
	// Parameters:
	//   - p: Byte slice to set as buffer content
	Set(p []byte)

	// SetString replaces the buffer contents with s.
	//
	// This is equivalent to Reset() followed by WriteString(s), but more efficient.
	//
	// Parameters:
	//   - s: String to set as buffer content
	SetString(s string)

	// Reset clears the buffer, retaining the underlying storage for reuse.
	//
	// This must be called before returning the buffer to the pool to ensure
	// no data leaks between uses.
	Reset()
}

// Pool defines the interface for buffer pooling.
// It abstracts the [bytebufferpool.Pool] type to avoid direct dependencies
// and enable efficient memory reuse.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Pool interface {
	// Get returns a buffer from the pool.
	//
	// The returned buffer may contain garbage data and should be Reset()
	// before use if not using Set/SetString.
	//
	// Returns:
	//   - Buffer: A reusable buffer instance
	Get() Buffer

	// Put returns a buffer to the pool.
	//
	// The buffer should be Reset() before calling Put() to prevent data leaks.
	//
	// Parameters:
	//   - b: Buffer to return to the pool
	Put(b Buffer)
}

// pool wraps [bytebufferpool.Pool] to implement Pool interface.
type pool struct{ p *bytebufferpool.Pool }

// Get returns a buffer from the pool.
func (p *pool) Get() Buffer { return p.p.Get() }

// Put returns a buffer to the pool.
func (p *pool) Put(b Buffer) {
	if buf, ok := b.(*bytebufferpool.ByteBuffer); ok {
		p.p.Put(buf)
	}
}

// Default is the default buffer pool used for efficient memory reuse in certificate operations.
//
// Example usage for reading certificate data:
//
//	// Get a buffer from the pool
//	buf := gc.Default.Get()
//
//	defer func() {
//		buf.Reset()         // Reset the buffer to prevent data leaks
//		gc.Default.Put(buf) // Return the buffer to the pool for reuse
//	}()
//
//	// Read certificate file into buffer
//	file, err := os.Open("cert.pem")
//	if err != nil {
//		return fmt.Errorf("error opening certificate file: %w", err)
//	}
//	defer file.Close()
//
//	if _, err := buf.ReadFrom(file); err != nil {
//		return fmt.Errorf("error reading certificate data: %w", err)
//	}
//
//	// Parse certificate from buffer
//	cert, err := x509certs.Decode(buf.Bytes())
//	if err != nil {
//		return fmt.Errorf("error parsing certificate: %w", err)
//	}
//
// Example usage for AI streaming responses:
//
//	buf := gc.Default.Get()
//
//	defer func() {
//		buf.Reset()         // Reset the buffer to prevent data leaks
//		gc.Default.Put(buf) // Return the buffer to the pool for reuse
//	}()
//
//	// Read streaming AI response into buffer
//	if _, err := buf.ReadFrom(resp.Body); err != nil {
//		return fmt.Errorf("error reading AI response: %w", err)
//	}
//
//	// Process AI analysis data
//	analysisResult := analyzeCertificateWithAI(buf.Bytes())
//
// Example usage for certificate chain encoding:
//
//	// Get a buffer from the pool
//	buf := gc.Default.Get()
//
//	defer func() {
//		buf.Reset()         // Reset the buffer to prevent data leaks
//		gc.Default.Put(buf) // Return the buffer to the pool for reuse
//	}()
//
//	// Encode multiple certificates to PEM format
//	for _, cert := range certs {
//		pemBlock := &pem.Block{
//			Type:  "CERTIFICATE",
//			Bytes: cert.Raw,
//		}
//		if err := pem.Encode(buf, pemBlock); err != nil {
//			return fmt.Errorf("error encoding certificate: %w", err)
//		}
//	}
//
//	// Write encoded certificates to file
//	if err := os.WriteFile("chain.pem", buf.Bytes(), 0644); err != nil {
//		return fmt.Errorf("error writing certificate chain: %w", err)
//	}
//
// Note: Buffer pooling provides efficient memory reuse for certificate operations,
// especially beneficial in high-concurrency environments processing multiple
// certificate chains. Memory usage remains low even under high load by reusing
// buffer allocations instead of constant allocation/deallocation.
var Default Pool = &pool{p: &bytebufferpool.Pool{}}
