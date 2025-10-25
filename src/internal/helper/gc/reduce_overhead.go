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
// It abstracts the [bytebufferpool.ByteBuffer] type to avoid direct dependencies.
type Buffer interface {
	// Write appends the contents of p to the buffer.
	Write(p []byte) (int, error)

	// WriteString appends the string s to the buffer.
	WriteString(s string) (int, error)

	// WriteByte appends the byte c to the buffer.
	WriteByte(c byte) error

	// WriteTo writes data to w until the buffer is drained or an error occurs.
	WriteTo(w io.Writer) (int64, error)

	// ReadFrom reads data from r until EOF and appends it to the buffer.
	ReadFrom(r io.Reader) (int64, error)

	// Bytes returns the accumulated bytes in the buffer.
	Bytes() []byte

	// String returns the accumulated string in the buffer.
	String() string

	// Len returns the number of bytes in the buffer.
	Len() int

	// Set replaces the buffer contents with p.
	Set(p []byte)

	// SetString replaces the buffer contents with s.
	SetString(s string)

	// Reset clears the buffer, retaining the underlying storage for reuse.
	Reset()
}

// Pool defines the interface for buffer pooling.
// It abstracts the [bytebufferpool.Pool] type to avoid direct dependencies.
//
// Pool implementations must be safe for concurrent use by multiple goroutines.
type Pool interface {
	Get() Buffer
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

// Default is the default buffer pool used for efficient memory reuse in I/O operations.
//
// Example usage for replacing I/O operations like ReadAll/ReadFull with Fiber's custom JSON encoder/decoder:
//
//	// Get a buffer from the pool
//	buf := gc.Default.Get()
//
//	defer func() {
//		buf.Reset()         // Reset the buffer to prevent data leaks
//		gc.Default.Put(buf) // Return the buffer to the pool for reuse
//	}()
//
//	if _, err := buf.ReadFrom(resp.Body); err != nil {
//		return "", fmt.Errorf("error reading response body: %w", err)
//	}
//
//	// Use the decoder from the Fiber app configuration
//	if err := j.c.App().Config().JSONDecoder(buf.Bytes(), &JsonStructPointer); err != nil {
//		return "", fmt.Errorf("error decoding response: %w", err)
//	}
//
// Example usage for rendering HTMX + TEMPL components:
//
//	buf := gc.Default.Get()
//
//	// Use defer to guarantee buffer cleanup (reset and return to the pool)
//	// even if an error occurs during rendering.
//	defer func() {
//		buf.Reset()         // Reset the buffer to prevent data leaks.
//		gc.Default.Put(buf) // Return the buffer to the pool for reuse.
//	}()
//
//	// Render the HTMX component into the byte buffer.
//	if err := component.Render(c.Context(), buf); err != nil {
//		// Handle any rendering errors by returning an internal server error page.
//		return v.renderErrorPage(c, fiber.StatusInternalServerError, "Error rendering component: %v", err)
//	}
//
//	// Convert the byte buffer to a string.
//	renderedHTML := buf.String()
//
//	// Set the appropriate response headers for HTMX.
//	c.Set("HX-Trigger", "update")
//	c.Set("Content-Type", "text/html")
//
//	// Send the rendered HTML as the response.
//	return c.SendString(renderedHTML)
//
// Example usage for efficient file reading:
//
//	// Get a buffer from the pool
//	buf := gc.Default.Get()
//
//	defer func() {
//		buf.Reset()         // Reset the buffer to prevent data leaks
//		gc.Default.Put(buf) // Return the buffer to the pool for reuse
//	}()
//
//	// Open the file for reading
//	file, err := os.Open("example.txt")
//	if err != nil {
//		return "", fmt.Errorf("error opening file: %w", err)
//	}
//	defer file.Close()
//
//	// Read the file contents into the buffer
//	if _, err := buf.ReadFrom(file); err != nil {
//		return "", fmt.Errorf("error reading file: %w", err)
//	}
//
//	// Process the file contents from the buffer
//	processFileContents(buf.Bytes())
//
// Example usage for handling HTTP requests and responses using the standard library net/http:
//
//	http.HandleFunc("/example", func(w http.ResponseWriter, r *http.Request) {
//		// Get a buffer from the pool
//		buf := gc.Default.Get()
//
//		defer func() {
//			buf.Reset()         // Reset the buffer to prevent data leaks
//			gc.Default.Put(buf) // Return the buffer to the pool for reuse
//		}()
//
//		// Read request body into the buffer
//		if _, err := buf.ReadFrom(r.Body); err != nil {
//			http.Error(w, "Error reading request body", http.StatusInternalServerError)
//			return
//		}
//
//		// Process the request data
//		processedData := processData(buf.Bytes())
//
//		// Set response headers
//		w.Header().Set("Content-Type", "text/plain")
//
//		// Write the processed data as the response
//		if _, err := w.Write(processedData); err != nil {
//			fmt.Printf("Error writing response: %v\n", err)
//		}
//	})
//
//	http.ListenAndServe(":8080", nil)
//
// Note: These examples demonstrate various I/O operations, such as JSON responses, rendering HTML components, reading files, and handling HTTP requests.
// Efficient memory usage is achieved by leveraging a buffer pool, which is especially beneficial in high-concurrency environments.
// For example, using 8 cores while keeping memory usage under 100MiB maintains high CPU efficiency with low memory consumption it's better.
var Default Pool = &pool{p: &bytebufferpool.Pool{}}
