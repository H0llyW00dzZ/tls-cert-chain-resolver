// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package gc provides reusable byte buffer pooling to reduce garbage collection overhead.
// It abstracts the [bytebufferpool] library to provide a consistent interface for
// buffer management across the application, particularly useful for high-throughput
// I/O operations in the MCP server and certificate processing pipelines.
//
// [bytebufferpool]: https://github.com/valyala/bytebufferpool
package gc
