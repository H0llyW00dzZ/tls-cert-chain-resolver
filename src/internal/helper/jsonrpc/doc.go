// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package jsonrpc provides helper functions for [JSON-RPC 2.0] message handling.
// It includes utilities for normalizing JSON payloads (lowercase keys), handling
// ID fields (preserving values while normalizing types), and safe unmarshaling
// of generic maps into typed structs. This package ensures compliance with
// JSON-RPC standards in the MCP transport layer.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
package jsonrpc
