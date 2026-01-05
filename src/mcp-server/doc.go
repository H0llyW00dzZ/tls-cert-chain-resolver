// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package mcpserver provides the [MCP] server framework for [X509] certificate chain resolution.
// It implements the Model Context Protocol ([MCP]) server with tools for certificate operations,
// including chain resolution, validation, expiry checking, and AI-powered analysis.
// The package uses a builder pattern for server construction and supports bidirectional AI communication.
//
// [X509]: https://grokipedia.com/page/X.509
// [MCP]: https://modelcontextprotocol.io/docs/getting-started/intro
//
//go:generate go run ../../tools/codegen
package mcpserver
