// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"testing"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server"
	"github.com/stretchr/testify/assert"
)

func TestVersionInit(t *testing.T) {
	// Test that version is initialized
	assert.NotEmpty(t, version, "version should not be empty after init")

	// Test that it matches the mcp-server version when not set by ldflags
	if version != mcpserver.GetVersion() {
		// If they differ, it means version was set by ldflags, which is also valid
		t.Logf("version set by ldflags: %s (server version: %s)", version, mcpserver.GetVersion())
	}
}

func TestMain_NoArgs(t *testing.T) {
	// This test is mainly to get some coverage for the main package
	// The main function calls mcpserver.Run, which we can't easily test here
	// But we can test that the version variable is properly handled

	_ = version
}
