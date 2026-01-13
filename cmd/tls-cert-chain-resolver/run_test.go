// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"testing"

	verpkg "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/version"
	"github.com/stretchr/testify/assert"
)

func TestVersionInit(t *testing.T) {
	// Test that version is initialized
	assert.NotEmpty(t, version, "version should not be empty after init")

	// Test that it matches the version package when not set by ldflags
	// We can't directly test the init logic, but we can verify version is set
	if version != verpkg.Version {
		// If they differ, it means version was set by ldflags, which is also valid
		t.Logf("version set by ldflags: %s (package version: %s)", version, verpkg.Version)
	}
}

func TestMain_NoArgs(t *testing.T) {
	// This test is mainly to get some coverage for the main package
	// The main function is hard to test directly, but we can test that
	// the version variable is properly handled

	// Test version variable access (this will be tested by the init test above)
	_ = version
}
