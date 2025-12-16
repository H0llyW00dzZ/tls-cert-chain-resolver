// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"testing"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/tools/codegen/internal"
)

func TestMain_NoArgs(t *testing.T) {
	// This test is mainly to get some coverage for the main package
	// The main function calls codegen functions which we can't easily test
	// without side effects, but we can test that the imports work

	// Test that we can reference the codegen functions (they exist)
	_ = codegen.GenerateResources
	_ = codegen.GenerateTools
	_ = codegen.GeneratePrompts
}
