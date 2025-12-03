// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"fmt"
	"os"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/tools/codegen/internal"
)

func main() {
	if err := codegen.GenerateResources(); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating resources: %v\n", err)
		os.Exit(1)
	}

	if err := codegen.GenerateTools(); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating tools: %v\n", err)
		os.Exit(1)
	}

	if err := codegen.GeneratePrompts(); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating prompts: %v\n", err)
		os.Exit(1)
	}
}
