// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"fmt"
	"os"

	mcpserver "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server"
)

func main() {
	if err := mcpserver.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
