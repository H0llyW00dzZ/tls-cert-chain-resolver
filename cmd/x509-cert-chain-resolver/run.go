// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	mcpserver "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server"
)

var version string // set by ldflags or defaults to imported version

func init() {
	if version == "" {
		version = mcpserver.GetVersion()
	}
}

// Keep main simple, no bloating with lots of dependencies even with Dependency Injection 🤪
func main() { mcpserver.Run(version, "") }
