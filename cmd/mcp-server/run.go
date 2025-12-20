// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server"
)

var version string // set by ldflags or defaults to imported version

func init() {
	if version == "" {
		version = mcpserver.GetVersion()
	}
}

func main() {
	mcpserver.Run(version, "")
}
