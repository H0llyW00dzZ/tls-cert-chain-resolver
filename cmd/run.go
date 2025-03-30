// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package main

import (
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/cli"
)

var version = "0.1.0" // default version if not set

func main() {
	cli.Execute(version)
}
