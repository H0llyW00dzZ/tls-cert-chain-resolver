// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package cli_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/cli"
)

const version = "1.3.3.7-testing"

func TestExecute_NoInputFile(t *testing.T) {
	ctx := context.Background()
	err := cli.Execute(ctx, version)
	if !errors.Is(err, cli.ErrInputFileRequired) {
		t.Errorf("expected ErrInputFileRequired, got %v", err)
	}
}

func TestExecute_InvalidFile(t *testing.T) {
	ctx := context.Background()

	tmpFile := filepath.Join(t.TempDir(), "invalid.cer")
	if err := os.WriteFile(tmpFile, []byte("invalid data"), 0644); err != nil {
		t.Fatal(err)
	}

	os.Args = []string{"cmd", "-f", tmpFile}
	err := cli.Execute(ctx, version)
	if err == nil {
		t.Error("expected error for invalid certificate file")
	}
}

func TestExecute_NonExistentFile(t *testing.T) {
	ctx := context.Background()

	os.Args = []string{"cmd", "-f", "/tmp/nonexistent-file-12345.cer"}
	err := cli.Execute(ctx, version)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}
