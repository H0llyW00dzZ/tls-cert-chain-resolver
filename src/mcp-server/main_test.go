// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Test loading default config
	config, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if config == nil {
		t.Fatal("Expected config, got nil")
	}

	// Check default values
	if config.Defaults.Format != "pem" {
		t.Errorf("Expected default format 'pem', got %s", config.Defaults.Format)
	}

	if config.Defaults.WarnDays != 30 {
		t.Errorf("Expected default warn days 30, got %d", config.Defaults.WarnDays)
	}
}
