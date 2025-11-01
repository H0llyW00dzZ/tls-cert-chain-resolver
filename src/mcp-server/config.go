// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents MCP server configuration
type Config struct {
	Defaults struct {
		Format            string `json:"format"`
		IncludeSystemRoot bool   `json:"includeSystemRoot"`
		IntermediateOnly  bool   `json:"intermediateOnly"`
		WarnDays          int    `json:"warnDays"`
		Port              int    `json:"port"`
		Timeout           int    `json:"timeoutSeconds"`
	} `json:"defaults"`
}

func loadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults
	config.Defaults.Format = "pem"
	config.Defaults.IncludeSystemRoot = false
	config.Defaults.IntermediateOnly = false
	config.Defaults.WarnDays = 30
	config.Defaults.Port = 443
	config.Defaults.Timeout = 10

	// Try to load from file if provided
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}

		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %v", err)
		}
	}

	return config, nil
}
