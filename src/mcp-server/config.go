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

// Config represents the MCP server configuration structure.
// It contains default settings for certificate operations and AI integration parameters.
//
// The configuration can be loaded from a JSON file specified by the MCP_X509_CONFIG_FILE
// environment variable, with defaults applied for any missing values.
type Config struct {
	// Defaults: Default settings for certificate chain operations
	Defaults struct {
		// Format: Default output format for certificates ("pem", "der", "json")
		Format string `json:"format"`
		// IncludeSystemRoot: Whether to include system root CAs in chain operations
		IncludeSystemRoot bool `json:"includeSystemRoot"`
		// IntermediateOnly: Whether to return only intermediate certificates
		IntermediateOnly bool `json:"intermediateOnly"`
		// WarnDays: Number of days before expiry to show warnings
		WarnDays int `json:"warnDays"`
		// Timeout: Default timeout in seconds for operations
		Timeout int `json:"timeoutSeconds"`
	} `json:"defaults"`

	// AI: Configuration for sampling/LLM integration
	AI struct {
		// APIKey: API key for AI service authentication (can also be set via X509_AI_APIKEY env var)
		APIKey string `json:"apiKey,omitempty"`
		// Endpoint: API endpoint URL for AI service (defaults to xAI)
		Endpoint string `json:"endpoint,omitempty"`
		// Model: Default AI model to use for certificate analysis
		Model string `json:"model,omitempty"`
		// Timeout: API timeout in seconds for AI requests
		Timeout int `json:"timeout,omitempty"`
	} `json:"ai"`
}

// loadConfig loads MCP server configuration from a JSON file or applies defaults.
// It sets up default values for certificate operations and AI integration settings.
//
// Parameters:
//   - configPath: Path to the JSON configuration file (optional, can be empty)
//
// Returns:
//   - A pointer to the loaded Config struct with defaults applied
//   - An error if the configuration file cannot be read or parsed
//
// The function first applies hardcoded defaults, then attempts to load and merge
// configuration from the specified file. Environment variables can override
// certain settings like the AI API key.
func loadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults
	config.Defaults.Format = "pem"
	config.Defaults.IncludeSystemRoot = false
	config.Defaults.IntermediateOnly = false
	config.Defaults.WarnDays = 30
	config.Defaults.Timeout = 30

	// Set AI defaults
	config.AI.Endpoint = "https://api.x.ai"
	config.AI.Model = "grok-beta"
	config.AI.Timeout = 30

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

	// Override API key from environment if not set in config
	if config.AI.APIKey == "" {
		config.AI.APIKey = os.Getenv("X509_AI_APIKEY")
	}

	return config, nil
}
