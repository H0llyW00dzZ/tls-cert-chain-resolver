// Copyright (c) 2026 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// configFormat represents supported configuration file formats.
type configFormat int

const (
	// configFormatJSON represents JSON configuration format (.json)
	configFormatJSON configFormat = iota
	// configFormatYAML represents YAML configuration format (.yaml, .yml)
	configFormatYAML
)

// Config represents the MCP server configuration structure.
// It contains default settings for certificate operations and AI integration parameters.
//
// The configuration can be loaded from a JSON or YAML file specified by the MCP_X509_CONFIG_FILE
// environment variable, with defaults applied for any missing values.
// Supported file extensions: .json, .yaml, .yml
type Config struct {
	// Defaults: Default settings for certificate chain operations
	Defaults struct {
		// WarnDays: Number of days before expiry to show warnings
		WarnDays int `json:"warnDays" yaml:"warnDays"`
		// Timeout: Default timeout in seconds for operations
		Timeout int `json:"timeoutSeconds" yaml:"timeoutSeconds"`
	} `json:"defaults" yaml:"defaults"`

	// AI: Configuration for sampling/LLM integration
	AI struct {
		// APIKey: API key for AI service authentication (can also be set via X509_AI_APIKEY env var)
		APIKey string `json:"apiKey,omitempty" yaml:"apiKey,omitempty"`
		// Endpoint: API endpoint URL for AI service (defaults to xAI)
		Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
		// Model: Default AI model to use for certificate analysis
		Model string `json:"model,omitempty" yaml:"model,omitempty"`
		// Timeout: API timeout in seconds for AI requests
		Timeout int `json:"timeout,omitempty" yaml:"timeout,omitempty"`
		// MaxTokens: Maximum tokens for AI analysis responses
		MaxTokens int `json:"maxTokens,omitempty" yaml:"maxTokens,omitempty"`
		// Temperature: Sampling temperature for AI responses (0.0 to 1.0)
		Temperature float64 `json:"temperature,omitempty" yaml:"temperature,omitempty"`
	} `json:"ai" yaml:"ai"`
}

// detectConfigFormat determines the configuration file format based on file extension.
// It supports .json, .yaml, and .yml extensions for flexible configuration management.
//
// Parameters:
//   - configPath: Path to the configuration file
//
// Returns:
//   - configFormat: The detected format (configFormatJSON or configFormatYAML)
//
// The function uses case-insensitive extension matching for cross-platform compatibility.
func detectConfigFormat(configPath string) configFormat {
	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".yaml", ".yml":
		return configFormatYAML
	default:
		return configFormatJSON
	}
}

// unmarshalConfig unmarshals configuration data based on the specified format.
// It supports both JSON and YAML formats for configuration flexibility.
//
// Parameters:
//   - data: Raw configuration file contents
//   - config: Pointer to Config struct to populate
//   - format: The configuration format (configFormatJSON or configFormatYAML)
//
// Returns:
//   - error: Any parsing error encountered during unmarshaling
//
// The function delegates to the appropriate parser based on the format parameter,
// ensuring consistent error handling across both configuration formats.
func unmarshalConfig(data []byte, config *Config, format configFormat) error {
	switch format {
	case configFormatYAML:
		if err := yaml.Unmarshal(data, config); err != nil {
			return fmt.Errorf("failed to parse YAML config file: %w", err)
		}
	default:
		if err := json.Unmarshal(data, config); err != nil {
			return fmt.Errorf("failed to parse JSON config file: %w", err)
		}
	}
	return nil
}

// loadConfig loads MCP server configuration from a JSON or YAML file or applies defaults.
// It sets up default values for certificate operations and AI integration settings.
//
// Parameters:
//   - configPath: Path to the configuration file (optional, can be empty)
//     Supported formats: .json, .yaml, .yml
//
// Returns:
//   - A pointer to the loaded Config struct with defaults applied
//   - An error if the configuration file cannot be read or parsed
//
// Configuration Priority:
//  1. Default values are set
//  2. MCP_X509_CONFIG_FILE environment variable is checked if configPath is empty
//  3. Config file values override defaults (if file exists and is valid)
//  4. Environment variables override config file values (X509_AI_APIKEY)
//
// The function first applies hardcoded defaults, then attempts to load and merge
// configuration from the specified file. The file format is automatically detected
// based on the file extension (.json, .yaml, or .yml). Environment variables can
// override certain settings like the AI API key.
func loadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults
	config.Defaults.WarnDays = 30
	config.Defaults.Timeout = 30

	// Set AI defaults
	config.AI.Endpoint = "https://api.x.ai"
	config.AI.Model = "grok-4-1-fast-non-reasoning"
	config.AI.Timeout = 30
	config.AI.MaxTokens = 4096
	config.AI.Temperature = 0.3

	// Check environment variable for config file path if not provided
	if configPath == "" {
		configPath = os.Getenv("MCP_X509_CONFIG_FILE")
	}

	// Try to load from file if path is provided
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		// Detect format and unmarshal accordingly
		format := detectConfigFormat(configPath)
		if err := unmarshalConfig(data, config, format); err != nil {
			return nil, err
		}

		// Validate and set defaults for invalid values
		if config.Defaults.WarnDays <= 0 {
			config.Defaults.WarnDays = 30
		}
		if config.Defaults.Timeout <= 0 {
			config.Defaults.Timeout = 30
		}
		if config.AI.Timeout <= 0 {
			config.AI.Timeout = 30
		}
	}

	// Override API key from environment if not set in config
	if config.AI.APIKey == "" {
		config.AI.APIKey = os.Getenv("X509_AI_APIKEY")
	}

	return config, nil
}
