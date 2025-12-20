// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package mcpserver

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

// CLIFramework integrates Cobra CLI with MCP server capabilities.
// It provides a unified interface for both CLI operations and MCP server functionality.
//
// The CLIFramework serves as a bridge between command-line interface patterns
// and MCP server operations, enabling users to interact with certificate tools
// through both traditional CLI commands and MCP protocol communication.
//
// Key features:
//   - Dynamic executable naming based on actual binary path (not hardcoded)
//   - Gopls-style --instructions flag for displaying certificate operation workflows
//   - Configuration file support via --config flag or MCP_X509_CONFIG_FILE environment variable
//   - Default MCP server startup when no arguments are provided
//   - Graceful shutdown handling with signal interception
//
// Fields:
//   - configFile: Path to the MCP server configuration file.
//     Can be set via --config flag or defaults to empty string for environment variable fallback.
//   - config: Server configuration containing AI settings, timeouts, and other options.
//     Loaded from configFile or defaults when not specified.
//   - embed: Embedded filesystem interface for static resources and templates.
//     Used for accessing embedded documentation, prompts, and resource files.
//   - version: Server version string for identification and User-Agent headers.
//     Displayed in CLI --version flag and used in HTTP requests.
//   - certManager: Certificate encoding/decoding operations interface.
//     Handles PEM/DER format conversions and multiple certificate parsing.
//   - chainResolver: Certificate chain creation and management interface.
//     Provides methods for building certificate chains from leaf certificates.
//   - tools: List of tool definitions without configuration requirements.
//     These tools operate independently without needing server config access.
//   - toolsWithConfig: List of tool definitions that require configuration access.
//     These tools receive the server Config parameter for AI API keys or timeouts.
//   - resources: List of static and dynamic resources provided by the server.
//     Resources like documentation or status information accessible via MCP protocol.
//   - resourcesWithEmbed: List of resources that require embedded filesystem access.
//     Resources that need to load templates or documentation from embedded files.
//   - prompts: List of predefined prompts for guided workflows.
//     Prompts for certificate analysis, expiry monitoring, security audits, etc.
//   - promptsWithEmbed: List of prompts that require embedded filesystem access.
//     Prompts that load dynamic content from embedded templates.
//   - samplingHandler: Handler for bidirectional AI communication and streaming responses.
//     Enables real-time AI analysis of certificates with streaming token callbacks.
//   - instructions: Server instructions for MCP clients describing capabilities and behavior.
//     Instructions sent during MCP initialization handshake.
//   - populateCache: Whether to populate metadata cache for resource handlers.
//     When enabled, resource handlers can access cached tool/prompt/resource metadata.
//
// This struct enables seamless integration between CLI and MCP server operations,
// providing both traditional command-line usage and modern MCP protocol support.
type CLIFramework struct {
	configFile         string
	config             *Config
	embed              templates.EmbedFS
	version            string
	certManager        CertificateManager
	chainResolver      ChainResolver
	tools              []ToolDefinition
	toolsWithConfig    []ToolDefinitionWithConfig
	resources          []ServerResource
	resourcesWithEmbed []ServerResourceWithEmbed
	prompts            []ServerPrompt
	promptsWithEmbed   []ServerPromptWithEmbed
	samplingHandler    client.SamplingHandler
	instructions       string
	populateCache      bool
}

// NewCLIFramework creates a new CLI framework instance with MCP server integration.
// It initializes the framework with all necessary dependencies for both CLI and MCP operations.
//
// The constructor performs dependency injection by accepting a configFile path and
// ServerDependencies struct containing all required components. This approach enables
// loose coupling and testability while ensuring all framework components are properly
// initialized with their dependencies.
//
// Configuration loading is deferred until runtime (in BuildRootCommand or startMCPServer)
// to allow CLI flag overrides and environment variable fallbacks.
//
// Parameters:
//   - configFile: Path to the MCP server configuration file.
//     Can be overridden via --config flag or MCP_X509_CONFIG_FILE environment variable.
//     Pass empty string to use environment variable or default configuration.
//   - deps: Server dependencies containing all required components for MCP server operation.
//     Includes certificate managers, chain resolvers, tools, resources, prompts, and handlers.
//
// Returns:
//   - *CLIFramework: Initialized CLI framework ready for building commands.
//
// The returned framework can be used to build Cobra commands and start MCP servers,
// providing unified access to certificate operations through both CLI and MCP protocols.
//
// Example usage:
//
//	deps := ServerDependencies{
//	    Version: "1.0.0",
//	    Config: &Config{...},
//	    CertManager: &DefaultCertManager{},
//	    // ... other dependencies
//	}
//	framework := NewCLIFramework("config.json", deps)
//	cmd := framework.BuildRootCommand()
//
// This constructor enables clean separation between configuration and initialization,
// allowing the framework to be configured at startup time rather than compile time.
func NewCLIFramework(configFile string, deps ServerDependencies) *CLIFramework {
	return &CLIFramework{
		configFile:         configFile,
		config:             deps.Config,
		embed:              deps.Embed,
		version:            deps.Version,
		certManager:        deps.CertManager,
		chainResolver:      deps.ChainResolver,
		tools:              deps.Tools,
		toolsWithConfig:    deps.ToolsWithConfig,
		resources:          deps.Resources,
		resourcesWithEmbed: deps.ResourcesWithEmbed,
		prompts:            deps.Prompts,
		promptsWithEmbed:   deps.PromptsWithEmbed,
		samplingHandler:    deps.SamplingHandler,
		instructions:       deps.Instructions,
		populateCache:      deps.PopulateCache,
	}
}

// BuildRootCommand creates the root Cobra command with integrated MCP server capabilities.
// It sets up the CLI structure and provides access to MCP server functionality through subcommands.
//
// The command is designed to be flexible and user-friendly:
//   - Uses dynamic executable naming based on os.Args[0] to match the actual binary name
//   - Provides gopls-style --instructions flag for displaying certificate operation workflows
//   - Includes --config flag for specifying MCP server configuration file
//   - Defaults to starting MCP server when no arguments are provided (no server subcommand needed)
//   - Supports --help and --version flags automatically via Cobra
//
// Command behavior:
//   - With --instructions: Displays formatted usage workflows and exits
//   - With arguments: Executes the specified subcommand (if any)
//   - Without arguments: Starts MCP server directly (default behavior)
//
// The root command serves as the main entry point for both CLI operations and MCP server startup,
// providing a unified interface that adapts to different usage patterns.
//
// Returns:
//   - *cobra.Command: Root command with MCP server integration.
//
// The returned command can be executed directly or used as a parent for subcommands.
// When executed, it handles the --instructions flag, loads configuration, and starts
// the MCP server with proper signal handling and graceful shutdown.
//
// Example usage:
//
//	framework := NewCLIFramework("config.json", deps)
//	rootCmd := framework.BuildRootCommand()
//	if err := rootCmd.Execute(); err != nil {
//	    log.Fatal(err)
//	}
//
// This method encapsulates the CLI-MCP integration logic, making it easy to create
// professional command-line applications that also serve as MCP servers.
func (cf *CLIFramework) BuildRootCommand() *cobra.Command {
	// Use dynamic executable name instead of hardcoded name for better UX
	// This matches professional tools that adapt to deployment scenarios
	exeName := filepath.Base(os.Args[0])

	rootCmd := &cobra.Command{
		Use:   exeName,
		Short: "TLS certificate chain resolver with MCP server integration",
		Long: `A comprehensive TLS certificate chain resolver that provides both
command-line interface and MCP server capabilities for certificate analysis,
validation, and management.

The binary supports both traditional CLI usage and modern MCP protocol integration,
enabling seamless certificate operations across different environments and use cases.`,
		Version: cf.version,
	}

	// Add instructions flag similar to gopls for displaying usage workflows
	// This provides users with immediate access to certificate operation guidance
	var showInstructions bool
	rootCmd.PersistentFlags().BoolVar(&showInstructions, "instructions", false, "print usage workflows for certificate operations")

	// Add config file flag with persistent behavior for subcommands
	// Allows configuration override via CLI flag while supporting environment variables
	rootCmd.PersistentFlags().StringVar(&cf.configFile, "config", cf.configFile, "path to MCP server configuration file")

	// Override root command run to handle instructions flag and default server behavior
	// This custom run logic enables the dual CLI/MCP functionality
	originalRunE := rootCmd.RunE
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Handle instructions flag by displaying formatted workflows
		if showInstructions {
			return cf.printInstructions()
		}
		// If no arguments and no instructions flag, start MCP server directly
		// This makes the default behavior user-friendly - just run the binary
		if len(args) == 0 && !showInstructions {
			return cf.startMCPServer()
		}
		// Allow original run logic for subcommands (if any are added later)
		if originalRunE != nil {
			return originalRunE(cmd, args)
		}
		return nil
	}

	return rootCmd
}

// startMCPServer starts the MCP server directly without requiring the 'server' subcommand.
// This is the default behavior when running the binary without arguments.
//
// The method performs a complete MCP server initialization sequence:
//  1. Loads configuration from file (with fallback to defaults)
//  2. Builds MCP server using the ServerBuilder pattern
//  3. Registers all tools, resources, prompts, and sampling handlers
//  4. Starts stdio-based MCP server for protocol communication
//  5. Implements graceful shutdown with signal handling
//
// Configuration loading:
//   - Uses cf.configFile if set via --config flag
//   - Falls back to MCP_X509_CONFIG_FILE environment variable
//   - Uses default configuration if no file specified
//   - Validates configuration before proceeding
//
// Server building process:
//   - Uses ServerBuilder fluent interface for clean dependency injection
//   - Registers tools (both regular and config-dependent variants)
//   - Adds resources (static and embedded filesystem variants)
//   - Includes prompts (standard and embedded template variants)
//   - Enables sampling for AI-powered certificate analysis
//   - Populates metadata cache if requested
//
// MCP server capabilities:
//   - Tool execution for certificate operations
//   - Resource serving for documentation and status
//   - Prompt handling for guided workflows
//   - Bidirectional AI sampling for real-time analysis
//
// Signal handling:
//   - Intercepts SIGINT (Ctrl+C) and SIGTERM signals
//   - Uses context cancellation for graceful shutdown
//   - Waits for active operations to complete before exiting
//
// The server runs indefinitely until interrupted, communicating via stdio
// for MCP protocol messages. This enables integration with MCP clients and AI assistants.
//
// Returns:
//   - error: Configuration loading, server building, or runtime errors.
//
// The method will block until the server is shut down via signal or context cancellation.
// All errors are properly wrapped with context for debugging.
func (cf *CLIFramework) startMCPServer() error {
	// Load config based on the --config flag or environment variable fallback
	// This allows users to override configuration without editing files
	config, err := loadConfig(cf.configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Build MCP server using the ServerBuilder pattern for clean dependency management
	// Each With* method adds specific capabilities to the server
	builder := NewServerBuilder().
		WithConfig(config).
		WithEmbed(cf.embed).
		WithVersion(cf.version).
		WithCertManager(cf.certManager).
		WithChainResolver(cf.chainResolver).
		WithTools(cf.tools...).
		WithToolsWithConfig(cf.toolsWithConfig...).
		WithResources(cf.resources...).
		WithEmbeddedResources(cf.resourcesWithEmbed...).
		WithPrompts(cf.prompts...).
		WithEmbeddedPrompts(cf.promptsWithEmbed...).
		WithSampling(cf.samplingHandler).
		WithInstructions(cf.instructions)

	// Enable metadata cache population if requested
	// This allows resource handlers to access cached tool/prompt/resource information
	if cf.populateCache {
		builder = builder.WithPopulate()
	}

	// Build the server with all configured components
	// This validates dependencies and creates the final server instance
	mcpServer, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build MCP server: %w", err)
	}

	// Start the MCP server with stdio transport for protocol communication
	// Stdio transport enables integration with MCP clients via standard input/output
	// The server will handle JSON-RPC messages over stdin/stdout
	stdioServer := server.NewStdioServer(mcpServer)

	// Implement graceful shutdown with context cancellation
	// This ensures clean termination when signals are received
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT/SIGTERM signals for graceful shutdown
	// Creates a goroutine that waits for termination signals
	go func() {
		// Set up signal channel to receive OS signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		// Block until signal is received, then cancel context
		<-sigChan
		cancel()
	}()

	// Start the server - this will block until context is cancelled
	// The server listens for MCP protocol messages on stdin and responds on stdout
	// All MCP tool calls, resource requests, and sampling operations are handled here
	return stdioServer.Listen(ctx, os.Stdin, os.Stdout)
}

// printInstructions displays usage workflows for certificate operations.
// It loads and renders the instruction template with dynamic tool data.
//
// The function uses the same instruction loading logic as the MCP server initialization,
// ensuring consistency between CLI and MCP server instruction display. It dynamically
// generates instructions based on available tools, providing users with accurate
// guidance on certificate operations.
//
// Returns:
//   - error: Template loading or rendering errors.
//
// This function provides the same instruction display capability as the MCP server
// but accessible through the CLI --instructions flag, similar to gopls. It serves
// as a user-friendly way to discover available certificate operations without starting
// the full MCP server.
func (cf *CLIFramework) printInstructions() error {
	// Load instructions using the same logic as MCP server initialization
	// This ensures consistency between CLI and server instruction display
	instructions, err := loadInstructions(cf.tools, cf.toolsWithConfig)
	if err != nil {
		return fmt.Errorf("failed to load instructions: %w", err)
	}

	// Print formatted instructions to stdout
	// This provides immediate user feedback without requiring MCP protocol
	fmt.Print(instructions)

	return nil
}
