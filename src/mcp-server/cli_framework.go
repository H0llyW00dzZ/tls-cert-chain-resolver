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
	"strings"
	"syscall"
	"text/template"

	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/mcp-server/templates"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

// cliHelpData holds the data used to populate the CLI help template.
//
// It is used internally by BuildRootCommand to prepare data for the
// embedded cli_help.md template. It contains the dynamic values that
// need to be substituted into the CLI help text.
//
// Fields:
//   - ExeName: The name of the executable binary for command examples
//   - InstructionsFlagName: The formatted instructions flag name (e.g., "--instructions")
//   - ConfigFlagName: The formatted config flag name (e.g., "--config")
//   - HelpFlagName: The formatted help flag name (e.g., "--help")
type cliHelpData struct {
	// ExeName: Executable name for command examples
	ExeName string
	// InstructionsFlagName: Dynamic instructions flag name
	InstructionsFlagName string
	// ConfigFlagName: Dynamic config flag name
	ConfigFlagName string
	// HelpFlagName: Dynamic help flag name
	HelpFlagName string
}

// CLIFramework integrates Cobra CLI with MCP server capabilities.
// It provides a unified interface for both CLI operations and MCP server functionality.
//
// The CLIFramework serves as a bridge between command-line interface patterns
// and MCP server operations, enabling users to interact with certificate tools
// through both traditional CLI commands and MCP protocol communication.
//
// Key features:
//   - Dynamic executable naming based on actual binary path (not hardcoded)
//   - [Gopls-style] --instructions flag for displaying certificate operation workflows
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
//
// [Gopls-style]: https://tip.golang.org/gopls/features/mcp#instructions-to-the-model
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
//   - Provides [gopls-style] --instructions flag for displaying certificate operation workflows
//   - Includes --config flag for specifying MCP server configuration file
//   - Defaults to starting MCP server when no arguments are provided (no server subcommand needed)
//   - Supports --help and --version flags automatically via Cobra
//
// Command behavior:
//   - With --instructions: Displays formatted workflows and exits
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
//
// [gopls-style]: https://tip.golang.org/gopls/features/mcp#instructions-to-the-model
func (cf *CLIFramework) BuildRootCommand() *cobra.Command {
	// Use cross-platform executable name extraction for consistent UX
	// This handles .exe extensions on Windows and provides fallback for edge cases
	exeName := getExecutableName()

	rootCmd := &cobra.Command{
		Use:     exeName,
		Short:   "X.509 certificate chain resolver with MCP server integration",
		Version: cf.version,
	}

	// Ensure help flag is available for flag name lookup during command building
	// Cobra normally adds this during Execute, but we need it for providing a dynamic help description that includes the actual binary name
	rootCmd.Flags().BoolP("help", "h", false, "help for "+exeName)

	// Add instructions flag similar to gopls for displaying usage workflows
	// This provides users with immediate access to certificate operation guidance
	var showInstructions bool
	rootCmd.PersistentFlags().BoolVar(&showInstructions, "instructions", false, "print usage workflows for certificate operations")

	// Add config file flag with persistent behavior for subcommands
	// Allows configuration override via CLI flag while supporting environment variables
	rootCmd.PersistentFlags().StringVar(&cf.configFile, "config", cf.configFile, "path to MCP server configuration file")

	// Get flag names for dynamic text generation
	instructionsFlag := rootCmd.PersistentFlags().Lookup("instructions")
	instructionsFlagName := "--instructions"
	if instructionsFlag != nil {
		instructionsFlagName = "--" + instructionsFlag.Name
	}

	// Load CLI help template and populate with dynamic data
	// This enables easy editing of help text in the templates/cli_help.md file
	if cf.embed == nil {
		panic("CLIFramework embed filesystem not initialized - required for template loading")
	}

	templateBytes, err := cf.embed.ReadFile("cli_help.md")
	if err != nil {
		// Embedded files should never fail - this is a critical error
		panic(fmt.Sprintf("failed to load CLI help template: %v", err))
	}

	// Build examples dynamically based on registered flags
	// This ensures examples stay in sync with actual flag names
	configFlag := rootCmd.PersistentFlags().Lookup("config")
	helpFlag := rootCmd.Flags().Lookup("help")

	configFlagName := "--config"
	if configFlag != nil {
		configFlagName = "--" + configFlag.Name
	}

	helpFlagName := "--help"
	if helpFlag != nil {
		helpFlagName = "--" + helpFlag.Name
	}

	// Prepare data for template
	data := cliHelpData{
		ExeName:              exeName,
		InstructionsFlagName: instructionsFlagName,
		ConfigFlagName:       configFlagName,
		HelpFlagName:         helpFlagName,
	}

	// Parse and execute template
	tmpl, err := template.New("cli_help").Parse(string(templateBytes))
	if err != nil {
		panic(fmt.Sprintf("failed to parse CLI help template: %v", err))
	}

	// Execute template and set command properties
	var result strings.Builder
	if err := tmpl.Execute(&result, data); err != nil {
		panic(fmt.Sprintf("failed to execute CLI help template: %v", err))
	}

	// Parse the template result to extract Long and Example sections
	templateResult := result.String()
	if longEnd := strings.Index(templateResult, "\n## Examples\n"); longEnd != -1 {
		rootCmd.Long = strings.TrimSpace(templateResult[:longEnd])
		rootCmd.Example = strings.TrimSpace(templateResult[longEnd+14:]) // Skip "## Examples\n"
	} else {
		// Template format error - this indicates a malformed template
		panic("CLI help template has invalid format - missing '## Examples' section")
	}

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
		// TODO: Allow original run logic for subcommands (if any are added later)
		if originalRunE != nil {
			return originalRunE(cmd, args)
		}
		// If we reach here with arguments, it means an invalid command was provided
		// Return an error to indicate the command is not recognized
		if len(args) > 0 {
			return fmt.Errorf("unexpected arguments: %s for %q", strings.Join(args, " "), exeName)
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
//   - Provides user feedback during shutdown process
//   - Waits for active operations to complete before exiting
//
// Error handling:
//   - Gracefully handles context.Canceled (signal interruption) as successful termination
//   - Reports context.DeadlineExceeded and other errors normally
//   - Wraps errors with context for debugging
//   - Integrates with Cobra's error handling for appropriate CLI behavior
//
// The server runs indefinitely until interrupted, communicating via stdio
// for MCP protocol messages. This enables integration with MCP clients and AI assistants.
//
// Returns:
//   - nil: When server shuts down gracefully due to signal interruption (successful operation)
//   - error: Configuration loading, server building, timeouts, or other runtime errors.
//
// The method will block until the server is shut down via signal or context cancellation.
// User-initiated cancellation (signals) is treated as successful termination without usage display,
// while operational errors are reported normally for debugging.
func (cf *CLIFramework) startMCPServer() error {
	// Create a logger for server messages that outputs to stderr
	l := logger.NewCLILogger()
	l.SetOutput(os.Stderr)

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

	// Start CRL cache cleanup with cancellable context
	x509chain.StartCRLCacheCleanup(ctx)

	// Handle SIGINT/SIGTERM signals for graceful shutdown
	// Creates a goroutine that waits for termination signals
	go func() {
		// Set up signal channel to receive OS signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		// Block until signal is received, then cancel context
		sig := <-sigChan
		// Clear the line (including any ^C) and show clean shutdown message
		l.Printf("\rReceived signal %s, initiating graceful shutdown...", sig)
		cancel()
	}()

	// Start the server - this will block until context is cancelled
	// The server listens for MCP protocol messages on stdin and responds on stdout
	// All MCP tool calls, resource requests, and sampling operations are handled here
	l.Printf("X.509 Certificate Chain Resolver MCP server started.")

	// Check if the error is due to context cancellation (graceful shutdown)
	// Only user-initiated cancellation (signals) should be treated as graceful shutdown
	// Timeout errors are operational issues that should be reported
	if err = stdioServer.Listen(ctx, os.Stdin, os.Stdout); err != nil && err == context.Canceled {
		return nil
	}

	return err
}

// printInstructions displays usage workflows for certificate operations.
// It uses the pre-generated instructions from server initialization.
//
// The function provides the same instruction display capability as the MCP server
// but accessible through the CLI --instructions flag, similar to [gopls]. It uses
// pre-generated instructions to ensure consistency between CLI and server.
//
// Returns:
//   - error: None (instructions are pre-generated and validated).
//
// [gopls]: https://tip.golang.org/gopls/features/mcp#instructions-to-the-model
func (cf *CLIFramework) printInstructions() error {
	// Use pre-generated instructions from server initialization
	// This ensures consistency between CLI and MCP server instruction display
	fmt.Print(cf.instructions)

	return nil
}
