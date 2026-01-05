A comprehensive X.509 certificate chain resolver that provides both
command-line interface and MCP server capabilities for certificate analysis,
validation, and management.

The binary supports both traditional CLI usage and modern MCP protocol integration,
enabling seamless certificate operations across different environments and use cases.

When run without arguments, the binary starts an MCP server that provides certificate
analysis tools. Use {{.InstructionsFlagName}} to see available certificate operation workflows.

## Examples

# Start MCP server (default behavior)
{{.ExeName}}

# Start MCP server with custom config (JSON or YAML)
{{.ExeName}} {{.ConfigFlagName}} /path/to/config.json
{{.ExeName}} {{.ConfigFlagName}} /path/to/config.yaml

# Display certificate operation workflows
{{.ExeName}} {{.InstructionsFlagName}}

# Show help and available options
{{.ExeName}} {{.HelpFlagName}}
