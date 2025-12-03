# Codegen

Generates MCP server resources and tools from configuration files. Refactored from a monolithic file into a maintainable, configuration-driven system using Go templates and JSON configuration.

## Structure

```
tools/codegen/
├── run.go                 # Main entry point
├── internal/
│   └── codegen.go         # Core generation logic
├── config/
│   ├── resources.json     # Resource definitions
│   └── tools.json         # Tool definitions
├── templates/
│   ├── resources.go.tmpl  # Resources template
│   └── tools.go.tmpl      # Tools template
└── README.md              # This documentation
```

## Improvements Made

### 1. Configuration-Driven
- Moved hard-coded data to JSON configuration files
- Easy to add new resources/tools without touching code
- Configuration validation ensures data integrity

### 2. Template-Based Generation
- Replaced string concatenation with Go templates
- Cleaner, more maintainable code generation
- Better separation of logic and presentation

### 3. Modular Architecture
- Split monolithic codegen.go into focused components
- Configuration loading, validation, and generation separated
- Easier to test and maintain individual pieces

### 4. Validation
- Configuration files are validated on load
- Checks for required fields, duplicates, and valid types
- Clear error messages for configuration issues

## Usage

### Direct Execution

```bash
cd tools/codegen
go run run.go
```

### Via go generate

The codegen tool is integrated with `go generate`:

```bash
# From project root
go generate ./src/mcp-server
```

This will generate:
- `src/mcp-server/resources.go`
- `src/mcp-server/tools.go`

The tool automatically finds its configuration and template files regardless of the current working directory.

## Adding New Resources/Tools

### Adding a Resource

1. Edit `config/resources.json`:
```json
{
  "resources": [
    {
      "uri": "new://resource",
      "name": "New Resource",
      "description": "Description of the new resource",
      "mimeType": "application/json",
      "handler": "handleNewResource"
    }
  ]
}
```

2. Run the codegen tool

### Adding a Tool

1. Edit `config/tools.json`:
```json
{
  "tools": [
    {
      "constName": "ToolNewTool",
      "name": "new_tool",
      "comment": "performs new functionality",
      "description": "Description of the new tool",
      "handler": "handleNewTool",
      "roleConst": "RoleNewTool",
      "roleName": "newTool",
      "roleComment": "handles new tool operations",
      "withConfig": false,
      "params": [
        {
          "name": "param1",
          "description": "Description of parameter",
          "type": "string",
          "required": true
        }
      ]
    }
  ]
}
```

2. Run the codegen tool

## Configuration Format

### Resources
```json
{
  "uri": "string",           // Required: Resource URI
  "name": "string",          // Required: Display name
  "description": "string",   // Required: Description
  "mimeType": "string",      // Required: MIME type
  "handler": "string"        // Required: Handler function name
}
```

### Tools
```json
{
  "constName": "string",     // Required: Constant name (e.g., "ToolName")
  "name": "string",          // Required: Tool name
  "comment": "string",       // Required: Comment for constant
  "description": "string",   // Required: Tool description
  "handler": "string",       // Required: Handler function name
  "roleConst": "string",     // Required: Role constant name
  "roleName": "string",      // Required: Role name
  "roleComment": "string",   // Required: Comment for role constant
  "withConfig": boolean,     // Required: Whether tool needs config
  "params": [                // Optional: Tool parameters
    {
      "name": "string",        // Required: Parameter name
      "description": "string", // Required: Parameter description
      "type": "string",        // Required: "string", "number", or "boolean"
      "required": boolean,     // Required: Whether parameter is required
      "default": "string"      // Optional: Default value as string
    }
  ]
}
```

## Validation Rules

The tool validates configuration on load:

- **Resources**: URI, name, and handler must be non-empty; URIs must be unique
- **Tools**: Name, constName, handler, and roleConst must be non-empty; names and role names must be unique
- **Parameters**: Name and type must be non-empty; type must be "string", "number", or "boolean"; parameter names must be unique within a tool

## Benefits

1. **Maintainability**: Easy to add/modify resources and tools
2. **Reliability**: Configuration validation prevents runtime errors
3. **Readability**: Template-based generation is cleaner than string concatenation
4. **Testability**: Modular design allows testing individual components
5. **Extensibility**: New features can be added without changing existing code
