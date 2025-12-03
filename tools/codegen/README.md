# Codegen

Generates MCP server resources, tools, and prompts from configuration files. Refactored from a monolithic file into a maintainable, configuration-driven system using Go templates and JSON configuration.

## Structure

```
tools/codegen/
├── run.go                 # Main entry point
├── internal/
│   └── codegen.go         # Core generation logic
├── config/
│   ├── resources.json     # Resource definitions
│   ├── tools.json         # Tool definitions
│   └── prompts.json       # Prompt definitions
├── templates/
│   ├── resources.go.tmpl  # Resources template
│   ├── tools.go.tmpl      # Tools template
│   └── prompts.go.tmpl    # Prompts template
└── README.md              # This documentation
```

## Improvements Made

### 1. Configuration-Driven
- Moved hard-coded data to JSON configuration files
- Easy to add new resources/tools/prompts without touching code
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
- `src/mcp-server/prompts.go`

The tool automatically finds its configuration and template files regardless of the current working directory.

## Adding New Components

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

### Adding a Prompt

1. Edit `config/prompts.json`:
```json
{
  "prompts": [
    {
      "name": "new-prompt",
      "description": "Description of the new prompt",
      "handler": "handleNewPrompt",
      "arguments": [
        {
          "name": "arg1",
          "description": "Description of argument"
        }
      ]
    }
  ]
}
```

2. Run the codegen tool

## Configuration Format

### Resources
```jsonc
{
  "uri": "string",           // Required: Resource URI
  "name": "string",          // Required: Display name
  "description": "string",   // Required: Description
  "mimeType": "string",      // Required: MIME type
  "handler": "string"        // Required: Handler function name
}
```

### Tools
```jsonc
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

### Prompts
```jsonc
{
  "name": "string",          // Required: Prompt name
  "description": "string",   // Required: Prompt description
  "handler": "string",       // Required: Handler function name
  "arguments": [             // Optional: Prompt arguments
    {
      "name": "string",        // Required: Argument name
      "description": "string"  // Required: Argument description
    }
  ]
}
```

## Validation Rules

The tool validates configuration on load:

- **Resources**: URI, name, and handler must be non-empty; URIs must be unique
- **Tools**: Name, constName, handler, and roleConst must be non-empty; names and role names must be unique
- **Prompts**: Name and handler must be non-empty; names must be unique
- **Parameters/Arguments**: Names must be non-empty and unique within their parent

## Future Enhancements

Due to the framework implementation in `src/mcp-server/`, it has better Go code style. Other components will be added here into codegen later as needed.

### Todo List

- [x] Implement prompts codegen
- [ ] Add other MCP components to codegen system if needed
- [ ] Enhance template system for improved code style consistency

## Benefits

1. **Maintainability**: Easy to add/modify resources, tools, and prompts
2. **Reliability**: Configuration validation prevents runtime errors
3. **Readability**: Template-based generation is cleaner than string concatenation
4. **Testability**: Modular design allows testing individual components
5. **Extensibility**: New features can be added without changing existing code
