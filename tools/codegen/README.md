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

2. Generate the code:
```bash
go generate ./src/mcp-server
```

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

2. Generate the code:
```bash
go generate ./src/mcp-server
```

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

2. Generate the code:
```bash
go generate ./src/mcp-server
```

## Configuration Format

### Resources
```jsonc
{
  "uri": "string",           // Required: Resource URI (must be unique)
  "name": "string",          // Required: Display name
  "description": "string",   // Required: Description
  "mimeType": "string",      // Required: MIME type
  "handler": "string",       // Required: Handler function name
  "audience": ["string"],    // Optional: MCP audience roles ("user", "assistant")
  "priority": number,        // Optional: MCP priority (0.0-10.0)
  "meta": {                  // Optional: Additional metadata
    "key": "value"
  }
}
```

### Tools
```jsonc
{
  "constName": "string",     // Required: Constant name (e.g., "ToolName")
  "name": "string",          // Required: Tool name (must be unique)
  "comment": "string",       // Required: Comment for constant
  "description": "string",   // Required: Tool description
  "handler": "string",       // Required: Handler function name
  "roleConst": "string",     // Required: Role constant name
  "roleName": "string",      // Required: Role name (must be unique)
  "roleComment": "string",   // Required: Comment for role constant
  "withConfig": boolean,     // Required: Whether tool needs config
  "params": [                // Optional: Tool parameters
    {
      "name": "string",        // Required: Parameter name (must be unique)
      "description": "string", // Required: Parameter description
      "type": "string",        // Required: "string", "number", "boolean", "array", "object"
      "required": boolean,     // Required: Whether parameter is required
      "default": "string",     // Optional: Default value as string
      "enum": ["string"],      // Optional: Allowed values (type-specific validation)
      "minLength": number,     // Optional: Minimum string length
      "maxLength": number,     // Optional: Maximum string length
      "minimum": number,       // Optional: Minimum number value
      "maximum": number,       // Optional: Maximum number value
      "pattern": "string",     // Optional: Regex pattern for strings
      "items": {               // Optional: Schema for array items
        "type": "string"
      },
      "properties": {          // Optional: Schema for object properties
        "key": {"type": "string"}
      }
    }
  ],
  // MCP annotations for LLM hints
  "titleAnnotation": "string",           // Optional: Title annotation
  "readOnlyHintAnnotation": boolean,     // Optional: Read-only hint
  "destructiveHintAnnotation": boolean,  // Optional: Destructive hint
  "idempotentHintAnnotation": boolean,   // Optional: Idempotent hint
  "openWorldHintAnnotation": boolean,    // Optional: Open world hint
  "meta": {                              // Optional: Additional metadata
    "key": "value"
  }
}
```

### Prompts
```jsonc
{
  "name": "string",          // Required: Prompt name (must be unique)
  "description": "string",   // Required: Prompt description
  "handler": "string",       // Required: Handler function name
  "arguments": [             // Optional: Prompt arguments
    {
      "name": "string",        // Required: Argument name (must be unique)
      "description": "string", // Required: Argument description
      "required": boolean      // Optional: Whether argument is required (default: false)
    }
  ],
  "audience": ["string"],    // Optional: MCP audience roles ("user", "assistant")
  "priority": number,        // Optional: MCP priority (0.0-10.0)
  "meta": {                  // Optional: Additional metadata
    "key": "value"
  }
}
```

## JSON Schema

The configuration files follow these formal JSON schemas for validation and documentation:

### Resources Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "resources": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["uri", "name", "description", "mimeType", "handler"],
        "properties": {
          "uri": {
            "type": "string",
            "description": "Resource URI (must be unique)"
          },
          "name": {
            "type": "string",
            "description": "Display name"
          },
          "description": {
            "type": "string",
            "description": "Description"
          },
          "mimeType": {
            "type": "string",
            "description": "MIME type"
          },
          "handler": {
            "type": "string",
            "description": "Handler function name"
          },
          "audience": {
            "type": "array",
            "items": {
              "type": "string",
              "enum": ["user", "assistant"]
            },
            "description": "MCP audience roles"
          },
          "priority": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 10.0,
            "description": "MCP priority"
          },
          "meta": {
            "type": "object",
            "description": "Additional metadata"
          }
        }
      }
    }
  }
}
```

### Tools Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "tools": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["constName", "name", "comment", "description", "handler", "roleConst", "roleName", "roleComment", "withConfig"],
        "properties": {
          "constName": {
            "type": "string",
            "description": "Constant name (e.g., 'ToolName')"
          },
          "name": {
            "type": "string",
            "description": "Tool name (must be unique)"
          },
          "comment": {
            "type": "string",
            "description": "Comment for constant"
          },
          "description": {
            "type": "string",
            "description": "Tool description"
          },
          "handler": {
            "type": "string",
            "description": "Handler function name"
          },
          "roleConst": {
            "type": "string",
            "description": "Role constant name"
          },
          "roleName": {
            "type": "string",
            "description": "Role name (must be unique)"
          },
          "roleComment": {
            "type": "string",
            "description": "Comment for role constant"
          },
          "withConfig": {
            "type": "boolean",
            "description": "Whether tool needs config"
          },
          "params": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["name", "description", "type", "required"],
              "properties": {
                "name": {
                  "type": "string",
                  "description": "Parameter name (must be unique)"
                },
                "description": {
                  "type": "string",
                  "description": "Parameter description"
                },
                "type": {
                  "type": "string",
                  "enum": ["string", "number", "boolean", "array", "object"],
                  "description": "Parameter type"
                },
                "required": {
                  "type": "boolean",
                  "description": "Whether parameter is required"
                },
                "default": {
                  "type": "string",
                  "description": "Default value as string"
                },
                "enum": {
                  "type": "array",
                  "items": {"type": "string"},
                  "description": "Allowed values (validated by type)"
                },
                "minLength": {
                  "type": "integer",
                  "minimum": 0,
                  "description": "Minimum string length"
                },
                "maxLength": {
                  "type": "integer",
                  "minimum": 0,
                  "description": "Maximum string length"
                },
                "minimum": {
                  "type": "number",
                  "description": "Minimum number value"
                },
                "maximum": {
                  "type": "number",
                  "description": "Maximum number value"
                },
                "pattern": {
                  "type": "string",
                  "description": "Regex pattern for strings"
                },
                "items": {
                  "type": "object",
                  "description": "Schema for array items"
                },
                "properties": {
                  "type": "object",
                  "description": "Schema for object properties"
                }
              }
            }
          },
          "titleAnnotation": {
            "type": "string",
            "description": "MCP title annotation"
          },
          "readOnlyHintAnnotation": {
            "type": "boolean",
            "description": "MCP read-only hint"
          },
          "destructiveHintAnnotation": {
            "type": "boolean",
            "description": "MCP destructive hint"
          },
          "idempotentHintAnnotation": {
            "type": "boolean",
            "description": "MCP idempotent hint"
          },
          "openWorldHintAnnotation": {
            "type": "boolean",
            "description": "MCP open world hint"
          },
          "meta": {
            "type": "object",
            "description": "Additional metadata"
          }
        }
      }
    }
  }
}
```

### Prompts Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "prompts": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "description", "handler"],
        "properties": {
          "name": {
            "type": "string",
            "description": "Prompt name (must be unique)"
          },
          "description": {
            "type": "string",
            "description": "Prompt description"
          },
          "handler": {
            "type": "string",
            "description": "Handler function name"
          },
          "arguments": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["name", "description"],
              "properties": {
                "name": {
                  "type": "string",
                  "description": "Argument name (must be unique)"
                },
                "description": {
                  "type": "string",
                  "description": "Argument description"
                },
                "required": {
                  "type": "boolean",
                  "description": "Whether argument is required",
                  "default": false
                }
              }
            }
          },
          "audience": {
            "type": "array",
            "items": {
              "type": "string",
              "enum": ["user", "assistant"]
            },
            "description": "MCP audience roles"
          },
          "priority": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 10.0,
            "description": "MCP priority"
          },
          "meta": {
            "type": "object",
            "description": "Additional metadata"
          }
        }
      }
    }
  }
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
6. **Scalability**: Ready to handle highly scalable scenarios such as many tools, focusing only on business logic
