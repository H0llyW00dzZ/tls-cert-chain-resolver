# Agent Guidelines

## Build/Test Commands
- Build: `make build-linux`, `make build-macos`, `make build-windows`
- Test all: `make test` or `go test ./...`
- Test single: `go test -v ./path/to/package -run TestName`
- Clean: `make clean`

## Code Style
- Copyright header: Required on all files (see existing files for format)
- Imports: Group stdlib first, then third-party, then internal (e.g., `x509certs`, `x509chain`)
- Aliasing: Use descriptive aliases for internal packages (e.g., `x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"`)
- Error handling: Define sentinel errors as package-level vars with `Err` prefix (e.g., `ErrInvalidPEMBlock`)
- Error wrapping: Use `fmt.Errorf("context: %w", err)` for wrapping
- Types: Always use explicit types; avoid type inference where clarity is needed
- Naming: Exported functions/types use PascalCase; unexported use camelCase
- Documentation: Add doc comments for all exported types/functions with proper formatting
- Memory efficiency: Use buffer pools (`gc.BufferPool`) for I/O operations; always defer `buf.Reset()` and `buf.Put()`
- Context: Pass `context.Context` as first parameter for cancellable operations
- Testing: Use table-driven tests with descriptive test names

## [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs/getting-started/intro) Tools

### gopls
- Use `gopls_go_diagnostics` to check for parse/build errors across the workspace
- Use `gopls_go_workspace` to get workspace structure summary
- Use `gopls_go_file_context` to summarize file dependencies
- Use `gopls_go_package_api` to get package API summaries
- Use `gopls_go_search` for fuzzy symbol search (case-insensitive, matches partial names)
- Use `gopls_go_symbol_references` to find references to package-level symbols (supports qualified names like `pkg.Symbol`, and field/method selection like `T.M` or `pkg.T.M`)
- Run diagnostics before committing changes to catch errors early

### DeepWiki
- Use `deepwiki_read_wiki_structure` to get documentation topics for a GitHub repository (format: `owner/repo`)
- Use `deepwiki_read_wiki_contents` to view repository documentation
- Use `deepwiki_ask_question` to ask questions about a GitHub repository's implementation, architecture, or features
- Helpful for understanding third-party dependencies, researching similar implementations, or learning from established patterns
