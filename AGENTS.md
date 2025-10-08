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
