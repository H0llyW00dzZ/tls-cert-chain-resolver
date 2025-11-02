# Memory and Context Management Instructions

## Purpose

Guidelines for efficient memory usage, context management, and resource optimization when working with the X509 certificate chain resolver.

## Context Management

### 1. Context in Certificate Operations

**Critical**: Always pass and use `context.Context` for certificate fetching

```go
// Good - context-aware certificate fetching
func fetchCertificateChain(ctx context.Context, cert *x509.Certificate, version string) (*x509chain.Chain, error) {
    chain := x509chain.New(cert, version)
    
    // Use goroutine with channel for context cancellation
    result := make(chan error, 1)
    go func() {
        result <- chain.FetchCertificate(ctx)
    }()
    
    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    case err := <-result:
        if err != nil {
            return nil, fmt.Errorf("error fetching certificate chain: %w", err)
        }
    }
    
    return chain, nil
}
```

### 2. Context Cancellation Handling

**Pattern**: Use context for graceful shutdown

```go
// Main function pattern in cmd/run.go
func main() {
    // Create cancellable context
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // Set up signal handling
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    
    // Run with context
    go func() {
        done <- cli.Execute(ctx, version)
    }()
    
    // Wait for signal or completion
    select {
    case <-sigs:
        cancel()  // Cancel context on signal
    case err := <-done:
        // Handle completion
    }
}
```

### 3. Context Best Practices

```
✅ DO:
- Pass context to all certificate fetching operations
- Use context.WithCancel for user-initiated cancellation
- Use context.WithTimeout for network operations (if needed)
- Check ctx.Done() in long-running operations

❌ DON'T:
- Use context.Background() directly in functions (accept it as parameter)
- Ignore context cancellation
- Create new contexts unnecessarily
- Use context for passing request-scoped values (use parameters)
```

### 4. Thread-Safe Logger Pattern

**Pattern**: Logger with mutex protection and buffer pooling (see `src/logger/logger.go`)

```go
// Thread-safe logger implementation with buffer pooling
type MCPLogger struct {
    mu      sync.Mutex                // Protects concurrent writes
    writer  io.Writer
    silent  bool
    bufPool gc.Pool                   // Buffer pool for efficient memory usage
}

// Thread-safe Printf - safe to call from multiple goroutines
func (m *MCPLogger) Printf(format string, v ...any) {
    if m.silent {
        return
    }
    
    // Get buffer from pool
    buf := m.bufPool.Get()
    defer func() {
        buf.Reset()                   // Reset buffer before returning to pool
        m.bufPool.Put(buf)
    }()
    
    // Build JSON directly in buffer (no intermediate allocations)
    msg := fmt.Sprintf(format, v...)
    buf.WriteString(`{"level":"info","message":"`)
    writeJSONString(buf, msg)         // Custom JSON escaping
    buf.WriteString(`"}`)
    buf.WriteByte('\n')
    
    // Lock only for write operation
    m.mu.Lock()
    m.writer.Write(buf.Bytes())
    m.mu.Unlock()
}

// All logger methods use same mutex protection + buffer pooling pattern
// This ensures safe concurrent logging with minimal allocations
```

**Key Points**:
- Use `sync.Mutex` to protect shared mutable state (writer)
- Use `gc.Pool` interface for efficient memory usage under high concurrency
- **IMPORTANT**: Always `Reset()` buffer before returning to pool to prevent memory leaks
- Minimize critical section - only lock for actual write
- Prepare data outside lock to reduce contention
- Build JSON directly in buffer to avoid intermediate string allocations
- Document thread-safety in type/function comments

## Memory Management

### 1. Buffer Pooling

**Package**: `src/internal/helper/gc`  
**Interface**: `gc.Pool` and `gc.Buffer`  
**Purpose**: Efficient memory usage with certificates and logging

The `gc` package provides buffer pool abstraction that wraps `bytebufferpool` to avoid direct dependencies.

```go
// Good - using gc.Default buffer pool for certificate data
import "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/gc"

func processCertificates(certs []*x509.Certificate) []byte {
    buf := gc.Default.Get()
    defer func() {
        buf.Reset()         // Reset buffer before returning to pool
        gc.Default.Put(buf) // Return buffer to pool for reuse
    }()
    
    // Use buf for operations
    for _, cert := range certs {
        buf.Write(pem.EncodeToMemory(&pem.Block{
            Type:  "CERTIFICATE",
            Bytes: cert.Raw,
        }))
    }
    
    // Copy result before returning (buf will be pooled)
    result := make([]byte, len(buf.Bytes()))
    copy(result, buf.Bytes())
    return result
}
```

**gc.Pool Interface**:
```go
// Pool is safe for concurrent use by multiple goroutines
type Pool interface {
    Get() Buffer
    Put(b Buffer)
}

// Buffer provides reusable byte buffer operations
type Buffer interface {
    Write(p []byte) (int, error)
    WriteString(s string) (int, error)
    WriteByte(c byte) error
    WriteTo(w io.Writer) (int64, error)
    ReadFrom(r io.Reader) (int64, error)
    Bytes() []byte
    String() string
    Len() int
    Set(p []byte)
    SetString(s string)
    Reset()
}

// Default pool available via gc.Default
var Default Pool
```

**Buffer Methods**:
- `Write(p []byte)` - Append byte slice to buffer
- `WriteString(s string)` - Append string to buffer
- `WriteByte(c byte)` - Append single byte to buffer
- `WriteTo(w io.Writer)` - Write buffer contents to writer (drains buffer)
- `ReadFrom(r io.Reader)` - Read from reader into buffer until EOF
- `Bytes()` - Get buffer contents as byte slice
- `String()` - Get buffer contents as string
- `Len()` - Get current buffer length
- `Set(p []byte)` - Replace buffer contents with byte slice
- `SetString(s string)` - Replace buffer contents with string
- `Reset()` - Clear buffer for reuse

**Usage Examples**:
```go
// Write methods for building content
buf := gc.Default.Get()
buf.Write([]byte("header"))
buf.WriteString(": value\n")
buf.WriteByte('\n')

// String/Len for inspection
fmt.Printf("Buffer contains %d bytes: %s", buf.Len(), buf.String())

// Set methods for replacing content
buf.Set([]byte("new content"))  // Replace entire buffer
buf.SetString("another value")  // Replace with string

// I/O operations
buf.ReadFrom(reader)       // Read file/response into buffer
buf.WriteTo(writer)        // Write buffer to file/response

// Always reset before returning to pool
defer func() {
    buf.Reset()
    gc.Default.Put(buf)
}()
```

### 2. Avoid Memory Leaks

```go
❌ BAD - potential memory leak:
func fetchAllCerts() []*x509.Certificate {
    var certs []*x509.Certificate
    for {
        cert := fetchNext()
        if cert == nil {
            break
        }
        certs = append(certs, cert)  // Unbounded growth
    }
    return certs
}

✅ GOOD - bounded with context:
func fetchAllCerts(ctx context.Context, maxCerts int) ([]*x509.Certificate, error) {
    certs := make([]*x509.Certificate, 0, maxCerts)
    for i := 0; i < maxCerts; i++ {
        select {
        case <-ctx.Done():
            return certs, ctx.Err()
        default:
        }
        
        cert, err := fetchNext()
        if err != nil {
            return certs, err
        }
        if cert == nil {
            break
        }
        certs = append(certs, cert)
    }
    return certs, nil
}
```

### 3. Efficient Certificate Handling

```go
// Good - process certificates without loading all into memory at once
func processCertificateStream(reader io.Reader, processor func(*x509.Certificate) error) error {
    decoder := pem.NewDecoder(reader)
    
    for {
        block, err := decoder.Decode()
        if err == io.EOF {
            break
        }
        if err != nil {
            return fmt.Errorf("decode error: %w", err)
        }
        
        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            return fmt.Errorf("parse error: %w", err)
        }
        
        // Process certificate immediately, don't accumulate
        if err := processor(cert); err != nil {
            return err
        }
        // cert can be garbage collected here
    }
    
    return nil
}
```

## Goroutine Management

### 1. Proper Goroutine Lifecycle

```go
✅ GOOD - controlled goroutine with cleanup:
func fetchWithTimeout(ctx context.Context) error {
    result := make(chan error, 1)  // Buffered channel prevents goroutine leak
    
    go func() {
        err := doFetch()
        select {
        case result <- err:
            // Sent successfully
        case <-ctx.Done():
            // Context cancelled, don't block
        }
    }()
    
    select {
    case <-ctx.Done():
        return ctx.Err()
    case err := <-result:
        return err
    }
}
```

### 2. Avoid Goroutine Leaks

```go
❌ BAD - goroutine leak:
func badFetch() error {
    result := make(chan error)  // Unbuffered!
    
    go func() {
        result <- doFetch()  // Blocks forever if no receiver
    }()
    
    // If function returns early, goroutine leaks
    return nil
}

✅ GOOD - buffered channel prevents leak:
func goodFetch(ctx context.Context) error {
    result := make(chan error, 1)  // Buffered - goroutine won't block
    
    go func() {
        result <- doFetch()
    }()
    
    select {
    case <-ctx.Done():
        return ctx.Err()  // Goroutine won't leak
    case err := <-result:
        return err
    }
}
```

## Agent Session Memory Management

### 1. Working Memory During Session

Keep track of important information discovered during session:

```
Session Working Memory Template:

KEY FINDINGS:
- Location of bug: src/cli/root.go:145
- Related functions: execCli, fetchCertificateChain
- Dependencies: x509certs.Decode, x509chain.New

FILES MODIFIED:
- src/cli/root.go (added timeout handling)
- src/internal/x509/chain/chain.go (updated error message)

TESTS TO RUN:
- go test -v ./src/cli
- go test -v ./src/internal/x509/chain
- go test -race ./...

PENDING ACTIONS:
- [ ] Run diagnostics on modified files
- [ ] Run test suite
- [ ] Update documentation if needed
```

### 2. Reuse Information Within Session

```
❌ BAD (re-reading same info):
1. grep("FetchCertificate", include="*.go")
2. ... do work ...
3. grep("FetchCertificate", include="*.go")  # Same result!

✅ GOOD (remember from first call):
1. grep("FetchCertificate", include="*.go")
   Result: Found in chain.go:105
2. ... use this information multiple times ...
3. No need to grep again
```

### 3. Todo List for Complex Tasks

Use todowrite for tracking multi-step operations:

```
todowrite([
  {"id": "1", "content": "Find certificate parsing bug location", "status": "completed", "priority": "high"},
  {"id": "2", "content": "Fix parsing logic in certs.go", "status": "in_progress", "priority": "high"},
  {"id": "3", "content": "Add test case for bug scenario", "status": "pending", "priority": "high"},
  {"id": "4", "content": "Run diagnostics on modified files", "status": "pending", "priority": "high"},
  {"id": "5", "content": "Run full test suite", "status": "pending", "priority": "medium"}
])
```

## Resource Optimization

### 1. Network Operations

```go
// Good - timeout and resource limits for HTTP requests
func fetchCertificateFromURL(ctx context.Context, url string) (*x509.Certificate, error) {
    client := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            MaxIdleConns:        10,
            MaxIdleConnsPerHost: 2,
            IdleConnTimeout:     30 * time.Second,
        },
    }
    
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, fmt.Errorf("create request: %w", err)
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("fetch certificate: %w", err)
    }
    defer resp.Body.Close()
    
    // Limit response size to prevent memory exhaustion
    limitedReader := io.LimitReader(resp.Body, 10*1024*1024) // 10MB max
    
    data, err := io.ReadAll(limitedReader)
    if err != nil {
        return nil, fmt.Errorf("read response: %w", err)
    }
    
    return parseCertificate(data)
}
```

### 2. File Operations

```go
// Good - streaming file processing
func processCertificateFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open file: %w", err)
    }
    defer file.Close()
    
    // Don't read entire file into memory
    return processCertificateStream(file, func(cert *x509.Certificate) error {
        // Process each certificate as it's read
        return processCertificate(cert)
    })
}
```

## MCP Connection Memory

### 1. Gopls MCP Connection

**Behavior**: Short-lived, closes after 3-5 operations  
**Memory Impact**: Low - connection state is minimal  
**Action**: No special handling needed, auto-reconnects

### 2. DeepWiki MCP Connection

**Behavior**: Long-lived, persistent connection  
**Memory Impact**: Low - stateless queries  
**Action**: Cache query results to avoid repeated calls

## Monitoring and Debugging

### 1. Memory Profiling (when needed)

```bash
# Run tests with memory profiling
go test -memprofile=mem.out ./...

# Analyze memory profile
go tool pprof mem.out

# Check for memory leaks in specific test
go test -run TestFetchCertificate -memprofile=mem.out ./src/internal/x509/chain
```

### 2. Race Detection

```bash
# Always run before merging changes
go test -race ./...

# Focus on specific package
go test -race -v ./src/internal/x509/chain
```

### 3. Goroutine Debugging

```go
// Add to code temporarily for debugging
import "runtime"

func debugGoroutines() {
    fmt.Printf("Number of goroutines: %d\n", runtime.NumGoroutine())
}
```

## Summary

### Context Management
1. **Always pass context** to certificate operations
2. **Handle cancellation** in long-running operations
3. **Use context.WithCancel** for user-initiated stops
4. **Check ctx.Done()** in loops and network calls

### Memory Management
1. **Use buffer pooling** (bytebufferpool) for certificate data
2. **Avoid unbounded growth** - set limits on certificate chains
3. **Stream processing** - don't load entire files into memory
4. **Proper cleanup** - defer Close() calls
5. **Thread-safe logging** - Use `src/logger` package with `sync.Mutex` for concurrent access

### Goroutine Management
1. **Buffered channels** (size 1) prevent goroutine leaks
2. **Handle context cancellation** in select statements
3. **Limit goroutine creation** - control concurrency
4. **Run race detection** before merges

### Session Management
1. **Track working memory** - remember key findings
2. **Use todo lists** for complex tasks
3. **Reuse information** - don't repeat identical queries

**Critical Pattern for Certificate Fetching**:
```go
// Always use this pattern for certificate operations
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

result := make(chan error, 1)  // Buffered!
go func() {
    result <- operation(ctx)
}()

select {
case <-ctx.Done():
    return ctx.Err()
case err := <-result:
    return err
}
```

### Context Cancellation Testing Pattern

**Test Pattern**: Verify context cancellation works properly in certificate operations

```go
func TestChain_ContextCancellation(t *testing.T) {
    block, _ := pem.Decode([]byte(testCertPEM))
    if block == nil {
        t.Fatal("failed to parse certificate PEM")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        t.Fatalf("failed to parse certificate: %v", err)
    }

    manager := x509chain.New(cert, version)

    ctx, cancel := context.WithCancel(context.Background())
    cancel()  // Cancel immediately

    err = manager.FetchCertificate(ctx)
    if err == nil {
        t.Error("expected error from cancelled context")
    }
}
```

### Graceful Shutdown Pattern

**Pattern**: Handle signal-based graceful shutdown in servers (see MCP server implementation)

```go
// Server graceful shutdown with signal handling
func Run(ctx context.Context, serverName, appVersion string) error {
    // Create cancellable context for graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Set up signal handling for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigChan
        cancel()  // Cancel context on signal
    }()

    // Start server in goroutine
    errChan := make(chan error, 1)
    go func() {
        errChan <- server.ServeStdio(s)  // Your server start function
    }()

    // Wait for either error or shutdown signal
    select {
    case err := <-errChan:
        return err  // Server error
    case <-ctx.Done():
        // Graceful shutdown triggered by signal
        return fmt.Errorf("server shutdown: %w", ctx.Err())
    }
}
```

**Key Elements**:
- `context.WithCancel()` creates cancellable context
- `signal.Notify()` catches SIGINT/SIGTERM
- Goroutine monitors signals and calls `cancel()`
- `select` waits for either server completion or cancellation
- Proper error wrapping with context

**Testing Graceful Shutdown**:

```go
func TestGracefulShutdown(t *testing.T) {
    // Skip on Windows as syscall.Kill is not available and signal handling differs
    if runtime.GOOS == "windows" {
        t.Skip("Skipping signal test on Windows - signals work differently")
    }

    // Start server in background
    go func() {
        err := Run(context.Background(), "test-server", "1.0.0")
        // Should return context.Canceled error on graceful shutdown
        if err == nil || !strings.Contains(err.Error(), "shutdown") {
            t.Errorf("Expected shutdown error, got: %v", err)
        }
    }()

    // Give server time to start
    time.Sleep(100 * time.Millisecond)

    // Send SIGINT to trigger graceful shutdown
    if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
        t.Fatalf("Failed to send SIGINT: %v", err)
    }

    // Wait for shutdown to complete
    select {
    case <-time.After(5 * time.Second):
        t.Fatal("Server did not shut down gracefully within 5 seconds")
    case <-done: // Assuming done channel is signaled when shutdown completes
    }
}
```

### Concurrent Buffer Pool Testing Pattern

**Test Pattern**: Verify buffer pool is safe for concurrent use

```go
func TestGoroutineCooking(t *testing.T) {
    const goroutines = 100
    const iterations = 1000

    var wg sync.WaitGroup
    wg.Add(goroutines)

    for i := range goroutines {
        go func(id int) {
            defer wg.Done()
            for range iterations {
                buf := gc.Default.Get()

                buf.WriteString("goroutine #")
                buf.WriteByte(byte('0' + (id % 10)))
                buf.WriteString(" is sizzling on the CPU like a perfectly grilled steak 🥩")

                if len(buf.Bytes()) < 10 {
                    t.Errorf("Buffer too small: %d bytes", len(buf.Bytes()))
                }

                buf.Reset()
                gc.Default.Put(buf)
            }
        }(i)
    }

    wg.Wait()
}
```

**Thread-Safe Logging Pattern** (see `src/logger/logger.go`):
```go
// Use logger package for concurrent logging
import "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"

// Initialize logger based on mode
var globalLogger logger.Logger
globalLogger = logger.NewMCPLogger(os.Stderr, false)  // Thread-safe with buffer pooling

// Safe to call from multiple goroutines
go func() {
    globalLogger.Printf("Goroutine 1: Processing certificate %d", id)
}()

go func() {
    globalLogger.Printf("Goroutine 2: Processing certificate %d", id)
}()
// MCPLogger uses sync.Mutex + gc.Pool internally - no races, efficient memory
```
