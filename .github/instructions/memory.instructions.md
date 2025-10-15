# Memory and Context Management Instructions

## Purpose

Guidelines for efficient memory usage, context management, and resource optimization when working with the TLS certificate chain resolver.

## Token Budget Management

**Total Budget**: 200,000 tokens per session  
**Current Usage Tracking**: Monitor via system warnings  
**Critical Threshold**: 80% usage (160,000 tokens)

### Token Usage Best Practices

#### 1. Efficient Tool Usage

```
❌ HIGH TOKEN USAGE:
- Reading entire large files repeatedly
- Repeated identical tool calls
- Reading files you won't modify
- Verbose command outputs

✅ LOW TOKEN USAGE:
- Windowed reading (offset + limit)
- Caching tool results in working memory
- Targeted grep before read
- Selective file reading
```

#### 2. Windowed Reading for Large Files

```
# Instead of reading entire file (2000 lines)
read("/path/to/large-file.go")  # Consumes ~8000 tokens

# Use windowed reading after grep
grep("FetchCertificate", include="*.go")  # Find line 105
read("/path/to/large-file.go", offset=100, limit=30)  # Only ~1000 tokens
```

#### 3. Avoid Redundant Operations

```
❌ BAD (repeats same read):
read("file.go")
... do something ...
read("file.go")  # Wasteful if content hasn't changed

✅ GOOD (read once, use multiple times):
read("file.go")
... analyze content ...
edit("file.go", ...)
gopls_go_diagnostics(["file.go"])
```

#### 4. Batch Independent Operations

```
❌ BAD (sequential, multiple round trips):
read("file1.go")
# wait for response
read("file2.go")
# wait for response
read("file3.go")

✅ GOOD (parallel, single round trip):
# Call all three read operations in one message
read("file1.go")
read("file2.go")
read("file3.go")
# All execute concurrently
```

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

## Memory Management

### 1. Buffer Pooling

**Library**: `github.com/valyala/bytebufferpool`  
**Purpose**: Efficient memory usage with certificates

```go
// Good - using buffer pool for certificate data
var bufPool bytebufferpool.Pool

func processCertificates(certs []*x509.Certificate) []byte {
    buf := bufPool.Get()
    defer bufPool.Put(buf)
    
    // Use buf for operations
    for _, cert := range certs {
        buf.Write(pem.EncodeToMemory(&pem.Block{
            Type:  "CERTIFICATE",
            Bytes: cert.Raw,
        }))
    }
    
    // Copy result before returning (buf will be pooled)
    result := make([]byte, buf.Len())
    copy(result, buf.Bytes())
    return result
}
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

### Token Management
1. **Use windowed reading** (offset + limit) for large files
2. **Batch tool calls** for parallel execution
3. **Avoid redundant reads** - remember information within session
4. **Use grep first** to locate content before reading

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

### Goroutine Management
1. **Buffered channels** (size 1) prevent goroutine leaks
2. **Handle context cancellation** in select statements
3. **Limit goroutine creation** - control concurrency
4. **Run race detection** before merges

### Session Management
1. **Track working memory** - remember key findings
2. **Use todo lists** for complex tasks
3. **Reuse information** - don't repeat identical queries
4. **Monitor token usage** - stay under 80% threshold

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
