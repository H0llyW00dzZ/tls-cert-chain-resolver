# Memory and Context Management Instructions

## Purpose

Guidelines for efficient memory usage, context management, and resource optimization when working with the X509 certificate chain resolver.

## Context Management

### 1. Context in Certificate Operations

**Critical**: Always pass and use `context.Context` for certificate fetching

```go
// ✅ Good - context-aware certificate fetching
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

**Transport Context Pattern**: Always pass context to transport constructors for proper lifecycle management

```go
// ✅ Good - context-aware transport creation (see src/mcp-server/transport.go)
func createTransport(ctx context.Context) (*InMemoryTransport, error) {
    // Pass context to constructor for proper cancellation handling
    transport := NewInMemoryTransport(ctx)
    
    // Transport will be cancelled when context is cancelled
    return transport, nil
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

### 1. Buffer Pooling for Certificate Pipelines

**Package**: `src/internal/helper/gc`  
**Interface**: `gc.Pool` and `gc.Buffer`  
**Purpose**: Efficient memory usage for certificate processing, logging, and AI sampling requests

The `gc` package wraps `bytebufferpool` to avoid direct dependencies while providing reusable buffers for high-throughput operations such as MCP AI sampling (`src/mcp-server/framework.go:246`).

```go
// ✅ Good - using gc.Default buffer pool for certificate data
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

// ✅ Good - pipe transport using buffer pooling for I/O (see src/mcp-server/pipe.go)
type pipeReader struct {
    t         *InMemoryTransport
    activeBuf gc.Buffer // Current buffer being read
    offset    int       // Read offset in activeBuf
}

func (r *pipeReader) Read(p []byte) (n int, err error) {
    // 1. Serve from active buffer if available
    if r.activeBuf != nil {
        // Read from buffer...
        // If buffer drained, reset and return to pool
        if r.offset >= r.activeBuf.Len() {
            r.activeBuf.Reset()
            gc.Default.Put(r.activeBuf)
            r.activeBuf = nil
        }
        return n, nil
    }
    
    // 2. Wait for new message...
    // 3. Get new buffer from pool
    r.activeBuf = gc.Default.Get()
    r.activeBuf.Write(msg)
    // ...
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
// ❌ BAD - potential memory leak:
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

// ✅ GOOD - bounded with context:
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
// ✅ Good - process certificates without loading all into memory at once
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

### 4. Efficient String Building with fmt.Fprintf

**Pattern**: Use `fmt.Fprintf` with `strings.Builder` or buffer pools for efficient string construction (see `src/mcp-server/handlers.go`)

**Why**: Avoids intermediate string allocations and concatenation overhead

```go
// ✅ Good - efficient string building for certificate context (see src/mcp-server/handlers.go)
func buildCertificateContext(certs []*x509.Certificate, analysisType string) string {
    var context strings.Builder
    
    // Direct writing to builder - no intermediate allocations
    fmt.Fprintf(&context, "Chain Length: %d certificates\n", len(certs))
    fmt.Fprintf(&context, "Analysis Type: %s\n", analysisType)
    fmt.Fprintf(&context, "Current Time: %s UTC\n\n", time.Now().UTC().Format("2006-01-02 15:04:05"))
    
    for i, cert := range certs {
        fmt.Fprintf(&context, "=== CERTIFICATE %d ===\n", i+1)
        fmt.Fprintf(&context, "Role: %s\n", getCertificateRole(i, len(certs)))
        
        // Certificate details with direct formatting
        fmt.Fprintf(&context, "  Common Name: %s\n", cert.Subject.CommonName)
        fmt.Fprintf(&context, "  Organization: %s\n", strings.Join(cert.Subject.Organization, ", "))
        // ... more fields
        
        fmt.Fprintf(&context, "  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
        fmt.Fprintf(&context, "  Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
        // ... more fields
    }
    
    return context.String()
}

// ❌ BAD - inefficient string concatenation:
func badBuildContext(certs []*x509.Certificate) string {
    result := ""
    for _, cert := range certs {
        result += "Certificate: " + cert.Subject.CommonName + "\n"  // Creates new string each time
        result += "Issuer: " + cert.Issuer.CommonName + "\n"        // More allocations
    }
    return result
}

// ✅ GOOD - efficient with fmt.Fprintf:
func goodBuildContext(certs []*x509.Certificate) string {
    var buf strings.Builder
    for _, cert := range certs {
        fmt.Fprintf(&buf, "Certificate: %s\n", cert.Subject.CommonName)  // Direct to buffer
        fmt.Fprintf(&buf, "Issuer: %s\n", cert.Issuer.CommonName)        // No intermediate strings
    }
    return buf.String()
}
```

**Performance Benefits**:
- Reduces memory allocations
- Avoids string concatenation overhead
- Direct writing to destination buffer
- Used extensively in certificate analysis functions

## Goroutine Management

### 1. Proper Goroutine Lifecycle

```go
// ✅ GOOD - controlled goroutine with cleanup:
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
// ❌ BAD - goroutine leak:
func badFetch() error {
    result := make(chan error)  // Unbuffered!
    
    go func() {
        result <- doFetch()  // Blocks forever if no receiver
    }()
    
    // If function returns early, goroutine leaks
    return nil
}

// ✅ GOOD - buffered channel prevents leak:
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

### 3. Semaphore Pattern for Concurrency Control

**Pattern**: Use buffered channels as semaphores to limit concurrent goroutines (see `src/mcp-server/transport.go`)

```go
// ✅ GOOD - controlled concurrency with semaphore and WaitGroups:
type InMemoryTransport struct {
    sem            chan struct{}  // Semaphore to limit concurrency
    shutdownWg     sync.WaitGroup // WaitGroup for graceful shutdown
    processWg      sync.WaitGroup // WaitGroup for message processing loop
    recvCh         chan []byte    // channel for receiving messages (ReadMessage)
    sendCh         chan []byte    // channel for sending messages (WriteMessage)
    internalRespCh chan []byte    // channel for internal responses (e.g. sampling)
    ctx            context.Context
    cancel         context.CancelFunc
}

func NewInMemoryTransport(ctx context.Context) *InMemoryTransport {
    ctx, cancel := context.WithCancel(ctx)
    return &InMemoryTransport{
        sem:            make(chan struct{}, 100), // Limit to 100 concurrent requests
        recvCh:         make(chan []byte, 100),
        sendCh:         make(chan []byte, 100),
        internalRespCh: make(chan []byte, 100),
        ctx:            ctx,
        cancel:         cancel,
    }
}

func (t *InMemoryTransport) processMessages() {
    defer t.processWg.Done()
    
    for {
        select {
        case <-t.ctx.Done():
            return
        case data := <-t.sendCh:
            // Acquire semaphore token (non-blocking check for context)
            select {
            case t.sem <- struct{}{}:
                t.shutdownWg.Add(1)
                // Handle message in a goroutine to avoid blocking the transport loop
                // This ensures that long-running tool calls don't prevent other messages
                // (like notifications or concurrent requests) from being processed.
                go func(data []byte) {
                    defer func() {
                        <-t.sem // Release token
                        t.shutdownWg.Done()
                    }()
                    
                    // Process message...
                }(data)
            case <-t.ctx.Done():
                return
            }
        }
    }
}

func (t *InMemoryTransport) Close() error {
    if t.cancel != nil {
        t.cancel()
    }
    
    // Wait for message processor to stop (no new tasks added)
    t.processWg.Wait()
    
    // Wait for active goroutines to finish
    t.shutdownWg.Wait()
    
    return nil
}
```

**Key Points**:
- Use buffered channel as semaphore to limit concurrent goroutines (e.g., 100 concurrent requests)
- Use separate `WaitGroup` for processor loop (`processWg`) vs active workers (`shutdownWg`)
- Acquire semaphore token before spawning goroutine (prevents unlimited spawning)
- Release semaphore token in deferred cleanup (ensures token release even on panic)
- Wait for `processWg` first (stops accepting new work), then `shutdownWg` (waits for active work)

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
// ✅ Good - timeout and resource limits for HTTP requests
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

// AI API streaming with buffer pooling (see src/mcp-server/framework.go:246)
func (h *DefaultSamplingHandler) CreateMessage(ctx context.Context, request mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
    buf := gc.Default.Get()
    defer func() {
        buf.Reset()
        gc.Default.Put(buf)
    }()

    if h.apiKey == "" {
        return &mcp.CreateMessageResult{
            SamplingMessage: mcp.SamplingMessage{
                Role:    mcp.RoleAssistant,
                Content: mcp.NewTextContent("AI API key not configured. Please set X509_AI_APIKEY environment variable or configure in config.json. This is a placeholder response for demonstration purposes."),
            },
            Model:      "placeholder",
            StopReason: "end",
        }, nil
    }

    var messages []map[string]any
    for _, msg := range request.Messages {
        entry := map[string]any{
            "role": string(msg.Role),
        }
        if textContent, ok := msg.Content.(mcp.TextContent); ok {
            entry["content"] = textContent.Text
        } else {
            entry["content"] = fmt.Sprintf("%v", msg.Content)
        }
        messages = append(messages, entry)
    }

    model := h.model
    if request.ModelPreferences != nil && len(request.ModelPreferences.Hints) > 0 {
        model = request.ModelPreferences.Hints[0].Name
    }

    if request.SystemPrompt != "" {
        systemMessage := map[string]any{
            "role":    "system",
            "content": request.SystemPrompt,
        }
        messages = append([]map[string]any{systemMessage}, messages...)
    }

    payload := map[string]any{
        "model":       model,
        "messages":    messages,
        "max_tokens":  request.MaxTokens,
        "temperature": request.Temperature,
        "stream":      true,
    }

    if len(request.StopSequences) > 0 {
        payload["stop"] = request.StopSequences
    }

    body, err := json.Marshal(payload)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal API request: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint+"/v1/chat/completions", bytes.NewReader(body))
    if err != nil {
        return nil, fmt.Errorf("failed to create HTTP request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+h.apiKey)
    req.Header.Set("User-Agent", "X.509-Certificate-Chain-Resolver-MCP/"+h.version+" (+https://github.com/H0llyW00dzZ/tls-cert-chain-resolver)")

    resp, err := h.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to call AI API: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        if _, err := buf.ReadFrom(resp.Body); err != nil {
            return nil, fmt.Errorf("AI API error (status %d): failed to read error response: %w", resp.StatusCode, err)
        }
        return nil, fmt.Errorf("AI API error (status %d): %s", resp.StatusCode, buf.String())
    }

    var content strings.Builder
    scanner := bufio.NewScanner(resp.Body)
    modelName := model
    stopReason := "stop"

    for scanner.Scan() {
        line := scanner.Text()
        if line == "" || strings.HasPrefix(line, ":") {
            continue
        }

        chunkJSON, ok := strings.CutPrefix(line, "data: ")
        if !ok {
            continue
        }
        if chunkJSON == "[DONE]" {
            break
        }

        var chunk map[string]any
        if err := json.Unmarshal([]byte(chunkJSON), &chunk); err != nil {
            continue
        }

        if v, ok := chunk["model"].(string); ok && modelName == model {
            modelName = v
        }

        choices, ok := chunk["choices"].([]any)
        if !ok || len(choices) == 0 {
            continue
        }
        choice, ok := choices[0].(map[string]any)
        if !ok {
            continue
        }

        if delta, ok := choice["delta"].(map[string]any); ok {
            if text, ok := delta["content"].(string); ok {
                content.WriteString(text)
            }
        }

        if finishReason, ok := choice["finish_reason"].(string); ok && finishReason != "" {
            stopReason = finishReason
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading streaming response: %w", err)
    }

    return &mcp.CreateMessageResult{
        SamplingMessage: mcp.SamplingMessage{
            Role:    mcp.RoleAssistant,
            Content: mcp.NewTextContent(content.String()),
        },
        Model:      modelName,
        StopReason: stopReason,
    }, nil
}
```

### 2. File Operations

```go
// ✅ Good - streaming file processing
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

### 3. X509 Resolver MCP Connection

**Behavior**: Long-lived local server with streaming AI analysis support  
**Memory Impact**: Medium when AI sampling is enabled (streaming buffers)  
**Action**: Use buffer pooling (`gc.Default`) and reset buffers immediately after streaming completes
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

### 4. JSON-RPC Message Handling Pattern

**Pattern**: Use `jsonrpc` helper package for normalization
**When to use**: Implementing MCP transports or handling JSON-RPC messages
**Implementation**: Use `src/internal/helper/jsonrpc` package for JSON-RPC 2.0 compliance

```go
// JSON-RPC message normalization pattern
// Import: "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/jsonrpc"

func normalizeJSONRPCMessage(msg jsonrpc.Message) ([]byte, error) {
    // Marshal to JSON first
    data, err := json.Marshal(msg)
    if err != nil {
        return nil, err
    }

    // Use helper package for canonicalization (lowercase keys, version, ID handling)
    return jsonrpc.Marshal(data)
}

// JSON-RPC unmarshaling pattern
// Use UnmarshalFromMap for safe conversion from map[string]any to struct
func convertParams(params map[string]any, target any) error {
    // mcp.JSONRPC_VERSION is handled automatically by jsonrpc.Map/Marshal
    return jsonrpc.UnmarshalFromMap(params, target)
}
```

**Key Points**:
- Helper package handles field name normalization (lowercase)
- Automatically handles ID field (null vs value) and float-to-int conversion
- Ensures `jsonrpc: "2.0"` is present
- Centralized logic avoids duplication across transports
- `UnmarshalFromMap` provides safe type conversion via JSON round-trip

## Summary

### Context Management
1. **Always pass context** to certificate operations
2. **Handle cancellation** in long-running operations
3. **Use context.WithCancel** for user-initiated stops
4. **Check ctx.Done()** in loops and network calls

### Memory Management
1. **Use buffer pooling** (bytebufferpool) for certificate and AI streaming data
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

// Always check revocation status after chain resolution
chain := x509chain.New(cert, version)
err := chain.FetchCertificate(ctx)
if err == nil {
    revocationStatus, _ := chain.CheckRevocationStatus(ctx)
    // Process revocation status with buffer pooling
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
