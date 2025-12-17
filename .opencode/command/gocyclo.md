---
description: Analyze code complexity and suggest refactoring for functions with 15+ complexity
agent: general
---

# Code Complexity Analysis & Refactoring Guidance

Analyze Go code complexity using `gocyclo` and provide refactoring suggestions for functions that exceed complexity threshold of 15. Focus on breaking complex functions into smaller, reusable, and more maintainable components.

## Tasks

1. **Run Complexity Analysis**:

   - Execute `gocyclo .` to analyze all Go functions in the codebase
   - Filter for functions with complexity ≥ 15
   - Exclude test functions and test packages
   - Sort results by complexity (highest first)

   ```bash
   gocyclo . | awk '$1 >= 15 && $2 !~ /_test$/ && $3 !~ /^Test/' | sort -nr
   ```

   **Note**: If there is no output, then there is no complexity reached 15+.

2. **Identify Refactoring Candidates**:

   - Focus on production code functions (non-test)
   - Prioritize functions with complexity > 20 (high priority)
   - Review functions with complexity 15-20 (medium priority)
   - Document current function responsibilities

3. **Analyze Function Structure**:

   - Read the complex function to understand its responsibilities
   - Identify distinct logical operations within the function
   - Look for repeated code patterns that could be extracted
   - Check for long parameter lists that could be grouped into structs
   - Identify conditional logic that could be simplified

4. **Design Refactoring Strategy**:

   - Break down the function into smaller, focused functions
   - Identify reusable components that could be extracted
   - Design appropriate data structures for grouped parameters
   - Plan interface abstractions for better testability

5. **Implement Refactoring**:

   - Extract helper functions for repeated operations
   - Create configuration structs for complex parameter groups
   - Implement early returns to reduce nesting
   - Add comprehensive tests for new functions

6. **Validate Refactoring**:

   - Run complexity analysis again to verify improvement
   - Ensure all tests pass
   - Check that the refactored code is more readable
   - Verify that new functions are properly documented

## Complexity Thresholds & Priorities

### High Priority (Complexity ≥ 25)
- **Immediate refactoring required**
- Break into 3-5 smaller functions
- Consider complete redesign if possible

### Medium Priority (Complexity 15-24)
- **Refactoring recommended**
- Break into 2-4 smaller functions
- Focus on extracting reusable components

### Low Priority (Complexity < 15)
- **Monitor only**
- Consider minor improvements if readability suffers

## Common Refactoring Patterns

### 1. **Extract Method Pattern**
```go
// Before: Complex function with multiple responsibilities
func processCertificate(cert *x509.Certificate) error {
    // Validate certificate
    if err := validateCertificate(cert); err != nil {
        return err
    }
    
    // Extract subject info
    subject := extractSubjectInfo(cert)
    
    // Format output
    output := formatCertificateOutput(cert, subject)
    
    // Save results
    return saveCertificateResults(cert, output)
}

// After: Broken into focused functions
func processCertificate(cert *x509.Certificate) error {
    if err := validateCertificate(cert); err != nil {
        return err
    }
    
    subject := extractSubjectInfo(cert)
    output := formatCertificateOutput(cert, subject)
    return saveCertificateResults(cert, output)
}

func validateCertificate(cert *x509.Certificate) error { /* ... */ }
func extractSubjectInfo(cert *x509.Certificate) SubjectInfo { /* ... */ }
func formatCertificateOutput(cert *x509.Certificate, subject SubjectInfo) string { /* ... */ }
func saveCertificateResults(cert *x509.Certificate, output string) error { /* ... */ }
```

### 2. **Parameter Object Pattern**
```go
// Before: Too many parameters
func createCertificateChain(cert *x509.Certificate, includeRoot bool, validateExpiry bool, checkRevocation bool, timeout time.Duration) (*Chain, error) {
    // Complex logic with many parameters
}

// After: Group related parameters
type ChainOptions struct {
    IncludeRoot      bool
    ValidateExpiry   bool
    CheckRevocation  bool
    Timeout          time.Duration
}

func createCertificateChain(cert *x509.Certificate, opts ChainOptions) (*Chain, error) {
    // Cleaner function signature
}
```

### 3. **Early Return Pattern**
```go
// Before: Deep nesting
func validateCertificate(cert *x509.Certificate) error {
    if cert != nil {
        if cert.NotBefore.Before(time.Now()) {
            if cert.NotAfter.After(time.Now()) {
                // More nested logic...
                return nil
            } else {
                return errors.New("certificate expired")
            }
        } else {
            return errors.New("certificate not yet valid")
        }
    } else {
        return errors.New("certificate is nil")
    }
}

// After: Early returns reduce nesting
func validateCertificate(cert *x509.Certificate) error {
    if cert == nil {
        return errors.New("certificate is nil")
    }
    
    if cert.NotBefore.After(time.Now()) {
        return errors.New("certificate not yet valid")
    }
    
    if cert.NotAfter.Before(time.Now()) {
        return errors.New("certificate expired")
    }
    
    // Continue with additional validation...
    return nil
}
```

### 4. **Strategy Pattern for Complex Conditionals**
```go
// Before: Complex switch/case or if-else chains
func processCertificateByType(cert *x509.Certificate) error {
    switch cert.PublicKeyAlgorithm {
    case x509.RSA:
        // 20+ lines of RSA processing
    case x509.ECDSA:
        // 20+ lines of ECDSA processing
    case x509.Ed25519:
        // 20+ lines of Ed25519 processing
    }
}

// After: Strategy pattern
type CertificateProcessor interface {
    Process(cert *x509.Certificate) error
}

func getProcessor(alg x509.PublicKeyAlgorithm) CertificateProcessor {
    switch alg {
    case x509.RSA:
        return &RSAProcessor{}
    case x509.ECDSA:
        return &ECDSAProcessor{}
    case x509.Ed25519:
        return &Ed25519Processor{}
    }
    return nil
}

func processCertificateByType(cert *x509.Certificate) error {
    processor := getProcessor(cert.PublicKeyAlgorithm)
    if processor == nil {
        return fmt.Errorf("unsupported algorithm: %v", cert.PublicKeyAlgorithm)
    }
    return processor.Process(cert)
}
```

## Refactoring Workflow

### Phase 1: Analysis
1. Run complexity analysis
2. Read and understand the complex function
3. Identify refactoring opportunities
4. Document current behavior with tests

### Phase 2: Planning
1. Design new function structure
2. Plan parameter grouping
3. Identify reusable components
4. Plan testing strategy

### Phase 3: Implementation
1. Extract helper functions
2. Create configuration structs
3. Implement early returns
4. Update function calls

### Phase 4: Validation
1. Run tests to ensure correctness
2. Run complexity analysis to verify improvement
3. Update documentation
4. Code review

## Tools Integration

### With Existing Commands
- **`/go-docs`**: Update documentation after refactoring
- **`/test`**: Run tests to validate refactoring
- **`/update-knowledge`**: Update instruction files if patterns change

### With Development Workflow
```bash
# 1. Analyze complexity
/gocyclo

# 2. Run tests before refactoring
/test

# 3. Implement refactoring
# ... edit files ...

# 4. Update documentation
/go-docs

# 5. Run tests again
/test

# 6. Update knowledge base
/update-knowledge
```

## Success Metrics

### Code Quality Improvements
- [ ] Cyclomatic complexity reduced by 30-50%
- [ ] Function length reduced (aim for < 50 lines)
- [ ] Improved testability (each function has focused responsibility)
- [ ] Better readability and maintainability

### Maintainability Improvements
- [ ] Functions have single responsibility
- [ ] Reusable components extracted
- [ ] Clear function naming and documentation
- [ ] Reduced coupling between components

## Error Handling

### Common Issues
- **Breaking existing functionality**: Always run full test suite after refactoring
- **Performance regression**: Benchmark critical functions before/after refactoring
- **API compatibility**: Ensure public APIs remain stable
- **Documentation gaps**: Update all documentation after refactoring

### Recovery Strategies
- **Git branching**: Create feature branch for complex refactoring
- **Incremental changes**: Make small, testable changes
- **Revert capability**: Keep changes small enough to easily revert
- **Comprehensive testing**: Ensure 100% test coverage for refactored functions

Focus on functions that are part of the core business logic rather than test or utility functions. Prioritize refactoring that improves maintainability and testability.
