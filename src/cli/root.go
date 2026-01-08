// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/helper/posix"
	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
	"github.com/spf13/cobra"
)

var (
	// OperationPerformed indicates whether the main certificate resolution operation was executed.
	OperationPerformed bool
	// OperationPerformedSuccessfully indicates whether the main certificate resolution operation was completed successfully.
	OperationPerformedSuccessfully bool
)

var (
	outputFile       string
	intermediateOnly bool
	derFormat        bool
	includeSystem    bool
	jsonFormat       bool          // New flag for JSON output
	treeFormat       bool          // New flag for ASCII tree visualization
	tableFormat      bool          // New flag for table visualization
	inputFile        string        // New variable for input file
	globalLogger     logger.Logger // Global logger instance
)

var (
	// ErrInputFileRequired is returned when no input file is specified.
	ErrInputFileRequired = errors.New("input file must be specified with -f or --file")
)

// Execute sets up and runs the TLS certificate chain resolver command-line interface.
//
// Execute initializes the root cobra command with all flags, validation, and
// execution logic for the certificate chain resolver. It configures the CLI
// with multiple output formats, validation options, and proper error handling.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control (passed to certificate operations)
//   - version: Version string to display in the CLI
//   - log: Logger instance for output (supports both CLI and MCP modes)
//
// Returns:
//   - error: Command execution error or nil on success
//
// Command Features:
//   - Input file validation (required -f/--file flag)
//   - Multiple output formats: PEM, DER, JSON, ASCII tree, table
//   - Certificate filtering: intermediate-only, include-system roots
//   - Context-aware cancellation support
//   - Comprehensive logging with version information
//
// The command structure includes:
//   - Argument validation ensuring input file is specified
//   - Pre-execution logging with version and cancellation instructions
//   - Post-execution success tracking
//   - Flag configuration for all supported options
//
// Example usage handled by this function:
//
//	<exe> -f cert.pem -o output.pem
//	<exe> -f cert.pem -t  # tree format
//	<exe> -f cert.pem -j  # JSON format
//
// Where <exe> is the actual executable name (determined dynamically).
func Execute(ctx context.Context, version string, log logger.Logger) error {
	globalLogger = log

	// Use cross-platform executable name for consistent CLI UX
	exeName := posix.GetExecutableName()

	rootCmd := &cobra.Command{
		Use:   exeName,
		Short: "TLS certificate chain resolver",
		Example: fmt.Sprintf(`  %s -f test-leaf.cer -o test-output-bundle.pem
  %s -f another-cert.cer -o test-output-bundle.crt --der --include-system`, exeName, exeName),
		Version: version,
		Args: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return ErrInputFileRequired
			}
			return nil
		},
		// TODO: This execution flow could be improved, but the current implementation
		// is sufficient for the CLI's needs.
		RunE: func(cmd *cobra.Command, args []string) error {
			// Log start with version
			globalLogger.Printf("Starting TLS certificate chain resolver (v%s)...", version)
			globalLogger.Println(
				"Note: Press CTRL+C or send a termination signal (e.g., SIGINT or SIGTERM)",
				"via your operating system to exit if incomplete (e.g., hanging while fetching certificates).\n",
			)
			OperationPerformed = true
			return execCli(ctx, cmd)
		},
		PostRun:      func(cmd *cobra.Command, args []string) { OperationPerformedSuccessfully = true },
		SilenceUsage: true,
	}

	rootCmd.Flags().StringVarP(&inputFile, "file", "f", "", "input certificate file")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output to OUTPUT_FILE (default: stdout)")
	rootCmd.Flags().BoolVarP(&intermediateOnly, "intermediate-only", "i", false, "output intermediate certificates only")
	rootCmd.Flags().BoolVarP(&derFormat, "der", "d", false, "output DER format")
	rootCmd.Flags().BoolVarP(&includeSystem, "include-system", "s", false, "include root CA from system in output")
	rootCmd.Flags().BoolVarP(&jsonFormat, "json", "j", false, "output in JSON format with PEM-encoded certificates and their chains")
	rootCmd.Flags().BoolVarP(&treeFormat, "tree", "t", false, "display certificate chain as ASCII tree")
	rootCmd.Flags().BoolVarP(&tableFormat, "table", "", false, "display certificate chain as formatted table")

	return rootCmd.Execute()
}

// certificateInfo represents the details of a single certificate,
// including its subject, issuer, serial number, and PEM-encoded data.
type certificateInfo struct {
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	Serial             string `json:"serial"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	PEM                string `json:"pem"`
}

// jsonOutput defines the structure for the JSON output format,
// containing a title, the total number of certificates in the chain,
// and a list of certificate details.
type jsonOutput struct {
	Title        string            `json:"title"`
	TotalChained int               `json:"totalChained"`
	Certificates []certificateInfo `json:"listCertificates"`
}

// execCli executes the main certificate chain resolution logic.
//
// It reads the input certificate file, decodes it, fetches the complete certificate
// chain, optionally adds the system root CA, and outputs the results in the
// requested format (DER, PEM, JSON, tree, or table visualization).
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//   - cmd: Cobra command instance containing version and flag information
//
// Returns:
//   - error: Any error that occurs during certificate processing or output
func execCli(ctx context.Context, cmd *cobra.Command) error {
	// Read the input certificate file
	certData, err := readCertificateFile(inputFile)
	if err != nil {
		return err
	}

	// Decode the certificate
	certManager := x509certs.New()
	cert, err := decodeCertificate(certData, certManager)
	if err != nil {
		return err
	}

	// Fetch the certificate chain
	chain, err := fetchCertificateChain(ctx, cert, cmd.Version)
	if err != nil {
		return err
	}

	// Optionally add the root CA
	if includeSystem {
		if err = chain.AddRootCA(); err != nil {
			return fmt.Errorf("error adding root CA: %w", err)
		}
	}

	// Filter certificates if needed
	certsToOutput := filterCertificates(chain)

	// Determine visualization format - default to tree
	visualizationFormat := "tree"
	if tableFormat {
		visualizationFormat = "table"
	}

	// Show visualization
	switch visualizationFormat {
	case "tree":
		globalLogger.Println("Certificate chain complete. Total", len(chain.Certs), "certificate(s) found.")
		treeOutput := chain.RenderASCIITree(ctx)
		globalLogger.Println(treeOutput)
	case "table":
		tableOutput := chain.RenderTable(ctx)
		globalLogger.Println(tableOutput)
		globalLogger.Println("Certificate chain complete. Total", len(chain.Certs), "certificate(s) found.\n")
	}

	// Output in JSON format if specified
	if jsonFormat {
		return outputJSON(certsToOutput, certManager)
	}
	// Output certificates in DER/PEM format
	return outputCertificates(certsToOutput, certManager)
}

// readCertificateFile reads certificate data from the specified file.
//
// It reads the entire file contents into memory and returns the raw certificate
// data. This data can then be parsed as either PEM or DER format.
//
// Parameters:
//   - inputFile: Path to the certificate file to read
//
// Returns:
//   - []byte: Raw certificate data from the file
//   - error: File reading error if the file cannot be accessed or read
func readCertificateFile(inputFile string) ([]byte, error) {
	certData, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("error reading input file '%s': %w", inputFile, err)
	}
	return certData, nil
}

// decodeCertificate decodes raw certificate data into an X.509 certificate.
//
// It uses the provided certificate manager to parse the certificate data,
// which can be in either PEM or DER format. The manager automatically
// detects the format and parses accordingly.
//
// Parameters:
//   - certData: Raw certificate data (PEM or DER format)
//   - certManager: Certificate manager instance for parsing operations
//
// Returns:
//   - *x509.Certificate: Parsed X.509 certificate
//   - error: Parsing error if the certificate data is invalid or malformed
func decodeCertificate(certData []byte, certManager *x509certs.Certificate) (*x509.Certificate, error) {
	cert, err := certManager.Decode(certData)
	if err != nil {
		return nil, fmt.Errorf("error decoding certificate (%d bytes): %w", len(certData), err)
	}
	return cert, nil
}

// fetchCertificateChain retrieves the complete certificate chain for the given certificate.
//
// It creates a new certificate chain manager, fetches all intermediate certificates
// using AIA (Authority Information Access) URLs, and returns the fully resolved chain.
// The operation is performed asynchronously with proper context cancellation support.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling during chain fetching
//   - cert: Starting certificate (typically the leaf/end-entity certificate)
//   - version: Application version string for HTTP User-Agent headers
//
// Returns:
//   - *x509chain.Chain: Fully resolved certificate chain with intermediates
//   - error: Any error that occurs during chain fetching or verification
func fetchCertificateChain(ctx context.Context, cert *x509.Certificate, version string) (*x509chain.Chain, error) {
	// Create a chain manager
	chain := x509chain.New(cert, version)

	// Channel to signal completion or error
	result := make(chan error, 1)

	// Fetch the certificate chain asynchronously
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

// filterCertificates filters the certificate chain based on command-line flags.
//
// It returns either all certificates in the chain or only the intermediate
// certificates, depending on the intermediateOnly flag setting.
//
// Parameters:
//   - chain: The resolved certificate chain to filter
//
// Returns:
//   - []*x509.Certificate: Filtered certificate slice
func filterCertificates(chain *x509chain.Chain) []*x509.Certificate {
	if intermediateOnly {
		return chain.FilterIntermediates()
	}
	return chain.Certs
}

// outputJSON outputs the certificates in structured JSON format.
//
// It creates a JSON array containing detailed certificate information
// including subject, issuer, validity dates, and PEM-encoded data.
// The JSON output is written to stdout.
//
// Parameters:
//   - certsToOutput: Certificates to include in the JSON output
//   - certManager: Certificate manager for PEM encoding operations
//
// Returns:
//   - error: JSON marshaling or output error
func outputJSON(certsToOutput []*x509.Certificate, certManager *x509certs.Certificate) error {
	certInfos := make([]certificateInfo, len(certsToOutput))
	for i, cert := range certsToOutput {
		pemData := certManager.EncodePEM(cert)
		// TODO: Leverage this certificateInfo JSON data effectively
		certInfos[i] = certificateInfo{
			Subject:            cert.Subject.CommonName,
			Issuer:             cert.Issuer.CommonName,
			Serial:             cert.SerialNumber.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PEM:                string(pemData),
		}
	}

	jsonOutput := jsonOutput{
		Title:        "TLS Certificate Resolver",
		TotalChained: len(certsToOutput),
		Certificates: certInfos,
	}

	outputData, err := json.MarshalIndent(jsonOutput, "", "  ")
	if err != nil {
		return fmt.Errorf("error encoding JSON: %w", err)
	}

	return writeOutput(outputData)
}

// outputCertificates outputs the certificates in the requested format (DER or PEM).
//
// It encodes all certificates in the chain using either DER or PEM format
// based on the derFormat flag, then writes the output to file or stdout.
//
// Parameters:
//   - certsToOutput: Certificates to encode and output
//   - certManager: Certificate manager for encoding operations
//
// Returns:
//   - error: Encoding or output error
func outputCertificates(certsToOutput []*x509.Certificate, certManager *x509certs.Certificate) error {
	// Prepare output
	var outputData []byte
	if derFormat {
		outputData = certManager.EncodeMultipleDER(certsToOutput)
	} else {
		outputData = certManager.EncodeMultiplePEM(certsToOutput)
	}

	// Output the certificates
	return writeOutput(outputData)
}

// writeOutput writes the certificate data to the specified output file or stdout.
//
// If an output file is specified via the outputFile flag, it writes the data
// to that file with appropriate permissions. Otherwise, it writes to stdout
// for console output or piping.
//
// Parameters:
//   - data: Certificate data to write (DER, PEM, JSON, etc.)
//
// Returns:
//   - error: File writing error if output file cannot be created or written
func writeOutput(data []byte) error {
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("error writing to output file: %w", err)
		}
		globalLogger.Printf("Output successfully written to %s.", outputFile)
	} else {
		fmt.Println(string(data))
		globalLogger.Println("Output successfully written to stdout.")
	}
	return nil
}
