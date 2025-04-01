// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
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
	jsonFormat       bool // New flag for JSON output
)

// Execute runs the root command, handling any errors that occur during execution.
func Execute(ctx context.Context, version string) error {
	rootCmd := &cobra.Command{
		Use:   "tls-cert-chain-resolver [INPUT_FILE]",
		Short: "TLS certificate chain resolver",
		Example: `  tls-cert-chain-resolver test-leaf.cer -o test-output-bundle.pem
  tls-cert-chain-resolver another-cert.cer -o test-output-bundle.crt --der --include-system`,
		Version: version,
		Args:    cobra.ExactArgs(1),
		// TODO: This might need improvment however this doesn't actually important to improve even cobra has 3 function execute,
		// because 2 function or 1 function execute its already enought.
		RunE: func(cmd *cobra.Command, args []string) error {
			// Log start with version
			log.Printf("Starting TLS certificate chain resolver (v%s)...", version)
			log.Println(
				"Note: Press CTRL+C or send a termination signal (e.g., SIGINT or SIGTERM)",
				"via your operating system to exit if incomplete (e.g., hanging while fetching certificates).",
			)
			log.Println()
			OperationPerformed = true
			return execCli(ctx, cmd, args)
		},
		PostRun: func(cmd *cobra.Command, args []string) { OperationPerformedSuccessfully = true },
	}

	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output to OUTPUT_FILE (default: stdout)")
	rootCmd.Flags().BoolVarP(&intermediateOnly, "intermediate-only", "i", false, "output intermediate certificates only")
	rootCmd.Flags().BoolVarP(&derFormat, "der", "d", false, "output DER format")
	rootCmd.Flags().BoolVarP(&includeSystem, "include-system", "s", false, "include root CA from system in output")
	rootCmd.Flags().BoolVarP(&jsonFormat, "json", "j", false, "output in JSON format with PEM-encoded certificates and their chains")

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

// execCli processes the command-line input to read, decode, and resolve the TLS certificate chain.
// It reads the input certificate file, decodes it, fetches the entire certificate chain, and optionally
// adds the root CA. The output is then prepared in either DER or PEM format and written to the specified
// output file or printed to stdout if no output file is specified.
func execCli(ctx context.Context, cmd *cobra.Command, args []string) error {
	// Read the input certificate file
	certData, err := readCertificateFile(args[0])
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

	// Log each certificate in the chain
	for i, c := range chain.Certs {
		log.Printf("%d: %s", i+1, c.Subject.CommonName)
	}
	log.Printf("Certificate chain complete. Total %d certificate(s) found.", len(chain.Certs))

	// Filter certificates if needed
	certsToOutput := filterCertificates(chain)

	// Output in JSON format if specified
	if jsonFormat {
		return outputJSON(certsToOutput, certManager)
	}

	// Output certificates in DER/PEM format
	return outputCertificates(certsToOutput, certManager)
}

// readCertificateFile reads the certificate from the specified file.
func readCertificateFile(inputFile string) ([]byte, error) {
	certData, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("error reading input file: %w", err)
	}
	return certData, nil
}

// decodeCertificate decodes the certificate data into an x509.Certificate.
func decodeCertificate(certData []byte, certManager *x509certs.Certificate) (*x509.Certificate, error) {
	cert, err := certManager.Decode(certData)
	if err != nil {
		return nil, fmt.Errorf("error decoding certificate: %w", err)
	}
	return cert, nil
}

// fetchCertificateChain retrieves the certificate chain starting from the given certificate.
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

// filterCertificates filters the certificates based on the intermediateOnly flag.
func filterCertificates(chain *x509chain.Chain) []*x509.Certificate {
	if intermediateOnly {
		return chain.FilterIntermediates()
	}
	return chain.Certs
}

// outputJSON outputs the certificates in JSON format.
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

// outputCertificates outputs the certificates in DER or PEM format.
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

// writeOutput writes the output data to the specified file or stdout.
func writeOutput(data []byte) error {
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("error writing to output file: %w", err)
		}
		log.Printf("Output successfully written to %s.", outputFile)
	} else {
		fmt.Print(string(data))
		log.Println("Output successfully written to stdout.")
	}
	return nil
}
