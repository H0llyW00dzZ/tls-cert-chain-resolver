// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package cli

import (
	"context"
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
)

var (
	outputFile       string
	intermediateOnly bool
	derFormat        bool
	includeSystem    bool
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
	}

	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output to OUTPUT_FILE (default: stdout)")
	rootCmd.Flags().BoolVarP(&intermediateOnly, "intermediate-only", "i", false, "output intermediate certificates only")
	rootCmd.Flags().BoolVarP(&derFormat, "der", "d", false, "output DER format")
	rootCmd.Flags().BoolVarP(&includeSystem, "include-system", "s", false, "include root CA from system in output")

	return rootCmd.Execute()
}

// execCli processes the command-line input to read, decode, and resolve the TLS certificate chain.
// It reads the input certificate file, decodes it, fetches the entire certificate chain, and optionally
// adds the root CA. The output is then prepared in either DER or PEM format and written to the specified
// output file or printed to stdout if no output file is specified.
func execCli(ctx context.Context, cmd *cobra.Command, args []string) error {
	inputFile := args[0]

	// Read the input certificate
	certData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// Decode the certificate
	decoder := x509certs.New()
	cert, err := decoder.Decode(certData)
	if err != nil {
		return fmt.Errorf("error decoding certificate: %w", err)
	}

	// Create a chain manager
	chain := x509chain.New(cert, cmd.Version)

	// Channel to signal completion or error
	result := make(chan error, 1)

	// Fetch the certificate chain asynchronously
	go func() {
		err := chain.FetchCertificate(ctx)
		result <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		if err != nil {
			return fmt.Errorf("error fetching certificate chain: %w", err)
		}
	}

	// Log each certificate in the chain
	for i, c := range chain.Certs {
		log.Printf("%d: %s", i+1, c.Subject.CommonName)
	}

	// Add root CA if needed
	if includeSystem {
		if err = chain.AddRootCA(); err != nil {
			return fmt.Errorf("error adding root CA: %w", err)
		}
	}

	// Filter intermediates if needed
	certsToOutput := chain.Certs
	if intermediateOnly {
		certsToOutput = chain.FilterIntermediates()
	}

	// Prepare output
	var outputData []byte
	if derFormat {
		outputData = chain.EncodeMultipleDER(certsToOutput)
	} else {
		outputData = chain.EncodeMultiplePEM(certsToOutput)
	}

	// Output the certificates
	if outputFile != "" {
		if err = os.WriteFile(outputFile, outputData, 0644); err != nil {
			return fmt.Errorf("error writing to output file: %w", err)
		}
		log.Printf("Output successfully written to %s.", outputFile)
	} else {
		fmt.Print(string(outputData))
		log.Println("Output successfully written to stdout.")
	}

	log.Printf("Certificate chain complete. Total %d certificate(s) found.", len(certsToOutput))
	return nil
}
