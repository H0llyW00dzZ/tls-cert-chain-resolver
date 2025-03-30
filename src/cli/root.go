// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package cli

import (
	"fmt"
	"os"

	x509certs "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/certs"
	x509chain "github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/internal/x509/chain"
	"github.com/spf13/cobra"
)

var (
	outputFile       string
	intermediateOnly bool
	derFormat        bool
	includeSystem    bool
)

// Execute runs the root command, handling any errors that occur during execution.
func Execute(version string) {
	rootCmd := &cobra.Command{
		Use:     "tls-cert-chain-resolver [INPUT_FILE]",
		Short:   "TLS certificate chain resolver",
		Version: version,
		Args:    cobra.ExactArgs(1),
		Run:     execCli,
	}

	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output to OUTPUT_FILE (default: stdout)")
	rootCmd.Flags().BoolVarP(&intermediateOnly, "intermediate-only", "i", false, "output intermediate certificates only")
	rootCmd.Flags().BoolVarP(&derFormat, "der", "d", false, "output DER format")
	rootCmd.Flags().BoolVarP(&includeSystem, "include-system", "s", false, "include root CA from system in output")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// execCli processes the command-line input to read, decode, and resolve the TLS certificate chain.
// It reads the input certificate file, decodes it, fetches the entire certificate chain, and optionally
// adds the root CA. The output is then prepared in either DER or PEM format and written to the specified
// output file or printed to stdout if no output file is specified.
func execCli(cmd *cobra.Command, args []string) {
	inputFile := args[0]

	// Read the input certificate
	certData, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
		os.Exit(1)
	}

	// Decode the certificate
	decoder := x509certs.New()
	cert, err := decoder.Decode(certData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding certificate: %v\n", err)
		os.Exit(1)
	}

	// Fetch the certificate chain
	chain := x509chain.New(cert)
	if err = chain.FetchCertificate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching certificate chain: %v\n", err)
		os.Exit(1)
	}

	// Add root CA if needed
	if includeSystem {
		if err = chain.AddRootCA(); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding root CA: %v\n", err)
			os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Error writing to output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(string(outputData))
	}
}
