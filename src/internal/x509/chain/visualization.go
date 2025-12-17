// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// parseRevocationStatusForVisualization parses the revocation status report into a map format
// suitable for visualization methods.
//
// It extracts the final status for each certificate from the detailed revocation report
// and creates a map where keys are certificate serial numbers and values are status strings.
//
// Parameters:
//   - revocationReport: The formatted string report from CheckRevocationStatus
//   - chain: The certificate chain to extract serial numbers from
//
// Returns:
//   - map[string]string: Map of serial number to revocation status
//
// Thread Safety: Safe for concurrent use (no state modification).
func parseRevocationStatusForVisualization(revocationReport string, chain *Chain) map[string]string {
	statusMap := initializeStatusMap(chain)

	// Parse the revocation report to extract actual statuses
	lines := strings.Split(revocationReport, "\n")
	for i, line := range lines {
		if certIndex := extractCertificateIndex(line); certIndex >= 0 {
			if status := findFinalStatus(lines, i); status != "" {
				// Update status for this certificate (certIndex is already 0-based)
				if certIndex < len(chain.Certs) {
					statusMap[chain.Certs[certIndex].SerialNumber.String()] = status
				}
			}
		}
	}

	return statusMap
}

// initializeStatusMap creates a status map with all certificates defaulting to "unknown".
//
// It initializes a map where each certificate's serial number is mapped to "unknown"
// status, providing a baseline for revocation status tracking.
//
// Parameters:
//   - chain: The certificate chain to extract serial numbers from
//
// Returns:
//   - map[string]string: Map of serial number to revocation status, all initialized to "unknown"
//
// Thread Safety: Safe for concurrent use (no state modification).
func initializeStatusMap(chain *Chain) map[string]string {
	statusMap := make(map[string]string)
	for _, cert := range chain.Certs {
		statusMap[cert.SerialNumber.String()] = "unknown"
	}
	return statusMap
}

// extractCertificateIndex extracts the 0-based certificate index from a "Certificate X:" line.
//
// It parses lines from revocation status reports that follow the format "Certificate X:"
// where X is a 1-based certificate index. The function converts this to a 0-based index
// for array access.
//
// Parameters:
//   - line: The line of text to parse (expected format: "Certificate X:")
//
// Returns:
//   - int: 0-based certificate index if found and valid, -1 if parsing fails
//
// Thread Safety: Safe for concurrent use (no state modification).
func extractCertificateIndex(line string) int {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "Certificate ") || !strings.Contains(line, ":") {
		return -1
	}

	parts := strings.Split(line, ":")
	if len(parts) < 1 {
		return -1
	}

	certIndexStr := strings.TrimPrefix(parts[0], "Certificate ")
	var certIndex int
	if _, err := fmt.Sscanf(certIndexStr, "%d", &certIndex); err != nil {
		return -1
	}

	return certIndex - 1 // Convert to 0-based index
}

// findFinalStatus searches for the "Final Status:" line within the next few lines after a certificate index.
//
// It scans the revocation report lines starting from the given index to find a line
// containing "Final Status:" followed by the revocation status. The search is limited
// to the next 10 lines to prevent excessive scanning.
//
// Parameters:
//   - lines: The array of revocation report lines to search
//   - startIndex: The index in the lines array to start searching from
//
// Returns:
//   - string: The final status string if found (e.g., "Good", "Revoked"), empty string if not found
//
// Thread Safety: Safe for concurrent use (no state modification).
func findFinalStatus(lines []string, startIndex int) string {
	for j := startIndex + 1; j < len(lines) && j < startIndex+10; j++ {
		nextLine := strings.TrimSpace(lines[j])
		if after, ok := strings.CutPrefix(nextLine, "Final Status:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

// getCertificateStatusIcon determines the appropriate status icon for a certificate based on revocation status.
//
// It maps revocation status strings to visual indicators for display in certificate
// visualizations. The function prioritizes explicit revocation status from the map,
// with fallback logic for root CAs when status is unknown.
//
// Parameters:
//   - cert: The certificate to determine status icon for
//   - certIndex: The 0-based index of the certificate in the chain
//   - revocationMap: Map of serial numbers to revocation statuses
//   - chain: The certificate chain for role determination
//
// Returns:
//   - string: Status icon ("✓" for good, "✗" for revoked, "⚠" for unknown/error)
//
// Thread Safety: Safe for concurrent use (no state modification).
func getCertificateStatusIcon(cert *x509.Certificate, certIndex int, revocationMap map[string]string, chain *Chain) string {
	// Default to warning for unknown/error states
	statusIcon := "⚠"

	if status, exists := revocationMap[cert.SerialNumber.String()]; exists {
		switch {
		case strings.Contains(status, "Good"):
			statusIcon = "✓"
		case strings.Contains(status, "Revoked"):
			statusIcon = "✗"
		case strings.Contains(status, "Unknown"):
			statusIcon = "⚠"
		default:
			// For root CA certificates, assume good status if revocation check failed
			if chain.GetCertificateRole(certIndex) == "Root CA Certificate" {
				statusIcon = "✓"
			} else {
				statusIcon = "⚠"
			}
		}
	}

	return statusIcon
}

// RenderASCIITree renders the certificate chain as an ASCII tree diagram.
//
// It displays the certificate hierarchy with visual connectors showing the
// relationship between leaf, intermediate, and root certificates.
// Revocation status is automatically checked and displayed.
//
// Parameters:
//   - ctx: Context for revocation checking operations
//
// Returns:
//   - string: ASCII tree representation of the certificate chain
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) RenderASCIITree(ctx context.Context) string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if len(ch.Certs) == 0 {
		return "No certificates in chain"
	}

	// Get revocation status for all certificates
	revocationMap := make(map[string]string)
	revocationError := ""
	if revocationResult, err := ch.CheckRevocationStatus(ctx); err != nil {
		revocationError = fmt.Sprintf("Warning: Revocation status check failed: %v\n", err)
	} else {
		revocationMap = parseRevocationStatusForVisualization(revocationResult, ch)
	}

	var result strings.Builder
	if revocationError != "" {
		result.WriteString(revocationError)
	}
	for i, cert := range ch.Certs {
		isLast := i == len(ch.Certs)-1

		// Certificate icon and connector
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		// Status indicator - check revocation status for this certificate
		statusIcon := getCertificateStatusIcon(cert, i, revocationMap, ch)

		// Certificate info
		role := ch.GetCertificateRole(i)
		certInfo := fmt.Sprintf("[%s] %s", statusIcon, cert.Subject.CommonName)
		if role != "" {
			certInfo += fmt.Sprintf(" (%s)", role)
		}

		result.WriteString(connector + certInfo + "\n")
	}

	return result.String()
}

// RenderTable renders the certificate chain as a formatted markdown table.
//
// It displays certificate details including role, subject, issuer, validity dates,
// key size, and revocation status in a tabular format using tablewriter.
// Revocation status is automatically checked and displayed.
//
// Parameters:
//   - ctx: Context for revocation checking operations
//
// Returns:
//   - string: Markdown table representation of the certificate chain
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) RenderTable(ctx context.Context) string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if len(ch.Certs) == 0 {
		return "No certificates to display"
	}

	var buf strings.Builder

	// Get revocation status for all certificates
	revocationMap := make(map[string]string)
	revocationError := ""
	if revocationResult, err := ch.CheckRevocationStatus(ctx); err != nil {
		revocationError = fmt.Sprintf("Warning: Revocation status check failed: %v\n\n", err)
		buf.WriteString(revocationError)
	} else {
		revocationMap = parseRevocationStatusForVisualization(revocationResult, ch)
	}

	table := tablewriter.NewTable(&buf,
		tablewriter.WithRenderer(renderer.NewMarkdown(tw.Rendition{Streaming: true})),
	)

	// Headers with emojis
	headers := []string{"🔢 #", "🏷️ Role", "📛 Subject", "🏢 Issuer", "📅 Valid Until", "🔐 Key Size", "✅ Status"}
	table.Header(headers)

	// Prepare rows
	var rows [][]string
	for i, cert := range ch.Certs {
		role := ch.GetCertificateRole(i)
		status := "unknown"
		if s, exists := revocationMap[cert.SerialNumber.String()]; exists {
			status = s
		}

		// Format key size
		keySize := "unknown"
		if keyBits := ch.KeySize(cert); keyBits > 0 {
			switch cert.PublicKey.(type) {
			case *rsa.PublicKey:
				keySize = fmt.Sprintf("%d-bit RSA", keyBits)
			case *ecdsa.PublicKey:
				keySize = fmt.Sprintf("%d-bit ECDSA", keyBits)
			}
		}

		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1),
			role,
			cert.Subject.CommonName,
			cert.Issuer.CommonName,
			cert.NotAfter.Format("January 2, 2006 at 3:04 PM MST"),
			keySize,
			status,
		})
	}

	table.Bulk(rows)
	table.Render()
	return buf.String()
}

// ToVisualizationJSON converts the certificate chain to structured JSON for external tools.
//
// It creates a comprehensive data structure including certificate details,
// hierarchical relationships, and revocation status suitable for visualization
// tools or programmatic processing. Revocation status is automatically checked.
//
// Parameters:
//   - ctx: Context for revocation checking operations
//
// Returns:
//   - []byte: JSON representation of the certificate chain
//   - error: Error if JSON marshaling fails
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) ToVisualizationJSON(ctx context.Context) ([]byte, error) {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	type CertificateVizData struct {
		Index              int       `json:"index"`
		Role               string    `json:"role"`
		Subject            string    `json:"subject"`
		Issuer             string    `json:"issuer"`
		SerialNumber       string    `json:"serialNumber"`
		SignatureAlgorithm string    `json:"signatureAlgorithm"`
		PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
		KeySize            int       `json:"keySize"`
		NotBefore          time.Time `json:"notBefore"`
		NotAfter           time.Time `json:"notAfter"`
		IsCA               bool      `json:"isCA"`
		RevocationStatus   string    `json:"revocationStatus"`
	}

	type RelationshipData struct {
		FromIndex int    `json:"fromIndex"`
		ToIndex   int    `json:"toIndex"`
		Type      string `json:"type"`
	}

	type VisualizationData struct {
		Timestamp         string               `json:"timestamp"`
		ChainLength       int                  `json:"chainLength"`
		Certificates      []CertificateVizData `json:"certificates"`
		Relationships     []RelationshipData   `json:"relationships"`
		RevocationWarning string               `json:"revocationWarning,omitempty"`
	}

	// Get revocation status for all certificates
	revocationMap := make(map[string]string)
	var revocationWarning string
	if revocationResult, err := ch.CheckRevocationStatus(ctx); err != nil {
		revocationWarning = fmt.Sprintf("Revocation status check failed: %v", err)
	} else {
		revocationMap = parseRevocationStatusForVisualization(revocationResult, ch)
	}

	data := VisualizationData{
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		ChainLength:       len(ch.Certs),
		Certificates:      make([]CertificateVizData, len(ch.Certs)),
		Relationships:     make([]RelationshipData, 0, len(ch.Certs)-1),
		RevocationWarning: revocationWarning,
	}

	// Convert certificates
	for i, cert := range ch.Certs {
		keySize := ch.KeySize(cert)
		pubKeyAlgo := "unknown"

		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
			pubKeyAlgo = "RSA"
		case *ecdsa.PublicKey:
			pubKeyAlgo = "ECDSA"
		}

		status := "unknown"
		if s, exists := revocationMap[cert.SerialNumber.String()]; exists {
			status = s
		}

		data.Certificates[i] = CertificateVizData{
			Index:              i,
			Role:               ch.GetCertificateRole(i),
			Subject:            cert.Subject.CommonName,
			Issuer:             cert.Issuer.CommonName,
			SerialNumber:       cert.SerialNumber.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PublicKeyAlgorithm: pubKeyAlgo,
			KeySize:            keySize,
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			IsCA:               cert.IsCA,
			RevocationStatus:   status,
		}
	}

	// Build relationships (each cert is signed by the next one in chain)
	for i := 0; i < len(ch.Certs)-1; i++ {
		data.Relationships = append(data.Relationships, RelationshipData{
			FromIndex: i,
			ToIndex:   i + 1,
			Type:      "signed_by",
		})
	}

	return json.MarshalIndent(data, "", "  ")
}
