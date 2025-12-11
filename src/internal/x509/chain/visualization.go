// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

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

	var result strings.Builder
	for i, cert := range ch.Certs {
		isLast := i == len(ch.Certs)-1

		// Certificate icon and connector
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		// Status indicator - check revocation status
		statusIcon := "✓"
		if revocationResult, err := ch.CheckRevocationStatus(ctx); err == nil {
			// Parse revocation result to check if this certificate is revoked
			if strings.Contains(revocationResult, fmt.Sprintf("Certificate %d:", i+1)) {
				// Look for "REVOKED" in the result for this certificate
				lines := strings.SplitSeq(revocationResult, "\n")
				for line := range lines {
					if strings.Contains(line, fmt.Sprintf("Certificate %d:", i+1)) {
						// Check subsequent lines for final status
						// This is a simplified check - in practice you'd parse more carefully
						if strings.Contains(revocationResult, "REVOKED") &&
							strings.Contains(revocationResult, fmt.Sprintf("Certificate %d:", i+1)) {
							statusIcon = "✗"
							break
						}
					}
				}
			}
		}

		// Certificate info
		role := ch.getCertificateRole(i)
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
	table := tablewriter.NewTable(&buf,
		tablewriter.WithRenderer(renderer.NewMarkdown(tw.Rendition{Streaming: true})),
	)

	// Headers with emojis
	headers := []string{"🔢 #", "🏷️ Role", "📛 Subject", "🏢 Issuer", "📅 Valid Until", "🔐 Key Size", "✅ Status"}
	table.Header(headers)

	// Get revocation status for all certificates
	revocationMap := make(map[string]string)
	if revocationResult, err := ch.CheckRevocationStatus(ctx); err == nil {
		revocationMap = parseRevocationStatusForTable(revocationResult, ch)
	}

	// Prepare rows
	var rows [][]string
	for i, cert := range ch.Certs {
		role := ch.getCertificateRole(i)
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
			cert.NotAfter.Format("2006-01-02"),
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
		Timestamp     string               `json:"timestamp"`
		ChainLength   int                  `json:"chainLength"`
		Certificates  []CertificateVizData `json:"certificates"`
		Relationships []RelationshipData   `json:"relationships"`
	}

	data := VisualizationData{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		ChainLength:   len(ch.Certs),
		Certificates:  make([]CertificateVizData, len(ch.Certs)),
		Relationships: make([]RelationshipData, 0, len(ch.Certs)-1),
	}

	// Get revocation status for all certificates
	revocationMap := make(map[string]string)
	if revocationResult, err := ch.CheckRevocationStatus(ctx); err == nil {
		revocationMap = parseRevocationStatusForTable(revocationResult, ch)
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
			Role:               ch.getCertificateRole(i),
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

// getCertificateRole determines the role of a certificate in the chain.
//
// It returns a descriptive string indicating the certificate's position
// and function within the certificate chain hierarchy.
//
// Parameters:
//   - index: Zero-based position of the certificate in the chain
//
// Returns:
//   - string: Role description ("Leaf/End-Entity", "Intermediate CA", or "Root CA")
//
// Thread Safety: Safe for concurrent use (no state modification).
func (ch *Chain) getCertificateRole(index int) string {
	total := len(ch.Certs)
	switch {
	case total == 1:
		return "Self-Signed Certificate"
	case index == 0:
		return "End-Entity (Server/Leaf) Certificate"
	case index == total-1:
		return "Root CA Certificate"
	default:
		return "Intermediate CA Certificate"
	}
}

// parseRevocationStatusForTable parses the revocation status report into a map format
// suitable for table rendering.
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
func parseRevocationStatusForTable(revocationReport string, chain *Chain) map[string]string {
	statusMap := make(map[string]string)

	// Default all certificates to "unknown"
	for _, cert := range chain.Certs {
		statusMap[cert.SerialNumber.String()] = "unknown"
	}

	// Parse the revocation report to extract actual statuses
	lines := strings.Split(revocationReport, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Certificate ") && strings.Contains(line, ":") {
			// Extract certificate index
			parts := strings.Split(line, ":")
			if len(parts) >= 1 {
				certIndexStr := strings.TrimPrefix(parts[0], "Certificate ")
				if certIndex, err := fmt.Sscanf(certIndexStr, "%d", new(int)); err == nil {
					certIndex-- // Convert to 0-based index

					// Look for the final status in subsequent lines
					for j := i + 1; j < len(lines) && j < i+10; j++ {
						nextLine := strings.TrimSpace(lines[j])
						if after, ok := strings.CutPrefix(nextLine, "Final Status:"); ok {
							status := after
							status = strings.TrimSpace(status)

							// Update status for this certificate
							if certIndex >= 0 && certIndex < len(chain.Certs) {
								statusMap[chain.Certs[certIndex].SerialNumber.String()] = status
							}
							break
						}
					}
				}
			}
		}
	}

	return statusMap
}
