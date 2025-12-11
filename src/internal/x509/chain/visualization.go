// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package x509chain

import (
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
//
// Parameters:
//   - revocationStatus: Optional map of certificate serial numbers to revocation status
//
// Returns:
//   - string: ASCII tree representation of the certificate chain
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) RenderASCIITree(revocationStatus map[string]string) string {
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

		// Status indicator
		statusIcon := "✓"
		if revocationStatus != nil {
			if status, exists := revocationStatus[cert.SerialNumber.String()]; exists && status != "good" && status != "Good" {
				statusIcon = "✗"
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
//
// Parameters:
//   - revocationStatus: Optional map of certificate serial numbers to revocation status
//
// Returns:
//   - string: Markdown table representation of the certificate chain
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) RenderTable(revocationStatus map[string]string) string {
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

	// Prepare rows
	var rows [][]string
	for i, cert := range ch.Certs {
		role := ch.getCertificateRole(i)
		status := "unknown"
		if revocationStatus != nil {
			if s, exists := revocationStatus[cert.SerialNumber.String()]; exists {
				status = s
			}
		}

		// Format key size
		keySize := "unknown"
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keySize = fmt.Sprintf("%d-bit RSA", rsaKey.Size()*8)
		} else if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			keySize = fmt.Sprintf("%d-bit ECDSA", ecdsaKey.Curve.Params().BitSize)
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
// tools or programmatic processing.
//
// Parameters:
//   - revocationStatus: Optional map of certificate serial numbers to revocation status
//
// Returns:
//   - []byte: JSON representation of the certificate chain
//   - error: Error if JSON marshaling fails
//
// Thread Safety: Safe for concurrent use.
func (ch *Chain) ToVisualizationJSON(revocationStatus map[string]string) ([]byte, error) {
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

	// Convert certificates
	for i, cert := range ch.Certs {
		keySize := 0
		pubKeyAlgo := "unknown"

		switch pubKey := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			keySize = pubKey.Size() * 8
			pubKeyAlgo = "RSA"
		case *ecdsa.PublicKey:
			keySize = pubKey.Curve.Params().BitSize
			pubKeyAlgo = "ECDSA"
		}

		status := "unknown"
		if revocationStatus != nil {
			if s, exists := revocationStatus[cert.SerialNumber.String()]; exists {
				status = s
			}
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
