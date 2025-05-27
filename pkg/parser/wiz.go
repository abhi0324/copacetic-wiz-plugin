package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/project-copacetic/wiz-scanner-plugin/pkg/types"
)

// WizVulnerability represents a vulnerability in Wiz scan report
type WizVulnerability struct {
	ID          string    `json:"id"`
	Package     string    `json:"package"`
	Version     string    `json:"version"`
	FixedIn     string    `json:"fixedIn"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	CVSS        float64   `json:"cvss"`
	Published   time.Time `json:"published"`
	References  []string  `json:"references"`
}

// WizScanReport represents the structure of a Wiz scan report
type WizScanReport struct {
	ImageID         string             `json:"imageId"`
	ScanTime        time.Time          `json:"scanTime"`
	Vulnerabilities []WizVulnerability `json:"vulnerabilities"`
	OS              struct {
		Type    string `json:"type"`
		Version string `json:"version"`
	} `json:"os"`
	Architecture string `json:"architecture"`
}

// WizParser implements the parser for Wiz scan reports
type WizParser struct {
	severityThreshold string
}

// ParserOption defines options for configuring the WizParser
type ParserOption func(*WizParser)

// WithSeverityThreshold sets the minimum severity level for vulnerabilities
func WithSeverityThreshold(severity string) ParserOption {
	return func(p *WizParser) {
		p.severityThreshold = severity
	}
}

// NewWizParser creates a new instance of WizParser with optional configuration
func NewWizParser(opts ...ParserOption) *WizParser {
	parser := &WizParser{
		severityThreshold: "LOW", // Default to include all severities
	}
	for _, opt := range opts {
		opt(parser)
	}
	return parser
}

// severityToWeight converts severity string to numeric weight for comparison
func severityToWeight(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// shouldIncludeVulnerability checks if a vulnerability should be included based on severity threshold
func (w *WizParser) shouldIncludeVulnerability(vuln WizVulnerability) bool {
	return severityToWeight(vuln.Severity) >= severityToWeight(w.severityThreshold)
}

// Parse reads and parses a Wiz scan report file
func (w *WizParser) Parse(file string) (*types.UpdateManifest, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file: %w", err)
	}

	var wizReport WizScanReport
	if err := json.Unmarshal(data, &wizReport); err != nil {
		return nil, fmt.Errorf("failed to parse Wiz report: %w", err)
	}

	manifest := &types.UpdateManifest{
		Metadata: types.Metadata{
			OS: types.OS{
				Type:    wizReport.OS.Type,
				Version: wizReport.OS.Version,
			},
			Config: types.Config{
				Arch: wizReport.Architecture,
			},
		},
		Updates: make([]types.UpdatePackage, 0),
	}

	for _, vuln := range wizReport.Vulnerabilities {
		if vuln.FixedIn != "" && w.shouldIncludeVulnerability(vuln) {
			manifest.Updates = append(manifest.Updates, types.UpdatePackage{
				Name:             vuln.Package,
				InstalledVersion: vuln.Version,
				FixedVersion:     vuln.FixedIn,
				VulnerabilityID:  vuln.ID,
			})
		}
	}

	return manifest, nil
}

// ValidateReport performs basic validation of the Wiz scan report
func (w *WizParser) ValidateReport(report *WizScanReport) error {
	if report.ImageID == "" {
		return fmt.Errorf("missing image ID in report")
	}
	if len(report.Vulnerabilities) == 0 {
		return fmt.Errorf("no vulnerabilities found in report")
	}
	return nil
}
