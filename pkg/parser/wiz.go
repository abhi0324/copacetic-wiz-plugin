package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/abhi0324/copacetic-wiz-plugin/pkg/types"
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

// WizParser implements the parser interface for Wiz scan reports
type WizParser struct{}

// NewWizParser creates a new WizParser instance
func NewWizParser() *WizParser {
	return &WizParser{}
}

// Parse converts a Wiz scan report into Copacetic's update manifest format
func (p *WizParser) Parse(reportPath string) (*types.UpdateManifest, error) {
	// Read the report file
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("error reading report file: %w", err)
	}

	// Parse the JSON report
	var report WizScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("error parsing report JSON: %w", err)
	}

	// Validate the report
	if report.ImageID == "" || len(report.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("invalid or incomplete Wiz report")
	}

	// Create the update manifest
	manifest := &types.UpdateManifest{
		Metadata: types.Metadata{
			OS: types.OS{
				Type:    report.OS.Type,
				Version: report.OS.Version,
			},
			Config: types.Config{
				Architecture: report.Architecture,
			},
		},
		Updates: make([]types.UpdatePackage, 0),
	}

	// Convert vulnerabilities to update packages
	for _, vuln := range report.Vulnerabilities {
		update := types.UpdatePackage{
			Name:             vuln.Package,
			InstalledVersion: vuln.Version,
			FixedVersion:     vuln.FixedIn,
			VulnerabilityID:  vuln.ID,
		}
		manifest.Updates = append(manifest.Updates, update)
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
