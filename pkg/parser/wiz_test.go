package parser

import (
	"os"
	"testing"

	"github.com/abhi0324/copacetic-wiz-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWizParser_Parse(t *testing.T) {
	tests := []struct {
		name           string
		reportData     string
		expectedCount  int
		expectedError  bool
		validateResult func(t *testing.T, manifest *types.UpdateManifest)
	}{
		{
			name: "valid report with high severity",
			reportData: `{
				"imageId": "test-image:latest",
				"scanTime": "2024-03-20T10:00:00Z",
				"os": {
					"type": "alpine",
					"version": "3.14.0"
				},
				"architecture": "amd64",
				"vulnerabilities": [
					{
						"id": "CVE-2024-1234",
						"package": "openssl",
						"version": "1.1.1k",
						"fixedIn": "1.1.1l",
						"severity": "HIGH",
						"description": "Test vulnerability",
						"cvss": 8.5,
						"published": "2024-03-20T00:00:00Z",
						"references": ["https://example.com/cve-2024-1234"]
					}
				]
			}`,
			expectedCount: 1,
			expectedError: false,
			validateResult: func(t *testing.T, manifest *types.UpdateManifest) {
				assert.Equal(t, "alpine", manifest.Metadata.OS.Type)
				assert.Equal(t, "3.14.0", manifest.Metadata.OS.Version)
				assert.Equal(t, "amd64", manifest.Metadata.Config.Architecture)
			},
		},
		{
			name:          "invalid report format",
			reportData:    `{"invalid": "format"}`,
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary test file
			tmpFile, err := os.CreateTemp("", "wiz-test-*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.Write([]byte(tt.reportData))
			require.NoError(t, err)
			tmpFile.Close()

			// Create parser
			parser := NewWizParser()

			// Parse the report
			manifest, err := parser.Parse(tmpFile.Name())

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, manifest)
			assert.Len(t, manifest.Updates, tt.expectedCount)

			if tt.validateResult != nil {
				tt.validateResult(t, manifest)
			}
		})
	}
}

func TestValidateReport(t *testing.T) {
	parser := NewWizParser()

	tests := []struct {
		name        string
		report      *WizScanReport
		expectError bool
	}{
		{
			name: "valid report",
			report: &WizScanReport{
				ImageID: "test-image:latest",
				Vulnerabilities: []WizVulnerability{
					{
						ID: "CVE-2024-1234",
					},
				},
			},
			expectError: false,
		},
		{
			name: "missing image ID",
			report: &WizScanReport{
				Vulnerabilities: []WizVulnerability{
					{
						ID: "CVE-2024-1234",
					},
				},
			},
			expectError: true,
		},
		{
			name: "no vulnerabilities",
			report: &WizScanReport{
				ImageID: "test-image:latest",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.ValidateReport(tt.report)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
