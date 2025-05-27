package types

// UpdatePackage represents a package that needs to be updated
type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
}

// UpdatePackages is a slice of UpdatePackage
type UpdatePackages []UpdatePackage

// UpdateManifest represents the update manifest
type UpdateManifest struct {
	Metadata Metadata       `json:"metadata"`
	Updates  UpdatePackages `json:"updates"`
}

// Metadata contains metadata about the update
type Metadata struct {
	OS     OS     `json:"os"`
	Config Config `json:"config"`
}

// OS represents operating system information
type OS struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

// Config represents configuration information
type Config struct {
	Architecture string `json:"architecture"`
}
