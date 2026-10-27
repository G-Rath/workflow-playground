package main

// Minimal stand-ins for the parts of pkg/models that githubannotation.go uses.

type SourceInfo struct {
	Path string
}

type PackageInfo struct {
	Name       string
	Version    string
	Deprecated bool
}

type GroupInfo struct {
	IDs         []string
	MaxSeverity string
	// FixedVersions replaces the groupFixedVersions lookup, which is computed
	// from the full vulnerability data in the real implementation
	FixedVersions []string
}

type PackageVulns struct {
	Package PackageInfo
	Groups  []GroupInfo
}

type PackageSource struct {
	Source   SourceInfo
	Packages []PackageVulns
}

type VulnerabilityResults struct {
	Results []PackageSource
}
