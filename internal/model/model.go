// Package model holds the core types shared across scan engines and reporters.
package model

// Ecosystem identifies a package ecosystem in OSV.dev terms.
type Ecosystem string

const (
	EcosystemGo        Ecosystem = "Go"
	EcosystemNpm       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "PyPI"
	EcosystemMaven     Ecosystem = "Maven"
	EcosystemPackagist Ecosystem = "Packagist"
	EcosystemNuGet     Ecosystem = "NuGet"
	EcosystemPub       Ecosystem = "Pub"
	EcosystemCratesIO  Ecosystem = "crates.io"
	EcosystemRubyGems  Ecosystem = "RubyGems"
	EcosystemSwiftURL  Ecosystem = "SwiftURL"
)

// Package is a dependency found in a manifest or lockfile.
type Package struct {
	Name      string
	Version   string
	Ecosystem Ecosystem
	Source    string // manifest file it was found in
}

// Vulnerability is a single OSV advisory affecting a package.
type Vulnerability struct {
	ID           string
	Summary      string
	Severity     string // CRITICAL/HIGH/MODERATE/LOW/UNKNOWN
	CVSSVector   string // raw CVSS vector string, if OSV provided one
	FixedVersion string // nearest version above the installed one that fixes this, if known
	Aliases      []string
	URL          string
}

// Finding pairs a package with the vulnerabilities affecting it.
type Finding struct {
	Package Package
	Vulns   []Vulnerability
}

// Issue is a single finding from a non-SCA scanner (secret, misconfig, sast).
// Severity here is a scanner-assigned label (CRITICAL/HIGH/MEDIUM/LOW/INFO),
// distinct from Vulnerability.Severity which holds a raw OSV/CVSS string.
type Issue struct {
	Scanner  string // "secret" | "misconfig" | "sast"
	RuleID   string
	Title    string
	Severity string
	File     string
	Line     int
	Match    string // short, possibly-redacted snippet
	Message  string
}
