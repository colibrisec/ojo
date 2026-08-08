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

type Package struct {
	Name      string
	Version   string
	Ecosystem Ecosystem
	Source    string // manifest file it was found in
}

type Vulnerability struct {
	ID           string
	Summary      string
	Severity     string
	CVSSVector   string
	FixedVersion string
	Aliases      []string
	URL          string
}

type Finding struct {
	Package Package
	Vulns   []Vulnerability
}

type Issue struct {
	Scanner  string
	RuleID   string
	Title    string
	Severity string
	File     string
	Line     int
	Match    string
	Message  string
}
