package manifest

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type composerLockParser struct{}

func (composerLockParser) Match(name string) bool { return name == "composer.lock" }

type composerLockFile struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License []string `json:"license"`
}

func (composerLockParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock composerLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	pkgs := make([]model.Package, 0, len(lock.Packages)+len(lock.PackagesDev))
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, model.Package{
			Name: p.Name, Version: trimVersionPrefix(p.Version), Ecosystem: model.EcosystemPackagist, Source: path,
			License: composerLicense(p.License),
		})
	}
	return pkgs, nil
}

// composerLicense turns a lockfile's license list into one SPDX expression.
// Composer records SPDX identifiers, and more than one means the package is
// offered under any of them -- a choice, so "OR".
func composerLicense(licenses []string) string {
	var parts []string
	for _, l := range licenses {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		parts = append(parts, l)
	}
	if len(parts) > 1 {
		for i, l := range parts {
			if strings.Contains(l, " ") {
				parts[i] = "(" + l + ")"
			}
		}
	}
	return strings.Join(parts, " OR ")
}

func trimVersionPrefix(v string) string {
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}
