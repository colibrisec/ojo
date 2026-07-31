package manifest

import (
	"encoding/json"
	"os"

	"github.com/colibrisec/ojo/internal/model"
)

type composerLockParser struct{}

func (composerLockParser) Match(name string) bool { return name == "composer.lock" }

type composerLockFile struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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
		})
	}
	return pkgs, nil
}

// trimVersionPrefix strips a leading "v" (composer.lock versions are
// frequently "v1.2.3"), which OSV's Packagist ecosystem doesn't expect.
func trimVersionPrefix(v string) string {
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}
