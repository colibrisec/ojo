package manifest

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type npmLockParser struct{}

func (npmLockParser) Match(name string) bool { return name == "package-lock.json" }

type npmLockFile struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"` // npm lockfile v2/v3
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"` // npm lockfile v1
}

func (npmLockParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var pkgs []model.Package
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			if key == "" || p.Version == "" {
				continue // root package entry has no name
			}
			idx := strings.LastIndex(key, "node_modules/")
			if idx < 0 {
				continue // local workspace member (e.g. "packages/ui"), not a resolvable npm-registry package
			}
			name := key[idx+len("node_modules/"):]
			pkgs = append(pkgs, model.Package{
				Name: name, Version: p.Version, Ecosystem: model.EcosystemNpm, Source: path,
			})
		}
		return pkgs, nil
	}
	for name, d := range lock.Dependencies {
		pkgs = append(pkgs, model.Package{
			Name: name, Version: d.Version, Ecosystem: model.EcosystemNpm, Source: path,
		})
	}
	return pkgs, nil
}
