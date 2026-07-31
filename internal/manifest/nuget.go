package manifest

import (
	"encoding/json"
	"os"

	"github.com/colibrisec/ojo/internal/model"
)

type nugetLockParser struct{}

func (nugetLockParser) Match(name string) bool { return name == "packages.lock.json" }

type nugetLockFile struct {
	// keyed by target framework (e.g. "net6.0"), each mapping package name to its entry
	Dependencies map[string]map[string]struct {
		Resolved string `json:"resolved"`
	} `json:"dependencies"`
}

func (nugetLockParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock nugetLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	seen := map[string]bool{} // dedupe the same (name, version) seen under multiple target frameworks
	var pkgs []model.Package
	for _, framework := range lock.Dependencies {
		for name, entry := range framework {
			if entry.Resolved == "" {
				continue
			}
			key := name + "@" + entry.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true
			pkgs = append(pkgs, model.Package{
				Name: name, Version: entry.Resolved, Ecosystem: model.EcosystemNuGet, Source: path,
			})
		}
	}
	return pkgs, nil
}
