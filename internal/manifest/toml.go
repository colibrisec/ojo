package manifest

import (
	"os"

	"github.com/pelletier/go-toml/v2"

	"github.com/colibrisec/ojo/internal/model"
)

// tomlPackageList is the shared shape of Cargo.lock and poetry.lock: a flat
// list of [[package]] tables, each with a name and version.
type tomlPackageList struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
}

func parseTomlPackages(path string, eco model.Ecosystem) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock tomlPackageList
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	pkgs := make([]model.Package, 0, len(lock.Package))
	for _, p := range lock.Package {
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, model.Package{Name: p.Name, Version: p.Version, Ecosystem: eco, Source: path})
	}
	return pkgs, nil
}
