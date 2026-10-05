package manifest

import (
	"os"

	"github.com/pelletier/go-toml/v2"

	"github.com/colibrisec/ojo/internal/model"
)

type tomlPackageList struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  any    `toml:"source"` // a table in uv.lock/poetry.lock, a plain string in Cargo.lock
	} `toml:"package"`
}

// localTomlSources are the uv.lock source kinds that mark a [[package]]
// entry as the project itself or a workspace/path member rather than a
// published package -- there is nothing to look up for those.
var localTomlSources = []string{"virtual", "editable", "directory", "path"}

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
		if p.Name == "" || p.Version == "" || isLocalTomlSource(p.Source) {
			continue
		}
		pkgs = append(pkgs, model.Package{Name: p.Name, Version: p.Version, Ecosystem: eco, Source: path})
	}
	return pkgs, nil
}

func isLocalTomlSource(source any) bool {
	table, ok := source.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range localTomlSources {
		if _, ok := table[k]; ok {
			return true
		}
	}
	return false
}
