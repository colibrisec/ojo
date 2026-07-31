package manifest

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type pipfileLockParser struct{}

func (pipfileLockParser) Match(name string) bool { return name == "Pipfile.lock" }

type pipfileLockFile struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"` // typically "==1.2.3"
}

func (pipfileLockParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock pipfileLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	pkgs := make([]model.Package, 0, len(lock.Default)+len(lock.Develop))
	for name, e := range lock.Default {
		if p, ok := pipfilePackage(name, e, path); ok {
			pkgs = append(pkgs, p)
		}
	}
	for name, e := range lock.Develop {
		if p, ok := pipfilePackage(name, e, path); ok {
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, nil
}

// pipfilePackage returns ok=false for git/path dependencies, which have no
// pinned "==version" entry to report.
func pipfilePackage(name string, e pipfileEntry, path string) (model.Package, bool) {
	if !strings.HasPrefix(e.Version, "==") {
		return model.Package{}, false
	}
	version := strings.TrimPrefix(e.Version, "==")
	return model.Package{Name: name, Version: version, Ecosystem: model.EcosystemPyPI, Source: path}, true
}
