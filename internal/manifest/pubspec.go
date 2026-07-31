package manifest

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/colibrisec/ojo/internal/model"
)

type pubspecLockParser struct{}

func (pubspecLockParser) Match(name string) bool { return name == "pubspec.lock" }

type pubspecLockFile struct {
	Packages map[string]struct {
		Version string `yaml:"version"`
	} `yaml:"packages"`
}

func (pubspecLockParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock pubspecLockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	pkgs := make([]model.Package, 0, len(lock.Packages))
	for name, p := range lock.Packages {
		if p.Version == "" {
			continue
		}
		pkgs = append(pkgs, model.Package{Name: name, Version: p.Version, Ecosystem: model.EcosystemPub, Source: path})
	}
	return pkgs, nil
}
