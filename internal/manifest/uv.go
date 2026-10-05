package manifest

import "github.com/colibrisec/ojo/internal/model"

type uvLockParser struct{}

func (uvLockParser) Match(name string) bool { return name == "uv.lock" }

func (uvLockParser) Parse(path string) ([]model.Package, error) {
	return parseTomlPackages(path, model.EcosystemPyPI)
}

type pdmLockParser struct{}

func (pdmLockParser) Match(name string) bool { return name == "pdm.lock" }

func (pdmLockParser) Parse(path string) ([]model.Package, error) {
	return parseTomlPackages(path, model.EcosystemPyPI)
}
