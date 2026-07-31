package manifest

import "github.com/colibrisec/ojo/internal/model"

type poetryLockParser struct{}

func (poetryLockParser) Match(name string) bool { return name == "poetry.lock" }

func (poetryLockParser) Parse(path string) ([]model.Package, error) {
	return parseTomlPackages(path, model.EcosystemPyPI)
}
