package manifest

import "github.com/colibrisec/ojo/internal/model"

type cargoLockParser struct{}

func (cargoLockParser) Match(name string) bool { return name == "Cargo.lock" }

func (cargoLockParser) Parse(path string) ([]model.Package, error) {
	return parseTomlPackages(path, model.EcosystemCratesIO)
}
