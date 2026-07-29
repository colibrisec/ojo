package manifest

import (
	"os"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/colibrisec/ojo/internal/model"
)

type goModParser struct{}

func (goModParser) Match(name string) bool { return name == "go.mod" }

func (goModParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0, len(f.Require))
	for _, req := range f.Require {
		pkgs = append(pkgs, model.Package{
			Name:      req.Mod.Path,
			Version:   strings.TrimPrefix(req.Mod.Version, "v"),
			Ecosystem: model.EcosystemGo,
			Source:    path,
		})
	}
	return pkgs, nil
}
