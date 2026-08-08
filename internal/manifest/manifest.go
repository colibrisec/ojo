// Package manifest discovers and parses dependency manifests/lockfiles into model.Package lists.
package manifest

import (
	"io/fs"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

type Parser interface {
	Match(name string) bool
	Parse(path string) ([]model.Package, error)
}

var parsers = []Parser{
	goModParser{},
	npmLockParser{},
	pipRequirementsParser{},
	composerLockParser{},
	pipfileLockParser{},
	nugetLockParser{},
	pubspecLockParser{},
	cargoLockParser{},
	poetryLockParser{},
	gemfileLockParser{},
	gradleLockParser{},
	mavenPomParser{},
	swiftPackageResolvedParser{},
}

func Discover(root string) ([]model.Package, error) {
	var pkgs []model.Package
	seen := map[model.Package]bool{}
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		for _, p := range parsers {
			if p.Match(d.Name()) {
				found, perr := p.Parse(path)
				if perr != nil {
					continue // ponytail: skip unparsable manifest, don't fail the whole scan
				}
				for _, pkg := range found {
					dedupeKey := pkg
					dedupeKey.Source = "" // same package via a different file is still a duplicate
					if seen[dedupeKey] {
						continue
					}
					seen[dedupeKey] = true
					pkgs = append(pkgs, pkg)
				}
			}
		}
		return nil
	})
	return pkgs, err
}
