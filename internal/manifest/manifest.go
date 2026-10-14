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
	uvLockParser{},
	pdmLockParser{},
	yarnLockParser{},
	pnpmLockParser{},
	podfileLockParser{},
}

// Unscannable is a declared dependency with no exact version to check.
type Unscannable struct {
	Name   string
	Source string
	Reason string
}

type partialParser interface {
	ParsePartial(path string) ([]model.Package, []Unscannable, error)
}

func Discover(root string) ([]model.Package, error) {
	pkgs, _, err := DiscoverAll(root)
	return pkgs, err
}

// DiscoverAll is Discover plus the dependencies that couldn't be pinned.
func DiscoverAll(root string) ([]model.Package, []Unscannable, error) {
	var pkgs []model.Package
	var skipped []Unscannable
	seen := map[model.Package]bool{}
	seenSkipped := map[Unscannable]bool{}
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		for _, p := range parsers {
			if p.Match(d.Name()) {
				var found []model.Package
				var unpinned []Unscannable
				var perr error
				if pp, ok := p.(partialParser); ok {
					found, unpinned, perr = pp.ParsePartial(path)
				} else {
					found, perr = p.Parse(path)
				}
				if perr != nil {
					continue // ponytail: skip unparsable manifest, don't fail the whole scan
				}
				for _, u := range unpinned {
					if !seenSkipped[u] {
						seenSkipped[u] = true
						skipped = append(skipped, u)
					}
				}
				for _, pkg := range found {
					// Deduped per file only: the same package in two files
					// (requirements.txt and uv.lock, or two lockfiles in a
					// monorepo) is two places to fix, and each is reported.
					dedupeKey := pkg
					dedupeKey.License = ""
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
	return pkgs, skipped, err
}
