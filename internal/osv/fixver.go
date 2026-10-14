package osv

import (
	"slices"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/version"
)

func resolveFixedVersion(d vulnDetail, pkg model.Package) string {
	var best string
	targets := queryTargets(pkg)
	for _, aff := range d.Affected {
		if !slices.Contains(targets, target{aff.Package.Name, aff.Package.Ecosystem}) {
			continue
		}
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed == "" || version.Compare(aff.Package.Ecosystem, ev.Fixed, pkg.Version) <= 0 {
					continue // not actually newer than what's installed
				}
				if best == "" || version.Compare(aff.Package.Ecosystem, ev.Fixed, best) < 0 {
					best = ev.Fixed // closest fix version above the installed one
				}
			}
		}
	}
	return best
}
