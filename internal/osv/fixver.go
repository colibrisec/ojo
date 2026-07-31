package osv

import (
	"regexp"
	"strconv"

	"github.com/colibrisec/ojo/internal/model"
)

// resolveFixedVersion finds the nearest version above pkg's installed
// version that fixes d, by matching d's affected ranges for pkg's
// name+ecosystem and scanning their "fixed" events.
//
// ponytail: uses a generic token-wise version comparator (see
// versionCompare below), not each ecosystem's canonical algorithm (dpkg's
// epoch/tilde rules, semver, PEP440, ...). Good enough to pick a sane
// display value; not a substitute for a real per-ecosystem version range
// check if this is ever used to gate automated remediation.
func resolveFixedVersion(d vulnDetail, pkg model.Package) string {
	var best string
	for _, aff := range d.Affected {
		if aff.Package.Name != pkg.Name || aff.Package.Ecosystem != string(pkg.Ecosystem) {
			continue
		}
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed == "" || versionCompare(ev.Fixed, pkg.Version) <= 0 {
					continue // not actually newer than what's installed
				}
				if best == "" || versionCompare(ev.Fixed, best) < 0 {
					best = ev.Fixed // closest fix version above the installed one
				}
			}
		}
	}
	return best
}

var versionTokenRe = regexp.MustCompile(`\d+|\D+`)

// versionCompare does a generic token-wise comparison of two version
// strings: alternating digit/non-digit runs are compared numerically or
// lexically as appropriate. Returns <0, 0, >0 like strings.Compare.
func versionCompare(a, b string) int {
	at := versionTokenRe.FindAllString(a, -1)
	bt := versionTokenRe.FindAllString(b, -1)
	for i := 0; i < len(at) || i < len(bt); i++ {
		var ta, tb string
		if i < len(at) {
			ta = at[i]
		}
		if i < len(bt) {
			tb = bt[i]
		}
		if ta == tb {
			continue
		}
		na, aErr := strconv.Atoi(ta)
		nb, bErr := strconv.Atoi(tb)
		if aErr == nil && bErr == nil {
			if na != nb {
				return na - nb
			}
			continue
		}
		if ta < tb {
			return -1
		}
		return 1
	}
	return 0
}
