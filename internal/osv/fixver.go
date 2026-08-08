package osv

import (
	"regexp"
	"strconv"

	"github.com/colibrisec/ojo/internal/model"
)

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
