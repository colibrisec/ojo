package version

import (
	"strings"

	"golang.org/x/mod/semver"
)

// Semver orders SemVer 2.0 versions, allowing a leading "v" and any number
// of release parts (missing parts count as 0).
func Semver(a, b string) int {
	ar, ap := splitSemver(a)
	br, bp := splitSemver(b)
	ap1, bp1 := strings.Split(ar, "."), strings.Split(br, ".")
	for i := 0; i < len(ap1) || i < len(bp1); i++ {
		x, y := "0", "0"
		if i < len(ap1) {
			x = ap1[i]
		}
		if i < len(bp1) {
			y = bp1[i]
		}
		if !isNumber(x) || !isNumber(y) {
			return Generic(a, b)
		}
		if c := compareNumbers(x, y); c != 0 {
			return c
		}
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return comparePrerelease(ap, bp)
}

func splitSemver(s string) (release, prerelease string) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "+")
	release, prerelease, _ = strings.Cut(s, "-")
	return release, prerelease
}

func comparePrerelease(a, b string) int {
	at, bt := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(at) && i < len(bt); i++ {
		x, y := at[i], bt[i]
		xn, yn := isNumber(x), isNumber(y)
		switch {
		case xn && yn:
			if c := compareNumbers(x, y); c != 0 {
				return c
			}
		case xn:
			return -1
		case yn:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(at), len(bt))
}

// Go orders Go module versions, including pseudo-versions.
func Go(a, b string) int {
	va, vb := "v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v")
	if !semver.IsValid(va) || !semver.IsValid(vb) {
		return Semver(a, b)
	}
	return semver.Compare(va, vb)
}
