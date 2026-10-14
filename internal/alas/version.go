package alas

import (
	"strings"

	"github.com/colibrisec/ojo/internal/version"
)

// evr is an rpm epoch:version-release.
type evr struct {
	epoch, version, release string
}

// parseEVR splits a version as internal/image writes it for an rpm:
// "[epoch:]version[-release]".
func parseEVR(s string) evr {
	var v evr
	if epoch, rest, ok := strings.Cut(s, ":"); ok {
		v.epoch, s = epoch, rest
	}
	v.version = s
	if i := strings.LastIndex(s, "-"); i >= 0 {
		v.version, v.release = s[:i], s[i+1:]
	}
	return v
}

// String formats v the way parseEVR reads it, leaving out a zero epoch.
func (v evr) String() string {
	s := v.version
	if v.release != "" {
		s += "-" + v.release
	}
	if e := strings.TrimLeft(v.epoch, "0"); e != "" {
		s = e + ":" + s
	}
	return s
}

// compareEVR orders two versions the way rpm does: epoch, then version,
// then release. It returns a negative number, zero or a positive number as
// a is older than, the same as or newer than b.
func compareEVR(a, b evr) int {
	// A missing epoch is 0, and epochs are plain numbers, which vercmp
	// compares correctly once both sides are non-empty.
	if c := version.RPMVercmp(orZero(a.epoch), orZero(b.epoch)); c != 0 {
		return c
	}
	if c := version.RPMVercmp(a.version, b.version); c != 0 {
		return c
	}
	return version.RPMVercmp(a.release, b.release)
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}
