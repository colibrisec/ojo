package alas

import "strings"

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
	if c := vercmp(orZero(a.epoch), orZero(b.epoch)); c != 0 {
		return c
	}
	if c := vercmp(a.version, b.version); c != 0 {
		return c
	}
	return vercmp(a.release, b.release)
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// vercmp is rpm's rpmvercmp: the strings are compared segment by segment,
// where a segment is a run of digits or a run of letters and everything
// else only separates. Digits compare as numbers and beat letters; "~"
// sorts before anything, even the end of the string (1.0~rc1 < 1.0), and
// "^" sorts after the end but before any other segment (1.0 < 1.0^git1 <
// 1.0.1).
func vercmp(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		a, b = strings.TrimLeftFunc(a, isSeparator), strings.TrimLeftFunc(b, isSeparator)

		aTilde, bTilde := strings.HasPrefix(a, "~"), strings.HasPrefix(b, "~")
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}

		aCaret, bCaret := strings.HasPrefix(a, "^"), strings.HasPrefix(b, "^")
		if aCaret || bCaret {
			switch {
			case a == "":
				return -1
			case b == "":
				return 1
			case !aCaret:
				return 1
			case !bCaret:
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}

		if a == "" || b == "" {
			break
		}

		numeric := isDigit(rune(a[0]))
		var segA, segB string
		if numeric {
			segA, a = cutWhile(a, isDigit)
			segB, b = cutWhile(b, isDigit)
		} else {
			segA, a = cutWhile(a, isAlpha)
			segB, b = cutWhile(b, isAlpha)
		}
		if segB == "" {
			// Different kinds of segment: the numeric one is newer.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			segA, segB = strings.TrimLeft(segA, "0"), strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				return len(segA) - len(segB)
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	// Whichever still has segments left is newer.
	return len(a) - len(b)
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

func isAlpha(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

func isSeparator(r rune) bool { return !isDigit(r) && !isAlpha(r) && r != '~' && r != '^' }

func cutWhile(s string, keep func(rune) bool) (head, rest string) {
	i := strings.IndexFunc(s, func(r rune) bool { return !keep(r) })
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}
