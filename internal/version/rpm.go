package version

import "strings"

// RPM orders [epoch:]version[-release] the way rpm does.
func RPM(a, b string) int {
	ae, av, ar := splitRPM(a)
	be, bv, br := splitRPM(b)
	if c := RPMVercmp(ae, be); c != 0 {
		return c
	}
	if c := RPMVercmp(av, bv); c != 0 {
		return c
	}
	return RPMVercmp(ar, br)
}

func splitRPM(s string) (epoch, version, release string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(s, ":"); ok {
		epoch, s = e, rest
		if epoch == "" {
			epoch = "0"
		}
	}
	version = s
	if i := strings.LastIndex(s, "-"); i >= 0 {
		version, release = s[:i], s[i+1:]
	}
	return epoch, version, release
}

// RPMVercmp is rpm's rpmvercmp: runs of digits compare as numbers and beat
// runs of letters; anything else only separates. "~" sorts before
// anything, even the end of the string, and "^" after the end but before
// any other segment.
func RPMVercmp(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		a, b = strings.TrimLeftFunc(a, rpmSeparator), strings.TrimLeftFunc(b, rpmSeparator)

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

		numeric := isDigit(a[0])
		var segA, segB string
		if numeric {
			segA, a = span(a, isDigit)
			segB, b = span(b, isDigit)
		} else {
			segA, a = span(a, isAlpha)
			segB, b = span(b, isAlpha)
		}
		if segB == "" {
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			if c := compareNumbers(segA, segB); c != 0 {
				return c
			}
			continue
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func rpmSeparator(r rune) bool {
	return !(r < 128 && (isDigit(byte(r)) || isAlpha(byte(r)))) && r != '~' && r != '^'
}
