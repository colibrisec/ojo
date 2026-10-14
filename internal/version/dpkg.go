package version

import "strings"

// Dpkg orders Debian versions: [epoch:]upstream[-revision], with "~"
// sorting before everything, even the end of the string.
func Dpkg(a, b string) int {
	ae, au, ar := splitDpkg(a)
	be, bu, br := splitDpkg(b)
	if c := compareNumbers(ae, be); c != 0 {
		return c
	}
	if c := dpkgVerrevcmp(au, bu); c != 0 {
		return c
	}
	return dpkgVerrevcmp(ar, br)
}

func splitDpkg(s string) (epoch, upstream, revision string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(s, ":"); ok && isNumber(e) {
		epoch, s = e, rest
	}
	upstream = s
	if i := strings.LastIndex(s, "-"); i >= 0 {
		upstream, revision = s[:i], s[i+1:]
	}
	return epoch, upstream, revision
}

func dpkgOrder(c byte, ok bool) int {
	switch {
	case !ok:
		return 0
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

func dpkgVerrevcmp(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			ac := dpkgOrder(at(a), a != "")
			bc := dpkgOrder(at(b), b != "")
			if ac != bc {
				return cmpInt(ac, bc)
			}
			a, b = rest(a), rest(b)
		}
		var na, nb string
		na, a = span(a, isDigit)
		nb, b = span(b, isDigit)
		if c := compareNumbers(na, nb); c != 0 {
			return c
		}
	}
	return 0
}

func at(s string) byte {
	if s == "" {
		return 0
	}
	return s[0]
}

func rest(s string) string {
	if s == "" {
		return s
	}
	return s[1:]
}
