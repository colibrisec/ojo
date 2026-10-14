// Package version orders package versions by each ecosystem's own rules.
package version

import (
	"regexp"
	"strconv"
	"strings"
)

// Compare returns a negative number, zero or a positive number as a is
// older than, the same as or newer than b under ecosystem's rules. An OSV
// ecosystem string such as "Debian:12" is matched on its name.
func Compare(ecosystem, a, b string) int {
	name, _, _ := strings.Cut(ecosystem, ":")
	switch name {
	case "Debian", "Ubuntu":
		return Dpkg(a, b)
	case "Red Hat", "Rocky Linux", "AlmaLinux", "Amazon Linux":
		return RPM(a, b)
	case "Alpine":
		return APK(a, b)
	case "PyPI":
		return PEP440(a, b)
	case "Maven":
		return Maven(a, b)
	case "RubyGems":
		return Gem(a, b)
	case "Go":
		return Go(a, b)
	case "npm", "crates.io", "Pub", "Packagist", "SwiftURL":
		return Semver(a, b)
	case "NuGet":
		return Semver(strings.ToLower(a), strings.ToLower(b))
	default:
		return Generic(a, b)
	}
}

var genericTokenRe = regexp.MustCompile(`\d+|\D+`)

// Generic compares runs of digits numerically and everything else as text.
func Generic(a, b string) int {
	at := genericTokenRe.FindAllString(a, -1)
	bt := genericTokenRe.FindAllString(b, -1)
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
		if isNumber(ta) && isNumber(tb) {
			if c := compareNumbers(ta, tb); c != 0 {
				return c
			}
			continue
		}
		return strings.Compare(ta, tb)
	}
	return 0
}

func isDigit(r byte) bool { return r >= '0' && r <= '9' }

func isAlpha(r byte) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// compareNumbers compares digit strings of any length.
func compareNumbers(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func span(s string, keep func(byte) bool) (head, rest string) {
	i := 0
	for i < len(s) && keep(s[i]) {
		i++
	}
	return s[:i], s[i:]
}
