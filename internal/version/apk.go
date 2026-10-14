package version

import "strings"

var apkSuffixes = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

type apkVersion struct {
	numbers  []string
	letter   byte
	suffixes [][2]int // rank, number
	revision string
}

func parseAPK(s string) (apkVersion, bool) {
	var v apkVersion
	if i := strings.LastIndex(s, "-r"); i >= 0 && isNumber(s[i+2:]) {
		s, v.revision = s[:i], s[i+2:]
	}
	for {
		var n string
		n, s = span(s, isDigit)
		if n == "" {
			return v, false
		}
		v.numbers = append(v.numbers, n)
		if !strings.HasPrefix(s, ".") {
			break
		}
		s = s[1:]
	}
	if s != "" && s[0] >= 'a' && s[0] <= 'z' {
		v.letter, s = s[0], s[1:]
	}
	for strings.HasPrefix(s, "_") {
		var name, n string
		name, s = span(s[1:], isAlpha)
		rank, ok := apkSuffixes[name]
		if !ok {
			return v, false
		}
		n, s = span(s, isDigit)
		v.suffixes = append(v.suffixes, [2]int{rank, atoi(n)})
	}
	return v, s == ""
}

// APK orders Alpine package versions:
// digits{.digits}[letter]{_suffix[digits]}[-rN].
func APK(a, b string) int {
	va, okA := parseAPK(a)
	vb, okB := parseAPK(b)
	if !okA || !okB {
		return Generic(a, b)
	}
	for i := 0; i < len(va.numbers) || i < len(vb.numbers); i++ {
		if i >= len(va.numbers) {
			return -1
		}
		if i >= len(vb.numbers) {
			return 1
		}
		if c := compareNumbers(va.numbers[i], vb.numbers[i]); c != 0 {
			return c
		}
	}
	if c := cmpInt(int(va.letter), int(vb.letter)); c != 0 {
		return c
	}
	for i := 0; i < len(va.suffixes) || i < len(vb.suffixes); i++ {
		var sa, sb [2]int
		if i < len(va.suffixes) {
			sa = va.suffixes[i]
		}
		if i < len(vb.suffixes) {
			sb = vb.suffixes[i]
		}
		if c := cmpInt(sa[0], sb[0]); c != 0 {
			return c
		}
		if c := cmpInt(sa[1], sb[1]); c != 0 {
			return c
		}
	}
	return compareNumbers(va.revision, vb.revision)
}
