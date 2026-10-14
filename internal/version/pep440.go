package version

import (
	"math"
	"regexp"
	"strings"
)

var pep440Re = regexp.MustCompile(`(?i)^\s*v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?([0-9]+)?)?` +
	`(?:-([0-9]+)|[-_.]?(post|rev|r)[-_.]?([0-9]+)?)?` +
	`(?:[-_.]?(dev)[-_.]?([0-9]+)?)?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$`)

type pep440Version struct {
	epoch   int
	release []int
	pre     [2]int
	post    int
	dev     int
	local   []string
}

const (
	pepNegInf = math.MinInt
	pepPosInf = math.MaxInt
)

func parsePEP440(s string) (pep440Version, bool) {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440Version{}, false
	}
	var v pep440Version
	v.epoch = atoi(m[1])
	for _, p := range strings.Split(m[2], ".") {
		v.release = append(v.release, atoi(p))
	}
	for len(v.release) > 1 && v.release[len(v.release)-1] == 0 {
		v.release = v.release[:len(v.release)-1]
	}

	hasPre, hasPost, hasDev := m[3] != "", m[5] != "" || m[6] != "", m[8] != ""
	switch {
	case hasPre:
		rank := map[string]int{"a": 0, "alpha": 0, "b": 1, "beta": 1}[strings.ToLower(m[3])]
		if l := strings.ToLower(m[3]); l == "c" || l == "rc" || l == "pre" || l == "preview" {
			rank = 2
		}
		v.pre = [2]int{rank, atoi(m[4])}
	case hasDev && !hasPost:
		v.pre = [2]int{pepNegInf, 0}
	default:
		v.pre = [2]int{pepPosInf, 0}
	}
	v.post = pepNegInf
	if hasPost {
		v.post = atoi(m[5] + m[7])
	}
	v.dev = pepPosInf
	if hasDev {
		v.dev = atoi(m[9])
	}
	if m[10] != "" {
		v.local = strings.FieldsFunc(strings.ToLower(m[10]), func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	}
	return v, true
}

// PEP440 orders Python package versions per PEP 440.
func PEP440(a, b string) int {
	va, okA := parsePEP440(a)
	vb, okB := parsePEP440(b)
	if !okA || !okB {
		return Generic(a, b)
	}
	if c := cmpInt(va.epoch, vb.epoch); c != 0 {
		return c
	}
	for i := 0; i < len(va.release) || i < len(vb.release); i++ {
		x, y := 0, 0
		if i < len(va.release) {
			x = va.release[i]
		}
		if i < len(vb.release) {
			y = vb.release[i]
		}
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	for _, c := range []int{
		cmpInt(va.pre[0], vb.pre[0]), cmpInt(va.pre[1], vb.pre[1]),
		cmpInt(va.post, vb.post), cmpInt(va.dev, vb.dev),
	} {
		if c != 0 {
			return c
		}
	}
	return comparePEP440Local(va.local, vb.local)
}

func comparePEP440Local(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		xn, yn := isNumber(x), isNumber(y)
		switch {
		case xn && yn:
			if c := compareNumbers(x, y); c != 0 {
				return c
			}
		case xn:
			return 1
		case yn:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}
