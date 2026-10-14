package version

import (
	"regexp"
	"strings"
)

var gemSegmentRe = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)

// Gem orders RubyGems versions the way Gem::Version does: a letter makes
// a version a prerelease, older than the release it precedes.
func Gem(a, b string) int {
	as, bs := gemSegments(a), gemSegments(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		x, y := "0", "0"
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x == y {
			continue
		}
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
			return strings.Compare(x, y)
		}
	}
	return 0
}

// gemSegments mirrors Gem::Version#canonical_segments: trailing zeros are
// dropped from the release part and from each run before a letter.
func gemSegments(s string) []string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "-", ".pre.")
	var out, run []string
	flush := func() {
		for len(run) > 0 && strings.Trim(run[len(run)-1], "0") == "" {
			run = run[:len(run)-1]
		}
		out = append(out, run...)
		run = nil
	}
	for _, seg := range gemSegmentRe.FindAllString(s, -1) {
		if !isNumber(seg) {
			flush()
		}
		run = append(run, seg)
	}
	flush()
	return out
}
