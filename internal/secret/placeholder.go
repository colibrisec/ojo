package secret

import (
	"path/filepath"
	"strings"
)

var testPathSegments = map[string]bool{
	"test":      true,
	"tests":     true,
	"testdata":  true,
	"fixtures":  true,
	"__tests__": true,
	"mocks":     true,
}

func isLikelyTestFile(path string) bool {
	slash := filepath.ToSlash(path)
	base := strings.ToLower(filepath.Base(slash))
	if strings.HasSuffix(base, "_test.go") ||
		strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") {
		return true
	}
	for _, seg := range strings.Split(slash, "/") {
		if testPathSegments[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

var placeholderMarkers = []string{
	"example", "placeholder", "changeme", "dummy", "fake", "sample",
	"foobar", "hunter2", "yourkey", "testtest", "notreal", "redacted",
}

func looksLikePlaceholder(secret string) bool {
	lower := strings.ToLower(secret)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return hasSequentialOrRepeatedRun(secret, 8)
}

func hasSequentialOrRepeatedRun(s string, minRun int) bool {
	if len(s) < minRun {
		return false
	}
	repeatRun, seqRun := 1, 1
	for i := 1; i < len(s); i++ {
		prev, cur := s[i-1], s[i]
		if cur == prev {
			repeatRun++
		} else {
			repeatRun = 1
		}
		if cur == prev+1 {
			seqRun++
		} else {
			seqRun = 1
		}
		if repeatRun >= minRun || seqRun >= minRun {
			return true
		}
	}
	return false
}
