package secret

import (
	"path/filepath"
	"strings"
)

// testPathSegments are directory names that mark a file as test-owned when
// they appear as a whole path segment (not a substring — "latest" must not match "test").
var testPathSegments = map[string]bool{
	"test":      true,
	"tests":     true,
	"testdata":  true,
	"fixtures":  true,
	"__tests__": true,
	"mocks":     true,
}

// isLikelyTestFile reports whether path is recognizably a test file by
// naming/path convention: a _test.go / .test. / .spec. basename, or a
// testdata/fixtures/__tests__/mocks/test/tests path segment.
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

// placeholderMarkers are substrings (case-insensitive) that indicate a match is a
// documentation/test placeholder rather than a live credential.
//
// ponytail: this is a fixed marker-word list plus a structural run check, not a
// learned or exhaustive model — it will miss creatively-worded fakes
// ("not-a-real-key", leetspeak, foreign-language placeholders). If real triage
// shows meaningful false negatives (real secrets in test dirs slipping through)
// or false positives (real secrets that happen to contain "sample"), the
// upgrade path is growing this list from actual findings, not rearchitecting
// how Scan() calls into it.
var placeholderMarkers = []string{
	"example", "placeholder", "changeme", "dummy", "fake", "sample",
	"foobar", "hunter2", "yourkey", "testtest", "notreal", "redacted",
}

// looksLikePlaceholder reports whether the matched secret text itself looks
// hand-written rather than a real generated credential: either it contains a
// common placeholder marker word, or it has a sequential/repeated character
// run of the kind humans type ("ABCDEFGH...", "00000000", "12345678") that
// cryptographically random secrets essentially never produce.
func looksLikePlaceholder(secret string) bool {
	lower := strings.ToLower(secret)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return hasSequentialOrRepeatedRun(secret, 8)
}

// hasSequentialOrRepeatedRun reports whether s contains a run of >= minRun
// bytes that are either all identical ("00000000") or strictly ascending by
// 1 ("12345678", "ABCDEFGH").
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
