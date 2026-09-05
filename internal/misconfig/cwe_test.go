package misconfig

import (
	"regexp"
	"testing"
)

var cweIDRe = regexp.MustCompile(`^CWE-\d+$`)

// TestRuleCWEsWellFormed catches typos in the hand-written CWE table (e.g. a
// stray "CWE-79o" or an accidentally empty entry) that a plain map literal
// won't catch on its own.
func TestRuleCWEsWellFormed(t *testing.T) {
	for ruleID, cwes := range ruleCWEs {
		if len(cwes) == 0 {
			t.Errorf("%s: empty CWE list", ruleID)
		}
		for _, c := range cwes {
			if !cweIDRe.MatchString(c) {
				t.Errorf("%s: malformed CWE id %q", ruleID, c)
			}
		}
	}
}
