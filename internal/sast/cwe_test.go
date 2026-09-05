package sast

import (
	"reflect"
	"regexp"
	"testing"
)

func TestCweFor(t *testing.T) {
	cases := map[string][]string{
		"go-sql-injection":    {"CWE-89"},
		"java-sql-injection":  {"CWE-89"},
		"py-hardcoded-secret": {"CWE-798"},
		"ruby-ssrf":           {"CWE-918"},
		"unknown-rule":        nil,
	}
	for ruleID, want := range cases {
		if got := cweFor(ruleID); !reflect.DeepEqual(got, want) {
			t.Errorf("cweFor(%q) = %v, want %v", ruleID, got, want)
		}
	}
}

var cweIDRe = regexp.MustCompile(`^CWE-\d+$`)

// TestCategoryCWEsWellFormed catches typos in the hand-written CWE table
// (e.g. a stray "CWE-79o" or an accidentally empty entry) that a plain map
// literal won't catch on its own.
func TestCategoryCWEsWellFormed(t *testing.T) {
	for category, cwes := range categoryCWEs {
		if len(cwes) == 0 {
			t.Errorf("%s: empty CWE list", category)
		}
		for _, c := range cwes {
			if !cweIDRe.MatchString(c) {
				t.Errorf("%s: malformed CWE id %q", category, c)
			}
		}
	}
}
