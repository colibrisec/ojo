package sast

import (
	"reflect"
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
