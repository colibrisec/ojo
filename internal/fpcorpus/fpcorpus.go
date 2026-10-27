// Package fpcorpus checks false-positive regression cases in scanner tests.
package fpcorpus

import (
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

// Check asserts what rule did in issues. want is "none" (must not fire),
// "fire" (must fire), "high"/"low" (must fire, at that severity) or "known"
// (a recorded false positive not fixed yet: must still fire, so a fix flips
// it to "none").
func Check(t *testing.T, rule, want, source string, issues []model.Issue) {
	t.Helper()
	var hits []model.Issue
	for _, i := range issues {
		if i.RuleID == rule {
			hits = append(hits, i)
		}
	}
	switch want {
	case "none":
		if len(hits) > 0 {
			t.Errorf("false positive regressed (%s): %s fired: %+v", source, rule, hits)
		}
	case "fire":
		if len(hits) == 0 {
			t.Errorf("%s no longer fires on a must-fire case (%s); all issues: %+v", rule, source, issues)
		}
	case "low", "high":
		if len(hits) == 0 {
			t.Errorf("%s no longer fires (%s)", rule, source)
		}
		for _, h := range hits {
			if !strings.EqualFold(h.Severity, want) {
				t.Errorf("%s: want %s, got %s: %+v", rule, strings.ToUpper(want), h.Severity, h)
			}
		}
	case "known":
		if len(hits) == 0 {
			t.Errorf("known false positive (%s) no longer fires for %s: mark the case \"none\"", source, rule)
		}
	default:
		t.Fatalf("bad want %q", want)
	}
}
