package quality

import (
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

// assertQualityIssues checks that each rule ID in want fired exactly that
// many times, and that no *other* rule fired unexpectedly (checked by
// comparing total counted issues against the sum of want) — a clean
// function in the same fixture should never trip any rule.
func assertQualityIssues(t *testing.T, issues []model.Issue, want map[string]int) {
	t.Helper()
	counts := map[string]int{}
	for _, i := range issues {
		counts[i.RuleID]++
	}
	total := 0
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
		total += n
	}
	if len(issues) != total {
		t.Errorf("got %d total issues, want %d (issues: %+v)", len(issues), total, issues)
	}
}
