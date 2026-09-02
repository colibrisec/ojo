package quality

import (
	"os"
	"path/filepath"
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

// TestScan exercises the exported Scan orchestrator directly (every other
// test in this package calls one of the per-language scanX helpers), so it
// covers the wiring in Scan itself: looping over all six language scanners
// plus scanDuplicates and scanTODOComments, and merging all their results.
func TestScan(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\n// TODO: replace with the real implementation\nfunc f() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range issues {
		if i.RuleID == "quality-todo-comment" {
			found = true
		}
		if i.Scanner != "quality" {
			t.Errorf("expected Scanner \"quality\" on every issue, got %q on %+v", i.Scanner, i)
		}
	}
	if !found {
		t.Errorf("expected Scan to include a quality-todo-comment issue from scanTODOComments, got: %+v", issues)
	}
}
