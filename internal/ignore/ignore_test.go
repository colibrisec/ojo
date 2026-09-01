package ignore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

func TestLoad_DefaultMissingIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	rules, err := Load("")
	if err != nil {
		t.Fatalf("expected no error for a missing default .ojoignore, got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected no rules, got %+v", rules)
	}
}

func TestLoad_ExplicitMissingIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error for a missing explicit --ignore-file path")
	}
}

func TestLoad_ParsesFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojoignore")
	content := "# full-line comment, skipped\n\n" +
		"CVE-2024-XXXX  path/to/package.json  # accepted risk, reviewed\n" +
		"go-sql-injection  internal/foo/*.go  # low risk here (expires: 2026-12-31)\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d: %+v", len(rules), rules)
	}

	r0 := rules[0]
	if r0.ID != "CVE-2024-XXXX" || r0.PathGlob != "path/to/package.json" || r0.Reason != "accepted risk, reviewed" || !r0.Expires.IsZero() {
		t.Errorf("rule 0 = %+v", r0)
	}

	r1 := rules[1]
	wantExpires, _ := time.Parse("2006-01-02", "2026-12-31")
	if r1.ID != "go-sql-injection" || r1.PathGlob != "internal/foo/*.go" || r1.Reason != "low risk here" || !r1.Expires.Equal(wantExpires) {
		t.Errorf("rule 1 = %+v", r1)
	}
}

func TestLoad_MissingReasonIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojoignore")
	if err := os.WriteFile(path, []byte("CVE-2024-XXXX  path/to/package.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected an error for a missing reason")
	}
}

func TestLoad_WrongFieldCountIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojoignore")
	if err := os.WriteFile(path, []byte("CVE-2024-XXXX  # reason, no path glob\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected an error for a missing path glob")
	}
}

func TestLoad_BadExpiryDateIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojoignore")
	if err := os.WriteFile(path, []byte("CVE-2024-XXXX  foo.json  # reason (expires: not-a-date)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected an error for a malformed expires date")
	}
}

func TestRuleMatches(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	future, _ := time.Parse("2006-01-02", "2026-12-31")
	past, _ := time.Parse("2006-01-02", "2025-01-01")

	r := Rule{ID: "CVE-1", PathGlob: "internal/foo/*.go", Reason: "x"}
	if !r.Matches("CVE-1", "internal/foo/bar.go", now) {
		t.Error("expected match on id + glob")
	}
	if r.Matches("CVE-2", "internal/foo/bar.go", now) {
		t.Error("expected no match on wrong id")
	}
	if r.Matches("CVE-1", "internal/foo/nested/bar.go", now) {
		t.Error("expected * to not span a path separator")
	}

	rActive := Rule{ID: "CVE-1", PathGlob: "*.go", Reason: "x", Expires: future}
	if !rActive.Matches("CVE-1", "bar.go", now) {
		t.Error("expected match before expiry")
	}
	rExpired := Rule{ID: "CVE-1", PathGlob: "*.go", Reason: "x", Expires: past}
	if rExpired.Matches("CVE-1", "bar.go", now) {
		t.Error("expected no match after expiry")
	}
}

func TestApply_FindingPartiallySuppressed(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Name: "foo", Version: "1.0", Source: "package.json"},
		Vulns: []model.Vulnerability{
			{ID: "CVE-1", Severity: "HIGH"},
			{ID: "CVE-2", Severity: "LOW"},
		},
	}}
	rules := []Rule{{ID: "CVE-1", PathGlob: "package.json", Reason: "accepted"}}

	kept, suppressed, _, _ := Apply(findings, nil, rules, "", time.Now())
	if len(kept) != 1 || len(kept[0].Vulns) != 1 || kept[0].Vulns[0].ID != "CVE-2" {
		t.Errorf("expected only CVE-2 to remain, got %+v", kept)
	}
	if len(suppressed) != 1 || suppressed[0].Vuln.ID != "CVE-1" || suppressed[0].Reason != "accepted" {
		t.Errorf("expected CVE-1 suppressed with reason, got %+v", suppressed)
	}
}

func TestApply_FindingFullySuppressedIsDropped(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Name: "foo", Source: "package.json"},
		Vulns:   []model.Vulnerability{{ID: "CVE-1"}},
	}}
	rules := []Rule{{ID: "CVE-1", PathGlob: "package.json", Reason: "accepted"}}

	kept, suppressed, _, _ := Apply(findings, nil, rules, "", time.Now())
	if len(kept) != 0 {
		t.Errorf("expected the finding to be dropped entirely, got %+v", kept)
	}
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed vuln, got %+v", suppressed)
	}
}

func TestApply_MatchesByAlias(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Source: "package.json"},
		Vulns:   []model.Vulnerability{{ID: "OSV-1", Aliases: []string{"CVE-2024-XXXX"}}},
	}}
	rules := []Rule{{ID: "CVE-2024-XXXX", PathGlob: "package.json", Reason: "accepted"}}

	kept, suppressed, _, _ := Apply(findings, nil, rules, "", time.Now())
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Errorf("expected the alias match to suppress the finding, kept=%+v suppressed=%+v", kept, suppressed)
	}
}

func TestApply_IssueSuppressed(t *testing.T) {
	issues := []model.Issue{
		{RuleID: "go-sql-injection", File: "internal/foo/bar.go"},
		{RuleID: "go-sql-injection", File: "internal/baz/qux.go"},
	}
	rules := []Rule{{ID: "go-sql-injection", PathGlob: "internal/foo/*.go", Reason: "reviewed"}}

	_, _, kept, suppressed := Apply(nil, issues, rules, "", time.Now())
	if len(kept) != 1 || kept[0].File != "internal/baz/qux.go" {
		t.Errorf("expected only the baz issue to remain, got %+v", kept)
	}
	if len(suppressed) != 1 || suppressed[0].Issue.File != "internal/foo/bar.go" || suppressed[0].Reason != "reviewed" {
		t.Errorf("expected the foo issue suppressed with reason, got %+v", suppressed)
	}
}

// Secret findings are model.Issues shaped identically to any other
// scanner's (RuleID + File), so .ojoignore suppresses them the same way
// with no secret-specific code -- pins that this stays true.
func TestApply_SuppressesSecretIssues(t *testing.T) {
	issues := []model.Issue{{Scanner: "secret", RuleID: "aws-access-key", File: "internal/testdata/fixture.env"}}
	rules := []Rule{{ID: "aws-access-key", PathGlob: "internal/testdata/*.env", Reason: "known-good test fixture"}}

	_, _, kept, suppressed := Apply(nil, issues, rules, "", time.Now())
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Errorf("expected the secret issue suppressed, kept=%+v suppressed=%+v", kept, suppressed)
	}
}

func TestApply_PathIsRelativeToRoot(t *testing.T) {
	issues := []model.Issue{{RuleID: "r1", File: filepath.Join("repo", "internal", "foo.go")}}
	rules := []Rule{{ID: "r1", PathGlob: "internal/foo.go", Reason: "x"}}

	_, _, kept, suppressed := Apply(nil, issues, rules, "repo", time.Now())
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Errorf("expected match against the root-relative path, kept=%+v suppressed=%+v", kept, suppressed)
	}
}
