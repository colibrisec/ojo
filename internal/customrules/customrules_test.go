package customrules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRule(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingDirIsNotAnError(t *testing.T) {
	rules, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing rules dir should not error, got: %v", err)
	}
	if rules != nil {
		t.Errorf("expected no rules, got %+v", rules)
	}
}

func TestLoadEmptyDirIsNotAnError(t *testing.T) {
	rules, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if rules != nil {
		t.Errorf("expected no rules, got %+v", rules)
	}
}

const validRule = `
id: py-custom-mktemp
language: python
severity: MEDIUM
title: insecure temp path
message: tempfile.mktemp() is insecure
query: |
  (call function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
    (#eq? @mod "tempfile") (#eq? @fn "mktemp")) @match
`

func TestLoadValidRule(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "mktemp.yaml", validRule)

	rules, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "py-custom-mktemp" {
		t.Fatalf("expected 1 rule with id py-custom-mktemp, got %+v", rules)
	}
}

func TestLoadRejectsUnknownLanguage(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", `
id: x
language: cobol
severity: HIGH
message: m
query: "(call) @match"
`)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected an error for unknown language")
	}
}

func TestLoadRejectsUnknownSeverity(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", `
id: x
language: python
severity: SUPER_HIGH
message: m
query: "(call) @match"
`)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected an error for unknown severity")
	}
}

func TestLoadRejectsMissingMatchCapture(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", `
id: x
language: python
severity: HIGH
message: m
query: "(call) @call"
`)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected an error for a query with no @match capture")
	}
}

func TestLoadRejectsInvalidQuery(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", `
id: x
language: python
severity: HIGH
message: m
query: "(not_a_real_node_type) @match"
`)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected an error for an invalid tree-sitter query")
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "a.yaml", validRule)
	writeRule(t, dir, "b.yaml", validRule)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected an error for a duplicate rule id across files")
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", `
id: x
language: python
severity: HIGH
message: m
query: "(call) @match"
oops: not_a_real_field
`)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected an error for an unrecognized YAML field")
	}
}

func TestScanFindsMatches(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "mktemp.yaml", validRule)
	rules, err := Load(rulesDir)
	if err != nil {
		t.Fatal(err)
	}

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "app.py"), []byte(`
import tempfile

def unsafe():
    return tempfile.mktemp()

def unrelated():
    return tempfile.NamedTemporaryFile()
`), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(srcDir, rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d: %+v", len(issues), issues)
	}
	if issues[0].RuleID != "py-custom-mktemp" || issues[0].Severity != "MEDIUM" || issues[0].File != filepath.Join(srcDir, "app.py") {
		t.Errorf("unexpected issue: %+v", issues[0])
	}
}

func TestScanNoRulesReturnsNil(t *testing.T) {
	issues, err := Scan(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if issues != nil {
		t.Errorf("expected no issues, got %+v", issues)
	}
}
