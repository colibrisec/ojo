package quality

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanTODOCommentsFindsMarkersAcrossLanguages(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go":   "package a\n\n// TODO: refactor this\nfunc f() {}\n",
		"a.py":   "# FIXME: handle the empty case\ndef f():\n    pass\n",
		"a.js":   "// TODO fix\nfunction f() {}\n/* FIXME later */\n",
		"a.php":  "<?php\n// HACK: workaround for #123\nfunction f() {}\n",
		"a.rb":   "# XXX this is fragile\ndef f\nend\n",
		"a.java": "class X {\n  // TODO revisit\n  void f() {}\n}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	issues, err := scanTODOComments(dir)
	if err != nil {
		t.Fatal(err)
	}
	// One marker per file except a.js, which has two (a TODO line comment
	// and a separate FIXME block comment) — 6 files + 1 extra = 7.
	if want := len(files) + 1; len(issues) != want {
		t.Fatalf("expected %d quality-todo-comment issues, got %d: %+v", want, len(issues), issues)
	}
	for _, i := range issues {
		if i.RuleID != "quality-todo-comment" {
			t.Errorf("unexpected rule id: %s", i.RuleID)
		}
		if i.Severity != "INFO" {
			t.Errorf("expected INFO severity, got %s", i.Severity)
		}
	}
}

func TestScanTODOCommentsIgnoresNonCommentText(t *testing.T) {
	dir := t.TempDir()
	src := "package a\n\nfunc f() {\n\tx := \"this string mentions TODO but isn't a comment\"\n\t_ = x\n\t// notes from the hackathon prototype, nothing tracked here\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := scanTODOComments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no quality-todo-comment issues (TODO is inside a string literal, not a comment; 'hackathon' isn't a standalone HACK marker), got %+v", issues)
	}
}
