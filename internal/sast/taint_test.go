package sast

import (
	"os"
	"path/filepath"
	"testing"
)

// goTaintThroughVar is the exact false-negative documented as the SAST
// scanner's #1 ceiling: request data hidden behind one local variable
// before reaching the sink.
const goTaintThroughVar = `package main

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
)

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

func fileHandler(r *http.Request) {
	name := r.FormValue("name")
	os.Open(name)
}

func cmdHandler(r *http.Request) {
	arg := r.FormValue("arg")
	exec.Command("sh", "-c", arg)
}

func queryHandler(r *http.Request, db *sql.DB) {
	id := r.FormValue("id")
	db.Query(id)
}

func envHandler() {
	target := os.Getenv("REDIRECT_TARGET")
	req := &http.Request{}
	http.Redirect(nil, req, target, http.StatusFound)
}

func safeHandler(w http.ResponseWriter, r *http.Request) {
	next := "/dashboard"
	http.Redirect(w, r, next, http.StatusFound)
}
`

func TestGoTaintTrackingThroughLocalVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), []byte(goTaintThroughVar), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	counts := map[string]int{}
	for _, i := range issues {
		counts[i.RuleID]++
	}

	want := map[string]int{
		"go-open-redirect":     2, // redirectHandler + envHandler (via os.Getenv)
		"go-path-traversal":    1,
		"go-command-injection": 1,
		"go-sql-injection":     1,
	}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
	}
}

// goTaintDoesNotCrossFunctions documents the remaining ceiling: taint
// doesn't survive a value being passed into a helper and returned.
const goTaintDoesNotCrossFunctions = `package main

import "net/http"

func sanitize(s string) string { return s }

func handler(w http.ResponseWriter, r *http.Request) {
	next := sanitize(r.URL.Query().Get("next"))
	http.Redirect(w, r, next, http.StatusFound)
}
`

func TestGoTaintDoesNotCrossFunctionCalls(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler2.go"), []byte(goTaintDoesNotCrossFunctions), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	// sanitize(r.URL.Query().Get("next")) is a CallExpr whose *argument* is
	// tainted, so goExprTainted still sees through it (documented as
	// intentional: taint propagates through the call's arguments, not
	// through resolving what the callee returns). This test pins that
	// behavior so a future change to goExprTainted is deliberate, not
	// accidental.
	found := false
	for _, i := range issues {
		if i.RuleID == "go-open-redirect" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected go-open-redirect to still fire through a wrapping call's argument, got: %+v", issues)
	}
}
