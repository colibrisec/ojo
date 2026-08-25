package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const vulnerable = `package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
)

var apiSecret = "sk_super_secret_value_123"

func run(userInput string, db *sql.DB) {
	exec.Command("sh", "-c", fmt.Sprintf("echo %s", userInput))
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput))
	_ = md5.New()
	_ = &tls.Config{InsecureSkipVerify: true}
	os.MkdirAll("/tmp/data", 0777)
}
`

const clean = `package main

import "os/exec"

func run() {
	exec.Command("ls", "-la")
}
`

func TestScanFindsVulnerablePatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(vulnerable), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"go-hardcoded-secret":         false,
		"go-command-injection":        false,
		"go-sql-injection":            false,
		"go-weak-hash":                false,
		"go-tls-insecure-skip-verify": false,
		"go-permissive-file-mode":     false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestScanNoFalsePositiveOnLiteralCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for a literal exec.Command call, got: %+v", issues)
	}
}

const goNewRules = `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	http.Redirect(w, r, fmt.Sprintf("/go/%s", "x"), http.StatusFound)
	http.Redirect(w, r, "/safe", http.StatusFound)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	_ = jwt.SigningMethodNone
}
`

func TestScanFindsNewGoRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), []byte(goNewRules), 0o644); err != nil {
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
	if counts["go-open-redirect"] != 2 {
		t.Errorf("expected 2 go-open-redirect issues (request-derived + Sprintf-built target), got %d: %+v", counts["go-open-redirect"], issues)
	}
	if counts["go-cors-wildcard"] != 1 {
		t.Errorf("expected 1 go-cors-wildcard issue, got %d: %+v", counts["go-cors-wildcard"], issues)
	}
	if counts["go-jwt-none-algorithm"] != 1 {
		t.Errorf("expected 1 go-jwt-none-algorithm issue, got %d: %+v", counts["go-jwt-none-algorithm"], issues)
	}
}

const goCookieAndPathRules = `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	_ = &http.Cookie{Name: "id", Secure: false, HttpOnly: false}
	os.Open(r.URL.Query().Get("path"))
	os.Open("/safe/path")
}
`

func TestScanFindsGoCookieAndPathTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler2.go"), []byte(goCookieAndPathRules), 0o644); err != nil {
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
	if counts["go-insecure-cookie"] != 2 {
		t.Errorf("expected 2 go-insecure-cookie issues (Secure + HttpOnly), got %d: %+v", counts["go-insecure-cookie"], issues)
	}
	if counts["go-path-traversal"] != 1 {
		t.Errorf("expected 1 go-path-traversal issue, got %d: %+v", counts["go-path-traversal"], issues)
	}
}

const goCookieMissingFlagsRules = `package main

import "net/http"

func handler() {
	_ = &http.Cookie{Name: "id", Value: "x"}
	_ = &http.Cookie{Name: "id2", Secure: true, HttpOnly: true}
}
`

func TestScanFindsGoCookieMissingFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler3.go"), []byte(goCookieMissingFlagsRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "go-cookie-missing-flags" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 go-cookie-missing-flags issues (Secure + HttpOnly missing on the first cookie only), got %d: %+v", count, issues)
	}
}
