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
