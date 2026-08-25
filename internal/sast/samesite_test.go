package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const goSameSiteFixture = `package main

import "net/http"

func unsafe(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		SameSite: http.SameSiteNoneMode,
	})
}

func safe(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	})
}
`

func TestGoSameSiteNoneWithoutSecure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goSameSiteFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "go-insecure-cookie" && i.Title == "SameSite=None cookie without Secure" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 SameSite=None-without-Secure issue, got %d: %+v", count, issues)
	}
}

const jsSameSiteFixture = `app.get('/go', (req, res) => {
	res.cookie('session', 'x', { sameSite: 'none' });
});

app.get('/safe', (req, res) => {
	res.cookie('session', 'x', { sameSite: 'none', secure: true });
});
`

func TestJSSameSiteNoneWithoutSecure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsSameSiteFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "js-insecure-cookie" && i.Title == "SameSite=None cookie without Secure" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 SameSite=None-without-Secure issue, got %d: %+v", count, issues)
	}
}
