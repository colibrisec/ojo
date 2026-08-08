package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const jsVulnerable = "const cp = require('child_process');\n" +
	"const crypto = require('crypto');\n" +
	"\n" +
	"const apiToken = \"sk_super_secret_value_123\";\n" +
	"\n" +
	"function run(userInput, db, req, res) {\n" +
	"    eval(userInput);\n" +
	"    cp.exec(`echo ${userInput}`);\n" +
	"    db.query(`SELECT * FROM users WHERE name = '${userInput}'`);\n" +
	"    crypto.createHash('md5');\n" +
	"    const agent = { rejectUnauthorized: false };\n" +
	"    document.getElementById('x').innerHTML = userInput;\n" +
	"    res.redirect(req.query.url);\n" +
	"    const opts = { algorithm: 'none' };\n" +
	"}\n" +
	"\n" +
	"function generateSessionToken() {\n" +
	"    return Math.random();\n" +
	"}\n"

const jsClean = "const cp = require('child_process');\n" +
	"\n" +
	"function run() {\n" +
	"    cp.execFile('ls', ['-la']);\n" +
	"}\n"

func TestJSScanFindsVulnerablePatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsVulnerable), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"js-hardcoded-secret":            false,
		"js-eval-detected":               false,
		"js-command-injection":           false,
		"js-sql-injection":               false,
		"js-weak-hash":                   false,
		"js-insecure-random-for-secrets": false,
		"js-tls-verify-disabled":         false,
		"js-dom-xss-innerhtml":           false,
		"js-open-redirect":               false,
		"js-jwt-none-algorithm":          false,
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

func TestJSScanNoFalsePositiveOnLiteralCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsClean), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for a literal execFile call, got: %+v", issues)
	}
}

func TestJSSQLInjectionViaConcatenation(t *testing.T) {
	dir := t.TempDir()
	src := "function run(db, userInput) {\n    db.query(\"SELECT * FROM t WHERE id=\" + userInput);\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.RuleID == "js-sql-injection" {
			return
		}
	}
	t.Errorf("expected js-sql-injection to fire for string-concatenation query, got: %+v", issues)
}

const tsxVulnerable = `function Comment({ html }: { html: string }) {
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
`

func TestTSXScanFindsDangerouslySetInnerHTML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "comment.tsx"), []byte(tsxVulnerable), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range issues {
		if i.RuleID == "js-react-dangerously-set-innerhtml" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected js-react-dangerously-set-innerhtml to fire, got: %+v", issues)
	}
}
