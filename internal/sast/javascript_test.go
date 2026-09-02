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

const jsCORSVulnerable = `function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
}
`

func TestJSScanFindsCORSWildcard(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app2.js"), []byte(jsCORSVulnerable), 0o644); err != nil {
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
	if counts["js-cors-wildcard"] != 1 {
		t.Errorf("expected 1 js-cors-wildcard issue, got %d: %+v", counts["js-cors-wildcard"], issues)
	}
}

const jsCookieAndPathRules = `function handler(req, res) {
  res.cookie('id', 'x', { httpOnly: false, secure: false });
  res.cookie('theme', 'dark', { httpOnly: true });
  fs.readFile(req.query.path, cb);
  fs.readFile('/safe/path', cb);
}
`

func TestJSScanFindsCookieAndPathTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app3.js"), []byte(jsCookieAndPathRules), 0o644); err != nil {
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
	if counts["js-insecure-cookie"] != 2 {
		t.Errorf("expected 2 js-insecure-cookie issues (httpOnly + secure), got %d: %+v", counts["js-insecure-cookie"], issues)
	}
	if counts["js-path-traversal"] != 1 {
		t.Errorf("expected 1 js-path-traversal issue, got %d: %+v", counts["js-path-traversal"], issues)
	}
}

const jsCookieMissingFlagsRules = `function handler(req, res) {
  res.cookie('id', 'v');
  res.cookie('id2', 'v2', { maxAge: 1000 });
  res.cookie('id3', 'v3', { httpOnly: true, secure: true });
}
`

func TestJSScanFindsCookieMissingFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app4.js"), []byte(jsCookieMissingFlagsRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "js-cookie-missing-flags" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 js-cookie-missing-flags issues (1 for no-options call, 2 for the partial-options call), got %d: %+v", count, issues)
	}
}

const jsWeakCipherRules = `function enc() {
  const c1 = crypto.createCipheriv('des-ede3-cbc', key, iv);
  const c2 = crypto.createCipher('rc4', password);
  const c3 = crypto.createCipheriv('aes-128-ecb', key, iv);
  const c4 = crypto.createCipheriv('aes-256-gcm', key, iv);
}
`

func TestJSScanFindsWeakCipher(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cipher.js"), []byte(jsWeakCipherRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "js-weak-cipher" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 js-weak-cipher issues (DES/RC4/ECB, not the AES-GCM call), got %d: %+v", count, issues)
	}
}

const jsYAMLUnsafeLoadRules = `const yaml = require('js-yaml');
function parse(userInput) {
  const a = yaml.load(userInput);
  const b = yaml.load(userInput, { schema: yaml.FAILSAFE_SCHEMA });
}
`

func TestJSScanFindsYAMLUnsafeLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "yaml.js"), []byte(jsYAMLUnsafeLoadRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "js-yaml-unsafe-load" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 js-yaml-unsafe-load issue (the bare load, not the explicit-schema one), got %d: %+v", count, issues)
	}
}
