package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const phpVulnerable = `<?php

$apiToken = "sk_super_secret_value_123";

function run($userInput, $conn) {
    eval($userInput);
    system("echo " . $userInput);
    $conn->query("SELECT * FROM users WHERE name = '" . $userInput . "'");
    md5($userInput);
    unserialize($userInput);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    include $userInput;
    preg_replace('/foo/e', 'bar', $userInput);
}

function generateSessionToken() {
    return mt_rand();
}
`

const phpClean = `<?php

function run() {
    system("ls -la");
}
`

func TestPHPScanFindsVulnerablePatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpVulnerable), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"php-hardcoded-secret":            false,
		"php-eval-detected":               false,
		"php-command-injection":           false,
		"php-sql-injection":               false,
		"php-weak-hash":                   false,
		"php-insecure-deserialization":    false,
		"php-insecure-random-for-secrets": false,
		"php-tls-verify-disabled":         false,
		"php-lfi-include":                 false,
		"php-preg-replace-eval-modifier":  false,
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

func TestPHPScanNoFalsePositiveOnLiteralCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpClean), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for a literal system() call, got: %+v", issues)
	}
}

const phpNewRules = `<?php

function go($userInput) {
    header("Location: " . $userInput);
    header("Location: /home");
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json");
    JWT::decode($token, $key, ['alg' => 'none']);
}
`

func TestPHPScanFindsNewRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app2.php"), []byte(phpNewRules), 0o644); err != nil {
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
	if counts["php-open-redirect"] != 1 {
		t.Errorf("expected 1 php-open-redirect issue, got %d: %+v", counts["php-open-redirect"], issues)
	}
	if counts["php-cors-wildcard"] != 1 {
		t.Errorf("expected 1 php-cors-wildcard issue, got %d: %+v", counts["php-cors-wildcard"], issues)
	}
	if counts["php-jwt-none-algorithm"] != 1 {
		t.Errorf("expected 1 php-jwt-none-algorithm issue, got %d: %+v", counts["php-jwt-none-algorithm"], issues)
	}
}

const phpCookieRules = `<?php

function go() {
    setcookie("session", "tok", ['secure' => false, 'httponly' => false]);
    setcookie("theme", "dark", ['secure' => true]);
}
`

func TestPHPScanFindsInsecureCookie(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app3.php"), []byte(phpCookieRules), 0o644); err != nil {
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
	if counts["php-insecure-cookie"] != 2 {
		t.Errorf("expected 2 php-insecure-cookie issues (secure + httponly), got %d: %+v", counts["php-insecure-cookie"], issues)
	}
}

const phpCookieMissingFlagsRules = `<?php

function go() {
    setcookie("session", "tok");
    setcookie("session2", "tok2", ['path' => '/']);
    setcookie("session3", "tok3", ['secure' => true, 'httponly' => true]);
    setcookie("legacy", "tok4", 0, "/", "", true);
    setcookie("legacy2", "tok5", 0, "/", "", true, true);
}
`

func TestPHPScanFindsCookieMissingFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app4.php"), []byte(phpCookieMissingFlagsRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "php-cookie-missing-flags" {
			count++
		}
	}
	// setcookie("session", ...): <6 args -> 1 combined issue
	// setcookie("session2", ..., ['path'=>'/']): options array missing both -> 2 issues
	// setcookie("session3", ...): options array has both -> 0
	// setcookie("legacy", ..., true): 6 positional args (secure passed, httponly missing) -> 1 issue
	// setcookie("legacy2", ..., true, true): 7 positional args -> 0
	if count != 4 {
		t.Errorf("expected 4 php-cookie-missing-flags issues, got %d: %+v", count, issues)
	}
}
