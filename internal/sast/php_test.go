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
