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

const phpWeakCipherRules = `<?php
$c1 = openssl_encrypt($data, 'des-ede3-cbc', $key);
$c2 = openssl_encrypt($data, 'aes-128-ecb', $key);
$c3 = openssl_encrypt($data, 'aes-256-gcm', $key);
`

func TestPHPScanFindsWeakCipher(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cipher.php"), []byte(phpWeakCipherRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "php-weak-cipher" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 php-weak-cipher issues (DES + ECB, not the AES-GCM call), got %d: %+v", count, issues)
	}
}

const phpMassAssignmentRules = `<?php
User::create($request->all());
$user->fill($request->all());
$user->update($request->all());
User::create(['name' => $request->input('name')]);
$user->fill($safeArray);
`

func TestPHPScanFindsMassAssignment(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mass.php"), []byte(phpMassAssignmentRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "php-mass-assignment" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 php-mass-assignment issues (create/fill/update via $request->all(), not the allowlisted or safe-array calls), got %d: %+v", count, issues)
	}
}

const phpReliabilityRules = `<?php
function a() {
  try { f(); } catch (Exception $e) { }
  try { f(); } catch (Exception $e) { log($e); }
  if ($x) { }
  if ($x) { } else { }
  while ($x) { }
  for ($i=0;$i<3;$i++) { }
  if ($x) { return; y(); }
}
`

func TestPHPScanFindsReliabilityRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "reliability.php"), []byte(phpReliabilityRules), 0o644); err != nil {
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
	if counts["php-empty-exception-handler"] != 1 {
		t.Errorf("expected 1 php-empty-exception-handler issue (not the catch that logs), got %d: %+v", counts["php-empty-exception-handler"], issues)
	}
	if counts["php-empty-block"] != 5 {
		t.Errorf("expected 5 php-empty-block issues (empty if, empty if+else=2, empty while, empty for), got %d: %+v", counts["php-empty-block"], issues)
	}
	if counts["php-unreachable-code"] != 1 {
		t.Errorf("expected 1 php-unreachable-code issue, got %d: %+v", counts["php-unreachable-code"], issues)
	}
}
