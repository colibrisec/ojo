package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const rubyVulnerable = `api_token = "sk_super_secret_value_123"

def run(user_input)
  eval(user_input)
  system("echo " + user_input)
  ` + "`echo #{user_input}`" + `
  User.where("name = '#{user_input}'")
  Digest::MD5.hexdigest(user_input)
  Marshal.load(user_input)
  YAML.load(user_input)
  ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
  params.permit!
  redirect_to params[:url]
end

def generate_session_token
  rand(1000)
end
`

const rubyClean = `def run
  system("ls", "-la")
end
`

func TestRubyScanFindsVulnerablePatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubyVulnerable), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"ruby-hardcoded-secret":            false,
		"ruby-eval-detected":               false,
		"ruby-command-injection":           false,
		"ruby-sql-injection":               false,
		"ruby-weak-hash":                   false,
		"ruby-insecure-deserialization":    false,
		"ruby-insecure-random-for-secrets": false,
		"ruby-tls-verify-disabled":         false,
		"ruby-mass-assignment":             false,
		"ruby-open-redirect":               false,
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

func TestRubyScanNoFalsePositiveOnLiteralCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubyClean), 0o644); err != nil {
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

func TestRubySQLInjectionViaStringInterpolation(t *testing.T) {
	dir := t.TempDir()
	src := "def run(user_input)\n  User.where(\"name = '#{user_input}'\")\nend\n"
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.RuleID == "ruby-sql-injection" {
			return
		}
	}
	t.Errorf("expected ruby-sql-injection to fire for an interpolated .where(...) query, got: %+v", issues)
}

const rubyNewRules = `class GoController
  def go
    redirect_to params[:next]
  end

  def safe
    redirect_to "/home"
  end

  def set_cors
    headers['Access-Control-Allow-Origin'] = '*'
    headers['Content-Type'] = 'application/json'
  end

  def token
    JWT.encode(payload, key, 'none')
  end

  ALG = {alg: 'none'}
end
`

func TestRubyScanFindsNewRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app2.rb"), []byte(rubyNewRules), 0o644); err != nil {
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
	if counts["ruby-cors-wildcard"] != 1 {
		t.Errorf("expected 1 ruby-cors-wildcard issue, got %d: %+v", counts["ruby-cors-wildcard"], issues)
	}
	if counts["ruby-jwt-none-algorithm"] != 2 {
		t.Errorf("expected 2 ruby-jwt-none-algorithm issues (JWT.encode + alg: 'none' hash), got %d: %+v", counts["ruby-jwt-none-algorithm"], issues)
	}
}

const rubyCookieAndPathRules = `class GoController
  def set_cookie
    cookies[:session] = { value: 'tok', secure: false, httponly: false }
  end

  def read(params)
    File.open(params[:path])
  end

  def read_safe
    File.open("/safe/path")
  end
end
`

func TestRubyScanFindsCookieAndPathTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app3.rb"), []byte(rubyCookieAndPathRules), 0o644); err != nil {
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
	if counts["ruby-insecure-cookie"] != 2 {
		t.Errorf("expected 2 ruby-insecure-cookie issues (secure + httponly), got %d: %+v", counts["ruby-insecure-cookie"], issues)
	}
	if counts["ruby-path-traversal"] != 1 {
		t.Errorf("expected 1 ruby-path-traversal issue, got %d: %+v", counts["ruby-path-traversal"], issues)
	}
}

const rubyCookieMissingFlagsRules = `class GoController
  def go
    cookies[:session] = "plain-value"
  end

  def partial
    cookies[:session2] = { value: 'tok', expires: 1.hour }
  end

  def hardened
    cookies[:session3] = { value: 'tok', secure: true, httponly: true }
  end
end
`

func TestRubyScanFindsCookieMissingFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app4.rb"), []byte(rubyCookieMissingFlagsRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-cookie-missing-flags" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 ruby-cookie-missing-flags issues (1 for plain-value assign, 2 for the partial hash), got %d: %+v", count, issues)
	}
}

const rubyWeakCipherRules = `
c1 = OpenSSL::Cipher.new('DES-EDE3-CBC')
c2 = OpenSSL::Cipher.new('AES-128-ECB')
c3 = OpenSSL::Cipher.new('aes-256-gcm')
`

func TestRubyScanFindsWeakCipher(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cipher.rb"), []byte(rubyWeakCipherRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-weak-cipher" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 ruby-weak-cipher issues (DES + ECB, not the AES-GCM call), got %d: %+v", count, issues)
	}
}

const rubyReliabilityRules = `
def a(x)
  begin
    f()
  rescue => e
  end
  begin
    f()
  rescue => e
    log(e)
  end
  if x
  end
  if x
  else
  end
  while x
  end
  if x
    return
    y()
  end
end
`

func TestRubyScanFindsReliabilityRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "reliability.rb"), []byte(rubyReliabilityRules), 0o644); err != nil {
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
	if counts["ruby-empty-exception-handler"] != 1 {
		t.Errorf("expected 1 ruby-empty-exception-handler issue (not the rescue that logs), got %d: %+v", counts["ruby-empty-exception-handler"], issues)
	}
	if counts["ruby-empty-block"] != 4 {
		t.Errorf("expected 4 ruby-empty-block issues (2 empty ifs + 1 empty else + 1 empty while), got %d: %+v", counts["ruby-empty-block"], issues)
	}
	if counts["ruby-unreachable-code"] != 1 {
		t.Errorf("expected 1 ruby-unreachable-code issue, got %d: %+v", counts["ruby-unreachable-code"], issues)
	}
}
