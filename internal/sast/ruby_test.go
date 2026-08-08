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
