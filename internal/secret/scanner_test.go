package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan(t *testing.T) {
	dir := t.TempDir()
	content := "aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n" +
		"db_url = \"postgres://admin:hunter2pass@db.internal:5432/prod\"\n" +
		"note = \"just a normal comment, nothing secret here\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	rules := map[string]bool{"aws-access-key-id": false, "db-connection-string": false}
	for _, i := range issues {
		if _, ok := rules[i.RuleID]; ok {
			rules[i.RuleID] = true
		}
	}
	for id, found := range rules {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
	if len(issues) != 2 {
		t.Errorf("expected exactly 2 issues (no false positive on the plain comment line), got %d: %+v", len(issues), issues)
	}
}

func TestScan_TestFileExclusion(t *testing.T) {
	t.Run("suppresses placeholder secret in a _test.go file", func(t *testing.T) {
		dir := t.TempDir()
		content := "aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n" +
			"db_url = \"postgres://admin:hunter2pass@db.internal:5432/prod\"\n"
		if err := os.WriteFile(filepath.Join(dir, "auth_test.go"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		issues, err := Scan(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(issues) != 0 {
			t.Errorf("expected placeholder secrets in a test file to be suppressed, got %d issues: %+v", len(issues), issues)
		}
	})

	t.Run("still flags a real-looking secret in a _test.go file", func(t *testing.T) {
		dir := t.TempDir()
		content := "awsKey = \"AKIAJ7QZX9K3M2NPLW4B\"\n"
		if err := os.WriteFile(filepath.Join(dir, "auth_test.go"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		issues, err := Scan(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(issues) != 1 || issues[0].RuleID != "aws-access-key-id" {
			t.Errorf("expected exactly 1 aws-access-key-id issue (real-looking secret must not be suppressed), got %+v", issues)
		}
	})
}

func TestIsLikelyTestFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"internal/secret/scanner_test.go", true},
		{`internal\secret\scanner_test.go`, true},
		{"foo.spec.ts", true},
		{"foo.test.js", true},
		{"testdata/fixture.json", true},
		{"fixtures/sample.env", true},
		{"__tests__/foo.js", true},
		{"mocks/client.go", true},
		{"internal/latest/foo.go", false},
		{"internal/contest/foo.go", false},
		{"config.py", false},
		{"internal/secret/scanner.go", false},
	}
	for _, c := range cases {
		if got := isLikelyTestFile(c.path); got != c.want {
			t.Errorf("isLikelyTestFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestLooksLikePlaceholder(t *testing.T) {
	cases := []struct {
		secret string
		want   bool
	}{
		{"AKIAABCDEFGHIJKLMNOP", true},          // sequential run
		{"00000000", true},                      // repeated run
		{"sk_live_example12345678901234", true}, // marker word
		{"hunter2pass", true},                   // marker word
		{"AKIAJ7QZX9K3M2NPLW4B", false},         // no marker, no run
	}
	for _, c := range cases {
		if got := looksLikePlaceholder(c.secret); got != c.want {
			t.Errorf("looksLikePlaceholder(%q) = %v, want %v", c.secret, got, c.want)
		}
	}
}
