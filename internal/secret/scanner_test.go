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
