package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRules_EmptyPathIsNotAnError(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil || rules != nil {
		t.Errorf("expected no rules and no error for an empty path, got %+v, err=%v", rules, err)
	}
}

func TestLoadRules_ParsesAndCompiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	content := "rules:\n  - id: internal-token\n    description: Internal service token\n    regex: \"itok_[A-Za-z0-9]{20}\"\n    severity: HIGH\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "internal-token" || rules[0].compiled == nil {
		t.Errorf("expected 1 compiled rule, got %+v", rules)
	}
}

func TestLoadRules_BadRegexIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	content := "rules:\n  - id: bad\n    regex: \"[unclosed\"\n    severity: HIGH\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(path); err == nil {
		t.Error("expected an error for an invalid regex")
	}
}

func TestLoadRules_UnknownFieldIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	content := "rules:\n  - id: bad\n    regex: \"x\"\n    severity: HIGH\n    typo: oops\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(path); err == nil {
		t.Error("expected an error for an unrecognized field")
	}
}

func TestMergeRules_DuplicateIDIsAnError(t *testing.T) {
	base := []Rule{{ID: "aws-access-key-id"}}
	if _, err := mergeRules(base, []Rule{{ID: "aws-access-key-id"}}); err == nil {
		t.Error("expected an error when a custom rule id collides with a default one")
	}
}

func TestScan_CustomRuleFiresAlongsideDefaults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("token = \"itok_ABCDEFGHIJ0123456789\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	content := "rules:\n  - id: internal-token\n    description: Internal service token\n    regex: \"itok_[A-Za-z0-9]{20}\"\n    severity: HIGH\n"
	if err := os.WriteFile(rulesPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	extra, err := LoadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir, extra)
	if err != nil {
		t.Fatal(err)
	}
	var fired bool
	for _, i := range issues {
		if i.RuleID == "internal-token" {
			fired = true
		}
	}
	if !fired {
		t.Errorf("expected the custom rule to fire alongside the defaults, got %+v", issues)
	}
}
