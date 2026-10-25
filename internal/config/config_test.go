package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_DefaultMissingIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	c, err := Load("")
	if err != nil {
		t.Fatalf("expected no error for a missing default .ojo.yaml, got %v", err)
	}
	if c.Scanners != "" || c.Format != "" {
		t.Errorf("expected zero-value Config, got %+v", c)
	}
}

func TestLoad_ExplicitMissingIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected an error for a missing explicit --config path")
	}
}

func TestLoad_ParsesFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojo.yaml")
	if err := os.WriteFile(path, []byte("scanners: vuln,secret\nformat: sarif\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Scanners != "vuln,secret" || c.Format != "sarif" {
		t.Errorf("got %+v", c)
	}
}

func TestLoad_UnknownKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojo.yaml")
	if err := os.WriteFile(path, []byte("scanner: vuln\n"), 0o644); err != nil { // typo: "scanner" not "scanners"
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Error("expected an error for an unrecognized config key")
	}
}

func TestLoad_EmptyFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojo.yaml")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Scanners != "" || c.Format != "" {
		t.Errorf("got %+v", c)
	}
}

func TestLoad_ParsesQualityThresholds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojo.yaml")
	src := "quality:\n  max-function-lines: 80\n  max-parameters: 7\n  max-nesting-depth: 3\n  max-complexity: 15\n  min-duplicate-lines: 10\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Quality{MaxFunctionLines: 80, MaxParameters: 7, MaxNestingDepth: 3, MaxComplexity: 15, MinDuplicateLines: 10}
	if c.Quality != want {
		t.Errorf("got %+v, want %+v", c.Quality, want)
	}
}

func TestLoad_NegativeQualityThresholdIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojo.yaml")
	if err := os.WriteFile(path, []byte("quality:\n  max-complexity: -1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Error("expected an error for a negative quality threshold")
	}
}

func TestLoad_UnknownQualityKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ojo.yaml")
	if err := os.WriteFile(path, []byte("quality:\n  max-complexty: 15\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Error("expected an error for an unrecognized quality key")
	}
}

func TestLoad_License(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ojo.yaml")
	for _, tc := range []struct {
		yaml    string
		wantErr bool
	}{
		{"license:\n  deny: [GPL-3.0-only]\n  exceptions: [foo]\n  unknown: fail\n", false},
		{"license:\n  allow: [MIT]\n  deny: [GPL-3.0-only]\n", true},
		{"license:\n  allow: [MIT]\n  unknown: maybe\n", true},
	} {
		if err := os.WriteFile(path, []byte(tc.yaml), 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: got err %v, wantErr %v", tc.yaml, err, tc.wantErr)
		}
		if err == nil && (len(c.License.Deny) != 1 || c.License.Exceptions[0] != "foo" || c.License.Unknown != "fail") {
			t.Errorf("%q: parsed %+v", tc.yaml, c.License)
		}
	}
}
