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
