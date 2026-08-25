package sast

import (
	"os"
	"path/filepath"
	"testing"
)

// Extra command-injection sinks added alongside the existing os.system /
// subprocess(shell=True) / system / exec / spawn / child_process.exec
// coverage: Python's os.popen, Ruby's IO.popen, and JS's spawn/execFile
// with { shell: true }.

const pyPopenFixture = `import os

def run():
    return os.popen("ls -la")
`

func TestPythonCommandInjectionPopen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyPopenFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-command-injection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-command-injection issue for os.popen, got %d: %+v", count, issues)
	}
}

const rubyPopenFixture = `class Runner
  def go
    cmd = params[:cmd]
    IO.popen(cmd)
  end

  def safe
    IO.popen("ls -la")
  end
end
`

func TestRubyCommandInjectionPopen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubyPopenFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-command-injection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 ruby-command-injection issue for IO.popen (tainted, not literal), got %d: %+v", count, issues)
	}
}

const jsSpawnShellFixture = `const child_process = require('child_process');

child_process.spawn("ls", ["-la"], { shell: true });

child_process.execFile("ls", ["-la"], { shell: true });

child_process.spawn("ls", ["-la"]);
`

func TestJSCommandInjectionSpawnShell(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsSpawnShellFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "js-command-injection" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 js-command-injection issues (spawn + execFile with shell: true, not the plain spawn), got %d: %+v", count, issues)
	}
}
