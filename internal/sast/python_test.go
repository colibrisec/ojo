package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const pyVulnerable = `import os
import subprocess
import hashlib
import pickle
import yaml
import ssl
import requests
from flask import Flask
from jinja2 import Environment

api_token = "sk_super_secret_value_123"

app = Flask(__name__)

def run(user_input, db):
    os.system("echo " + user_input)
    subprocess.run(user_input, shell=True)
    db.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    eval(user_input)
    hashlib.md5(b"x")
    pickle.loads(user_input)
    yaml.load(user_input)
    requests.get("https://example.com", verify=False)
    ssl._create_unverified_context()

def generate_session_token():
    import random
    return random.choice("abcdef")

app.run(debug=True)
Environment(autoescape=False)
`

const pyClean = `import subprocess

def run():
    subprocess.run(["ls", "-la"])
`

func TestPythonScanFindsVulnerablePatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyVulnerable), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"py-hardcoded-secret":            false,
		"py-eval-exec":                   false,
		"py-command-injection":           false,
		"py-sql-injection":               false,
		"py-weak-hash":                   false,
		"py-pickle-deserialization":      false,
		"py-yaml-unsafe-load":            false,
		"py-insecure-random-for-secrets": false,
		"py-tls-verify-disabled":         false,
		"py-flask-debug-enabled":         false,
		"py-jinja2-autoescape-disabled":  false,
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

func TestPythonScanNoFalsePositiveOnLiteralCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyClean), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for a literal subprocess.run call, got: %+v", issues)
	}
}

func TestPythonSQLInjectionViaDotFormat(t *testing.T) {
	dir := t.TempDir()
	src := "def run(db, user_input):\n    db.execute(\"SELECT * FROM t WHERE id={}\".format(user_input))\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.RuleID == "py-sql-injection" {
			return
		}
	}
	t.Errorf("expected py-sql-injection to fire for .format(...) query, got: %+v", issues)
}
