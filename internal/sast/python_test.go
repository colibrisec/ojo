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

const pyNewRules = `from flask import Flask, request, redirect
import jwt

app = Flask(__name__)

@app.route("/go")
def go():
    return redirect(request.args.get("next"))

@app.route("/safe")
def safe():
    return redirect("/home")

def check(token):
    return jwt.decode(token, "key", verify=False)

def set_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Content-Type'] = 'application/json'
    return response
`

func TestPythonScanFindsNewRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app2.py"), []byte(pyNewRules), 0o644); err != nil {
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
	if counts["py-open-redirect"] != 1 {
		t.Errorf("expected 1 py-open-redirect issue, got %d: %+v", counts["py-open-redirect"], issues)
	}
	if counts["py-jwt-verify-disabled"] != 1 {
		t.Errorf("expected 1 py-jwt-verify-disabled issue, got %d: %+v", counts["py-jwt-verify-disabled"], issues)
	}
	if counts["py-cors-wildcard"] != 1 {
		t.Errorf("expected 1 py-cors-wildcard issue, got %d: %+v", counts["py-cors-wildcard"], issues)
	}
}

const pyCookieAndPathRules = `def set_cookie(response, token):
    response.set_cookie("session", token, secure=False, httponly=False)
    response.set_cookie("theme", "dark", secure=True)

def read(request):
    return open(request.args.get("path"))

def read_safe():
    return open("/safe/path")
`

func TestPythonScanFindsCookieAndPathTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app3.py"), []byte(pyCookieAndPathRules), 0o644); err != nil {
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
	if counts["py-insecure-cookie"] != 2 {
		t.Errorf("expected 2 py-insecure-cookie issues (secure + httponly), got %d: %+v", counts["py-insecure-cookie"], issues)
	}
	if counts["py-path-traversal"] != 1 {
		t.Errorf("expected 1 py-path-traversal issue, got %d: %+v", counts["py-path-traversal"], issues)
	}
}

const pyCookieMissingFlagsRules = `def go(response, token):
    response.set_cookie("session", token)
    response.set_cookie("theme", "dark", secure=True, httponly=True)
`

func TestPythonScanFindsCookieMissingFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app4.py"), []byte(pyCookieMissingFlagsRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "py-cookie-missing-flags" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 py-cookie-missing-flags issues (secure + httponly missing on the first call only), got %d: %+v", count, issues)
	}
}
