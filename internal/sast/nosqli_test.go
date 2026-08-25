package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const pyNoSQLiFixture = `from flask import Flask, request

app = Flask(__name__)

@app.route("/go")
def go(collection):
    return collection.find(request.json)

@app.route("/safe")
def safe(collection):
    return collection.find({"email": request.json.get("email")})
`

func TestPythonNoSQLi(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyNoSQLiFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-nosqli" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-nosqli issue (whole-object passthrough, not the safe field-by-field filter), got %d: %+v", count, issues)
	}
}

const jsNoSQLiFixture = `app.post('/go', (req, res) => {
	User.find(req.body).then(u => res.json(u));
});

app.post('/go2', (req, res) => {
	const filter = req.body;
	User.findOne(filter);
});

app.post('/safe', (req, res) => {
	User.find({ email: req.body.email });
});
`

func TestJSNoSQLi(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsNoSQLiFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "js-nosqli" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 js-nosqli issues (direct + through local var, not the safe field-by-field filter), got %d: %+v", count, issues)
	}
}

const phpNoSQLiFixture = `<?php
function go($collection) {
	return $collection->find($_GET);
}

function safe($collection) {
	return $collection->find(['email' => $_GET['email']]);
}
`

func TestPHPNoSQLi(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpNoSQLiFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "php-nosqli" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 php-nosqli issue (whole-array passthrough, not the safe field-by-field filter), got %d: %+v", count, issues)
	}
}
