package sast

import (
	"os"
	"path/filepath"
	"testing"
)

// Parity check with taint_test.go's Go coverage: the same "request data
// hidden behind one local variable" shape, once per tree-sitter-backed
// language, wired into whichever rules structurally support it (see
// TODO.md's phase-1 note on which sink rules gained taint tracking and
// why command-injection didn't for every language).

const pyTaintFixture = `from flask import Flask, request
import os
import subprocess

app = Flask(__name__)

@app.route("/go")
def go():
    next_url = request.args.get("next")
    return redirect(next_url)

@app.route("/file")
def read():
    name = request.args.get("name")
    return open(name)

def query(db):
    id = request.args.get("id")
    db.execute(id)

def env_redirect():
    target = os.getenv("REDIRECT_TARGET")
    return redirect(target)
`

func TestPythonTaintTrackingThroughLocalVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyTaintFixture), 0o644); err != nil {
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
	want := map[string]int{"py-open-redirect": 2, "py-path-traversal": 1, "py-sql-injection": 1}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
	}
}

const jsTaintFixture = `const express = require('express');
const app = express();

app.get('/go', (req, res) => {
	const next = req.query.next;
	res.redirect(next);
});

app.get('/file', (req, res) => {
	const name = req.query.name;
	fs.readFile(name, cb);
});

app.get('/cmd', (req, res) => {
	const arg = req.query.arg;
	child_process.exec(arg);
});

app.get('/sql', (req, res) => {
	const id = req.query.id;
	db.query(id);
});
`

func TestJSTaintTrackingThroughLocalVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsTaintFixture), 0o644); err != nil {
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
	want := map[string]int{"js-open-redirect": 1, "js-path-traversal": 1, "js-command-injection": 1, "js-sql-injection": 1}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
	}
}

const phpTaintFixture = `<?php
function runCmd() {
	$arg = $_GET['arg'];
	system($arg);
}

function runQuery($db) {
	$id = $_POST['id'];
	$db->query($id);
}
`

func TestPHPTaintTrackingThroughLocalVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpTaintFixture), 0o644); err != nil {
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
	want := map[string]int{"php-command-injection": 1, "php-sql-injection": 1}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
	}
}

const rubyTaintFixture = `class PagesController
  def go
    next_url = params[:next]
    redirect_to next_url
  end

  def read
    name = params[:name]
    File.open(name)
  end

  def run_cmd
    arg = params[:arg]
    system(arg)
  end

  def run_query
    id = params[:id]
    Model.where(id)
  end
end
`

func TestRubyTaintTrackingThroughLocalVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubyTaintFixture), 0o644); err != nil {
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
	want := map[string]int{"ruby-open-redirect": 1, "ruby-path-traversal": 1, "ruby-command-injection": 1, "ruby-sql-injection": 1}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
	}
}

const javaTaintFixture = `import javax.servlet.http.*;
import java.io.*;
import java.sql.*;

class Handler {
	void redirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String next = request.getParameter("next");
		response.sendRedirect(next);
	}

	void readFile(HttpServletRequest request) throws IOException {
		String name = request.getParameter("name");
		new File(name);
	}

	void runCmd(HttpServletRequest request) throws IOException {
		String arg = request.getParameter("arg");
		Runtime.getRuntime().exec(arg);
	}

	void runQuery(HttpServletRequest request, Statement st) throws SQLException {
		String id = request.getParameter("id");
		st.executeQuery(id);
	}
}
`

func TestJavaTaintTrackingThroughLocalVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Handler.java"), []byte(javaTaintFixture), 0o644); err != nil {
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
	want := map[string]int{"java-open-redirect": 1, "java-path-traversal": 1, "java-command-injection": 1, "java-sql-injection": 1}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
	}
}
