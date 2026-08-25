package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const rubySendFixture = `class Widget
  def unsafe
    method_name = params[:method]
    send(method_name)
  end

  def safe
    send(:calculate)
  end
end
`

func TestRubyUnsafeReflection(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "widget.rb"), []byte(rubySendFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-unsafe-reflection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 ruby-unsafe-reflection issue (tainted method name, not the literal :calculate symbol), got %d: %+v", count, issues)
	}
}

const phpCallUserFuncFixture = `<?php
function unsafe() {
	$fn = $_GET['fn'];
	call_user_func($fn);
}

function safe() {
	call_user_func('strtolower', 'X');
}
`

func TestPHPUnsafeReflection(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpCallUserFuncFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "php-unsafe-reflection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 php-unsafe-reflection issue, got %d: %+v", count, issues)
	}
}

const javaClassForNameFixture = `import javax.servlet.http.HttpServletRequest;

class C {
	void unsafe(HttpServletRequest request) throws ClassNotFoundException {
		String className = request.getParameter("class");
		Class.forName(className);
	}

	void safe() throws ClassNotFoundException {
		Class.forName("com.example.Widget");
	}
}
`

func TestJavaUnsafeReflection(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "C.java"), []byte(javaClassForNameFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "java-unsafe-reflection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 java-unsafe-reflection issue, got %d: %+v", count, issues)
	}
}

const jsRequireFixture = `app.get('/go', (req, res) => {
	const mod = req.query.module;
	require(mod);
});

require('./plugins/known-plugin');
`

func TestJSUnsafeReflection(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsRequireFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "js-unsafe-reflection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 js-unsafe-reflection issue, got %d: %+v", count, issues)
	}
}

const pyImportModuleFixture = `import importlib
from flask import request

def unsafe():
    mod = request.args.get("module")
    return importlib.import_module(mod)

def safe():
    return importlib.import_module("json")
`

func TestPythonUnsafeReflection(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyImportModuleFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-unsafe-reflection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-unsafe-reflection issue, got %d: %+v", count, issues)
	}
}
