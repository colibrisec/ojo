package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const goSSTIFixture = `package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func direct(r *http.Request) {
	src := r.URL.Query().Get("tpl")
	t := template.Must(template.New("x").Parse(src))
	_ = t
}

func sprintf(name string) {
	template.New("x").Parse(fmt.Sprintf("Hello {{.%s}}", name))
}

func safe() {
	template.New("x").Parse("Hello {{.Name}}")
}
`

func TestGoSSTI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goSSTIFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "go-ssti" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 go-ssti issues (direct + sprintf, not safe), got %d: %+v", count, issues)
	}
}

const pySSTIFixture = `from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/go")
def go():
    tpl = request.args.get("tpl")
    return render_template_string(tpl)

@app.route("/safe")
def safe():
    return render_template_string("Hello {{ name }}", name=request.args.get("name"))
`

func TestPythonSSTI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pySSTIFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-ssti" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-ssti issue, got %d: %+v", count, issues)
	}
}

const jsSSTIFixture = `const ejs = require('ejs');

app.get('/go', (req, res) => {
	const tpl = req.query.tpl;
	res.send(ejs.render(tpl, {}));
});

app.get('/safe', (req, res) => {
	res.send(ejs.render("Hello <%= name %>", { name: req.query.name }));
});
`

func TestJSSSTI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsSSTIFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "js-ssti" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 js-ssti issue, got %d: %+v", count, issues)
	}
}

const rubySSTIFixture = `class Renderer
  def go
    tpl = params[:tpl]
    ERB.new(tpl).result
  end

  def safe
    ERB.new("Hello <%= name %>").result(binding)
  end
end
`

func TestRubySSTI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubySSTIFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-ssti" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 ruby-ssti issue, got %d: %+v", count, issues)
	}
}
