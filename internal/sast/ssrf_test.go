package sast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One fixture per language: a dynamic/tainted URL (should fire) and a
// literal/allowlisted URL (should not), covering every ssrf sink wired up
// for that language.

const goSSRFFixture = `package main

import (
	"fmt"
	"net/http"
	"net/url"
)

type client struct{ baseURL string }

func direct(r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Get(target)
}

func request(r *http.Request) {
	target := r.URL.Query().Get("url")
	http.NewRequest("GET", target, nil)
}

func sprintfHostFromInput(r *http.Request) {
	http.Get(fmt.Sprintf("%s/healthz", r.FormValue("base")))
}

func hostConcat(r *http.Request) {
	http.Get("https://" + r.FormValue("host") + "/x")
}

func parsed(r *http.Request) {
	u, _ := url.Parse(r.FormValue("u"))
	http.Get(u.String())
}

func sprintf(r *http.Request) {
	id := r.URL.Query().Get("id")
	http.Get(fmt.Sprintf("https://internal/%s", id))
}

func (c *client) configBase(r *http.Request) {
	http.Get(c.baseURL + "/items/" + r.FormValue("id"))
}

func (c *client) configOnly(path string) {
	http.Get(c.baseURL + path)
}

func safe() {
	http.Get("https://example.com/healthz")
}
`

// TestGoSSRF pins the three-way split: HIGH when input can choose the
// host, LOW when only the path, nothing when no request data is involved.
func TestGoSSRF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goSSRFFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]string{}
	for _, i := range issues {
		if i.RuleID == "go-ssrf" {
			got[i.Line] = i.Severity
		}
	}
	want := map[int]string{
		13: "HIGH", // direct
		18: "HIGH", // request
		22: "HIGH", // Sprintf("%s/...")
		26: "HIGH", // "https://" + host
		31: "HIGH", // url.Parse(input)
		36: "LOW",  // Sprintf("https://internal/%s", id)
		40: "LOW",  // c.baseURL + "/items/" + id
	}
	if len(got) != len(want) {
		t.Errorf("got %d go-ssrf findings, want %d: %v", len(got), len(want), got)
	}
	for line, sev := range want {
		if got[line] != sev {
			t.Errorf("line %d: got %q, want %s (all: %v)", line, got[line], sev, got)
		}
	}
	for _, i := range issues {
		if i.RuleID == "go-ssrf" && i.Line == 36 && !strings.Contains(i.Message, "host is fixed, but request input chooses the path or query") {
			t.Errorf("LOW message should say the host is fixed: %q", i.Message)
		}
	}
}

const pySSRFFixture = `import requests
from flask import request

def fetch():
    target = request.args.get("url")
    requests.get(target)

def safe():
    requests.get("https://example.com/healthz")
`

func TestPythonSSRF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pySSRFFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-ssrf" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-ssrf issue, got %d: %+v", count, issues)
	}
}

const jsSSRFFixture = `const axios = require('axios');

app.get('/fetch', (req, res) => {
	const target = req.query.url;
	fetch(target);
});

app.get('/axios', (req, res) => {
	const target = req.query.url;
	axios.get(target);
});

app.get('/safe', (req, res) => {
	fetch("https://example.com/healthz");
});
`

func TestJSSSRF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsSSRFFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "js-ssrf" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 js-ssrf issues (fetch + axios, not safe), got %d: %+v", count, issues)
	}
}

const phpSSRFFixture = `<?php
function fetchIt() {
	$url = $_GET['url'];
	file_get_contents($url);
}

function curlIt($ch) {
	$url = $_GET['url'];
	curl_setopt($ch, CURLOPT_URL, $url);
}

function safe() {
	file_get_contents("https://example.com/healthz");
}
`

func TestPHPSSRF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpSSRFFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "php-ssrf" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 php-ssrf issues (file_get_contents + curl_setopt), got %d: %+v", count, issues)
	}
}

const rubySSRFFixture = `class Fetcher
  def net_http
    target = params[:url]
    Net::HTTP.get(target)
  end

  def uri_open
    target = params[:url]
    URI.open(target)
  end

  def safe
    Net::HTTP.get("https://example.com/healthz")
  end
end
`

func TestRubySSRF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubySSRFFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-ssrf" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 ruby-ssrf issues (Net::HTTP.get + URI.open), got %d: %+v", count, issues)
	}
}

const javaSSRFFixture = `import javax.servlet.http.*;
import java.net.URL;
import java.io.IOException;

class Fetcher {
	void fetch(HttpServletRequest request) throws IOException {
		String target = request.getParameter("url");
		new URL(target);
	}

	void safe() throws IOException {
		new URL("https://example.com/healthz");
	}
}
`

func TestJavaSSRF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Fetcher.java"), []byte(javaSSRFFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "java-ssrf" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 java-ssrf issue, got %d: %+v", count, issues)
	}
}

// TestSSRFSeveritySplit checks the HIGH/LOW/none split in each tree-sitter
// language: request input choosing the host, only the path, or nothing.
func TestSSRFSeveritySplit(t *testing.T) {
	cases := []struct {
		name, file, rule, code, want string
	}{
		{"py host", "a.py", "py-ssrf", "import requests\nfrom flask import request\ndef f():\n    requests.get(f\"https://{request.args['h']}/x\")\n", "HIGH"},
		{"py path", "a.py", "py-ssrf", "import requests\nfrom flask import request\ndef f():\n    p = request.args['p']\n    requests.get(\"https://api.internal/items/\" + p)\n", "LOW"},
		{"py config", "a.py", "py-ssrf", "import requests\nBASE = 'https://api.internal'\ndef f(path):\n    requests.get(f\"{BASE}/{path}\")\n", ""},
		{"php host", "a.php", "php-ssrf", "<?php\nfunction f() {\n  file_get_contents(\"https://\" . $_GET['h'] . \"/x\");\n}\n", "HIGH"},
		{"php path", "a.php", "php-ssrf", "<?php\nfunction f() {\n  $id = $_GET['id'];\n  file_get_contents(\"https://api.internal/items/$id\");\n}\n", "LOW"},
		{"php config", "a.php", "php-ssrf", "<?php\nfunction f($base, $p) {\n  file_get_contents($base . $p);\n}\n", ""},
		{"ruby host", "a.rb", "ruby-ssrf", "def f\n  Net::HTTP.get(\"https://#{params[:h]}/x\")\nend\n", "HIGH"},
		{"ruby path", "a.rb", "ruby-ssrf", "def f\n  id = params[:id]\n  Net::HTTP.get(\"https://api.internal/items/#{id}\")\nend\n", "LOW"},
		{"ruby config", "a.rb", "ruby-ssrf", "def f(base, path)\n  Net::HTTP.get(base + path)\nend\n", ""},
		{"java host", "A.java", "java-ssrf", "import javax.servlet.http.*;\nimport java.net.URL;\nclass A {\n  void f(HttpServletRequest request) throws Exception {\n    new URL(\"https://\" + request.getParameter(\"h\") + \"/x\");\n  }\n}\n", "HIGH"},
		{"java path", "A.java", "java-ssrf", "import javax.servlet.http.*;\nimport java.net.URL;\nclass A {\n  void f(HttpServletRequest request) throws Exception {\n    String id = request.getParameter(\"id\");\n    new URL(\"https://api.internal/items/\" + id);\n  }\n}\n", "LOW"},
		{"java config", "A.java", "java-ssrf", "import java.net.URL;\nclass A {\n  String base;\n  void f(String path) throws Exception {\n    new URL(base + path);\n  }\n}\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.code), 0o644); err != nil {
				t.Fatal(err)
			}
			issues, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, i := range issues {
				if i.RuleID == c.rule {
					got = append(got, i.Severity)
				}
			}
			switch {
			case c.want == "" && len(got) > 0:
				t.Errorf("want no %s finding, got %v", c.rule, got)
			case c.want != "" && (len(got) != 1 || got[0] != c.want):
				t.Errorf("want one %s %s finding, got %v", c.want, c.rule, got)
			}
		})
	}
}
