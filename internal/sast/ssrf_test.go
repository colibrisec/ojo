package sast

import (
	"os"
	"path/filepath"
	"testing"
)

// One fixture per language: a dynamic/tainted URL (should fire) and a
// literal/allowlisted URL (should not), covering every ssrf sink wired up
// for that language.

const goSSRFFixture = `package main

import (
	"fmt"
	"net/http"
)

func direct(r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Get(target)
}

func request(r *http.Request) {
	target := r.URL.Query().Get("url")
	http.NewRequest("GET", target, nil)
}

func sprintf(id string) {
	http.Get(fmt.Sprintf("https://internal/%s", id))
}

func safe() {
	http.Get("https://example.com/healthz")
}
`

func TestGoSSRF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goSSRFFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "go-ssrf" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 go-ssrf issues (direct/request/sprintf, not safe), got %d: %+v", count, issues)
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
