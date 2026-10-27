package sast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/colibrisec/ojo/internal/fpcorpus"
)

// False-positive regression corpus. Each case is code that was reported and
// triaged as a false positive (source says where), next to a must-fire twin
// so a fix can't pass by switching the rule off.
//
// want is one of fpcorpus.Check's values.
type fpCase struct {
	name   string
	source string
	file   string
	code   string
	rule   string
	want   string
}

var sastFPCorpus = []fpCase{
	{
		name:   "go path from os.Getenv is deployment config",
		source: "triaged false positive",
		file:   "internal/config/file.go",
		rule:   "go-path-traversal",
		want:   "none",
		code: `package config

import "os"

func Load() ([]byte, error) {
	p := os.Getenv("APP_CONFIG")
	if p == "" {
		p = "/etc/app/config.yaml"
	}
	return os.ReadFile(p)
}
`,
	},
	{
		name:   "go path from request still fires",
		source: "twin",
		file:   "internal/config/file.go",
		rule:   "go-path-traversal",
		want:   "fire",
		code: `package config

import (
	"net/http"
	"os"
)

func Load(r *http.Request) ([]byte, error) {
	p := r.URL.Query().Get("config")
	return os.ReadFile(p)
}
`,
	},
	{
		name:   "go ssrf against own httptest server in _test.go",
		source: "triaged false positive",
		file:   "internal/proxy/recon_test.go",
		rule:   "go-ssrf",
		want:   "none",
		code: `package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvents(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
`,
	},
	{
		name:   "go host from request outside tests stays HIGH",
		source: "twin",
		file:   "internal/proxy/recon.go",
		rule:   "go-ssrf",
		want:   "high",
		code: `package proxy

import "net/http"

func fetch(r *http.Request) {
	http.Get(r.FormValue("base") + "/events")
}
`,
	},
	{
		name:   "go configured base URL plus a non-request path",
		source: "triaged false positive",
		file:   "internal/client/client.go",
		rule:   "go-ssrf",
		want:   "none",
		code: `package client

import (
	"context"
	"io"
	"net/http"
)

type Host struct{ baseURL string }

func (h *Host) do(ctx context.Context, method, path string, body io.Reader) {
	http.NewRequestWithContext(ctx, method, h.baseURL+path, body)
	http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/api/graphql", body)
}
`,
	},
	{
		name:   "go configured base URL plus a request path is LOW",
		source: "twin",
		file:   "internal/client/client.go",
		rule:   "go-ssrf",
		want:   "low",
		code: `package client

import "net/http"

type Host struct{ baseURL string }

func (h *Host) proxy(w http.ResponseWriter, r *http.Request) {
	http.Get(h.baseURL + "/repos/" + r.URL.Query().Get("repo"))
}
`,
	},
	{
		name:   "go upload path from auth context and a generated id",
		source: "triaged false positive",
		file:   "handlers/files_handler.go",
		rule:   "go-path-traversal",
		want:   "none",
		code: `package handlers

import (
	"net/http"
	"os"
	"path/filepath"
)

func (h *H) Upload(w http.ResponseWriter, r *http.Request) {
	org := mustOrg(r.Context())
	src, _, _ := r.FormFile("file")
	defer src.Close()
	dir := filepath.Join(h.uploadDir, org.String())
	os.Create(filepath.Join(dir, newID()))
}
`,
	},
	{
		name:   "go path from a method on request data still fires",
		source: "twin",
		file:   "handlers/files_handler.go",
		rule:   "go-path-traversal",
		want:   "fire",
		code: `package handlers

import (
	"net/http"
	"net/url"
	"os"
)

func (h *H) Get(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.FormValue("u"))
	os.Open(u.Path)
}
`,
	},
	{
		name:   "go open redirect fixture inside a test",
		source: "triaged false positive",
		file:   "internal/scan/send_test.go",
		rule:   "go-open-redirect",
		want:   "none",
		code: `package scan

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoFollow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	}))
	defer srv.Close()
}
`,
	},
	{
		name:   "go command from $EDITOR is reported at LOW",
		source: "triaged false positive",
		file:   "editor.go",
		rule:   "go-command-injection",
		want:   "low",
		code: `package editor

import (
	"context"
	"os"
	"os/exec"
)

func open(file string) error {
	editor := os.Getenv("EDITOR")
	return exec.CommandContext(context.TODO(), editor, file).Run()
}
`,
	},
	{
		name:   "go command from request stays HIGH",
		source: "twin",
		file:   "editor.go",
		rule:   "go-command-injection",
		want:   "fire",
		code: `package editor

import (
	"net/http"
	"os/exec"
)

func run(r *http.Request) {
	arg := r.FormValue("arg")
	exec.Command("sh", "-c", arg)
}
`,
	},
	{
		name:   "go redirect to server-configured URL plus generated code",
		source: "triaged false positive",
		file:   "handlers/oidc_handler.go",
		rule:   "go-open-redirect",
		want:   "known",
		code: `package handlers

import "net/http"

type H struct{ ui string }

func (h *H) Callback(w http.ResponseWriter, r *http.Request, xcode string) {
	http.Redirect(w, r, h.ui+"?code="+xcode, http.StatusFound)
}
`,
	},
	{
		name:   "python f-string DDL in pytest conftest",
		source: "triaged false positive",
		file:   "tests/conftest.py",
		rule:   "py-sql-injection",
		want:   "none",
		code: `import uuid

def make_db(conn):
    name = f"test_{uuid.uuid4().hex[:12]}"
    conn.execute(f"CREATE DATABASE {name}")
    return name
`,
	},
	{
		name:   "python f-string SQL in app code still fires",
		source: "twin",
		file:   "api/db.py",
		rule:   "py-sql-injection",
		want:   "fire",
		code: `def make_db(conn, name):
    conn.execute(f"CREATE DATABASE {name}")
`,
	},
	{
		name:   "python trailing comment after return",
		source: "triaged false positive",
		file:   "service.py",
		rule:   "py-unreachable-code",
		want:   "none",
		code: `def encrypt(cipher, value):
    if not cipher:
        return value  # fall back to plain text
    return cipher.encrypt(value)
`,
	},
	{
		name:   "python comment indented under an early return",
		source: "triaged false positive",
		file:   "rag.py",
		rule:   "py-unreachable-code",
		want:   "none",
		code: `def resolve_scope(make, model_name, year):
    if make and model_name and year:
        return make, model_name, year
        # otherwise look it up in the catalog
    row = catalog(make)
    return row
`,
	},
	{
		name:   "python statement after return still fires",
		source: "twin",
		file:   "auth.py",
		rule:   "py-unreachable-code",
		want:   "fire",
		code: `def link(db, user):
    return user
    # dead
    db.insert(user)
`,
	},
	{
		name:   "python narrowly typed except pass",
		source: "triaged false positive",
		file:   "limiter.py",
		rule:   "py-empty-exception-handler",
		want:   "none",
		code: `try:
    from dotenv import load_dotenv
except ImportError:
    pass

def key(token, decode, JWTError):
    try:
        return decode(token)
    except JWTError:
        pass
    return None
`,
	},
	{
		name:   "python bare and broad except pass still fire",
		source: "twin",
		file:   "limiter.py",
		rule:   "py-empty-exception-handler",
		want:   "fire",
		code: `def f(g):
    try:
        g()
    except Exception:
        pass
`,
	},
	{
		name:   "js same-origin relative fetch",
		source: "triaged false positive",
		file:   "web/src/lib/api.ts",
		rule:   "js-ssrf",
		want:   "none",
		code: `export async function req(path: string, code: string) {
  await fetch(` + "`/api/v2${path}`" + `, { credentials: "include" });
  await fetch(` + "`/api/v2/auth/sso/exchange?code=${encodeURIComponent(code)}`" + `);
  await fetch("/api/v2" + path);
}
`,
	},
	{
		name:   "js protocol-relative fetch with a request host stays HIGH",
		source: "twin",
		file:   "server/proxy.js",
		rule:   "js-ssrf",
		want:   "high",
		code: `app.get("/p", async (req, res) => {
  await fetch("//" + req.query.host + "/x");
  await fetch(` + "`https://${req.query.host}/x`" + `);
});
`,
	},
	{
		name:   "js frontend axios against a configured base URL",
		source: "triaged false positive",
		file:   "frontend/src/stores/auth.js",
		rule:   "js-ssrf",
		want:   "none",
		code: `import axios from "axios";
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api";
export async function login(email, password, token) {
  await axios.post(` + "`${API_BASE_URL}/auth/token`" + `, { email, password });
  await axios.get(` + "`${API_BASE_URL}/users/me`" + `, { headers: { Authorization: token } });
}
`,
	},
	{
		name:   "js fixed host with a request path is LOW",
		source: "twin",
		file:   "server/proxy.js",
		rule:   "js-ssrf",
		want:   "low",
		code: `app.get("/p", async (req, res) => {
  await fetch(` + "`https://api.internal/items/${req.params.id}`" + `);
  await fetch("/api/" + req.query.path);
});
`,
	},
	{
		name:   "js client fetch against build-time base URL",
		source: "triaged false positive",
		file:   "src/lib/api.ts",
		rule:   "js-ssrf",
		want:   "none",
		code: `const API_BASE_URL = "https://api.example.com";
export async function req(path: string) {
  return fetch(` + "`${API_BASE_URL}${path}`" + `);
}
`,
	},
	{
		name:   "js secret file path from process.env",
		source: "triaged false positive",
		file:   "src/utils/secrets.ts",
		rule:   "js-path-traversal",
		want:   "none",
		code: `import fs from "fs";
export function getSecret(name: string) {
  const filePath = process.env[` + "`${name}_FILE`" + `];
  if (filePath) {
    return fs.readFileSync(filePath, "utf-8");
  }
}
`,
	},
	{
		name:   "js comment after return",
		source: "triaged false positive",
		file:   "Languages.tsx",
		rule:   "js-unreachable-code",
		want:   "none",
		code: `export function f(x: number) {
  return { x };
  // eslint-disable-next-line react-hooks/exhaustive-deps
}
`,
	},
	{
		name:   "react html passed through DOMPurify",
		source: "triaged false positive",
		file:   "ChatScreen.tsx",
		rule:   "js-react-dangerously-set-innerhtml",
		want:   "none",
		code: `import DOMPurify from "dompurify";
import { marked } from "marked";
export function Msg({ text }: { text: string }) {
  const html = DOMPurify.sanitize(marked.parse(text) as string);
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(text) }} />
    </div>
  );
}
`,
	},
	{
		name:   "react unsanitized html still fires",
		source: "twin",
		file:   "ChatScreen.tsx",
		rule:   "js-react-dangerously-set-innerhtml",
		want:   "fire",
		code: `export function Msg({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
`,
	},
	{
		name:   "ruby ssrf in a spec",
		source: "test-file policy",
		file:   "spec/client_spec.rb",
		rule:   "ruby-ssrf",
		want:   "none",
		code: `require "net/http"
describe "client" do
  it "fetches" do
    Net::HTTP.get("http://localhost:" + params[:port] + "/x")
  end
end
`,
	},
	{
		name:   "ruby port from params outside specs stays HIGH",
		source: "twin",
		file:   "lib/client.rb",
		rule:   "ruby-ssrf",
		want:   "high",
		code: `require "net/http"
def fetch(port)
  Net::HTTP.get("http://localhost:" + params[:port] + "/x")
end
`,
	},
	{
		name:   "java path traversal under src/test",
		source: "test-file policy",
		file:   "src/test/java/app/LoaderTest.java",
		rule:   "java-path-traversal",
		want:   "none",
		code: `package app;
import java.io.File;
import javax.servlet.http.HttpServletRequest;
class LoaderTest {
  void t(HttpServletRequest request) {
    new File(request.getParameter("f"));
  }
}
`,
	},
	{
		name:   "java path traversal in main code still fires",
		source: "twin",
		file:   "src/main/java/app/Loader.java",
		rule:   "java-path-traversal",
		want:   "fire",
		code: `package app;
import java.io.File;
import javax.servlet.http.HttpServletRequest;
class Loader {
  void t(HttpServletRequest request) {
    new File(request.getParameter("f"));
  }
}
`,
	},
}

func TestSASTFalsePositiveCorpus(t *testing.T) {
	for _, c := range sastFPCorpus {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, filepath.FromSlash(c.file))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(c.code), 0o644); err != nil {
				t.Fatal(err)
			}
			issues, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			fpcorpus.Check(t, c.rule, c.want, c.source, issues)
		})
	}
}
