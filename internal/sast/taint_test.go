package sast

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// goTaintThroughVar is the exact false-negative documented as the SAST
// scanner's #1 ceiling: request data hidden behind one local variable
// before reaching the sink.
const goTaintThroughVar = `package main

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
)

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

func fileHandler(r *http.Request) {
	name := r.FormValue("name")
	os.Open(name)
}

func cmdHandler(r *http.Request) {
	arg := r.FormValue("arg")
	exec.Command("sh", "-c", arg)
}

func queryHandler(r *http.Request, db *sql.DB) {
	id := r.FormValue("id")
	db.Query(id)
}

func envHandler() {
	target := os.Getenv("REDIRECT_TARGET")
	req := &http.Request{}
	http.Redirect(nil, req, target, http.StatusFound)
}

func safeHandler(w http.ResponseWriter, r *http.Request) {
	next := "/dashboard"
	http.Redirect(w, r, next, http.StatusFound)
}
`

func TestGoTaintTrackingThroughLocalVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), []byte(goTaintThroughVar), 0o644); err != nil {
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

	want := map[string]int{
		"go-open-redirect":     2, // redirectHandler + envHandler (via os.Getenv)
		"go-path-traversal":    1,
		"go-command-injection": 1,
		"go-sql-injection":     1,
	}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d, want %d (issues: %+v)", id, counts[id], n, issues)
		}
	}
}

// goTaintSurvivesWrappingCall documents a real, deliberate over-approximation:
// goExprTainted treats *any* call expression containing a tainted argument
// as tainted overall, without knowing (or caring) what the callee actually
// does with it. That means a genuine sanitizer call looks just as tainted
// as a no-op one — a real limitation in the false-positive direction — but
// it also means this already covers most of what "return-taint
// propagation" would add as a new feature, for free, across every call
// site in every language, not just same-file-resolved ones (see
// interproc.go's own doc comment for why that direction wasn't built as a
// separate same-file call-graph feature).
const goTaintSurvivesWrappingCall = `package main

import "net/http"

func sanitize(s string) string { return s }

func handler(w http.ResponseWriter, r *http.Request) {
	next := sanitize(r.URL.Query().Get("next"))
	http.Redirect(w, r, next, http.StatusFound)
}
`

func TestGoTaintSurvivesThroughAWrappingCall(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler2.go"), []byte(goTaintSurvivesWrappingCall), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, i := range issues {
		if i.RuleID == "go-open-redirect" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected go-open-redirect to still fire through a wrapping call's argument, got: %+v", issues)
	}
}

// goInterprocSinkInCallee is the interprocedural gap this file's own
// comment used to call unfixable: runQuery's own body has no dynamic
// string building and no request-rooted expression at all — q is just a
// plain parameter. Only same-file interprocedural tracking (runQuery is
// called with a request-derived argument at its one call site) can make
// this fire.
const goInterprocSinkInCallee = `package main

import (
	"database/sql"
	"net/http"
)

func runQuery(db *sql.DB, q string) {
	db.Query(q)
}

func handler(db *sql.DB, r *http.Request) {
	runQuery(db, r.URL.Query().Get("x"))
}

func safeHandler(db *sql.DB) {
	runQuery(db, "SELECT * FROM t")
}
`

func TestGoInterproceduralSinkInsideCallee(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "interproc.go"), []byte(goInterprocSinkInCallee), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "go-sql-injection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 go-sql-injection issue (runQuery's db.Query(q) via the tainted call in handler, not the literal-only call in safeHandler), got %d: %+v", count, issues)
	}
}

// goInterprocTransitive pins the fixed-round iteration actually catches a
// two-hop chain (handler -> middle -> inner), not just a single hop.
const goInterprocTransitive = `package main

import (
	"database/sql"
	"net/http"
)

func inner(db *sql.DB, q string) {
	db.Query(q)
}

func middle(db *sql.DB, x string) {
	inner(db, x)
}

func handler(db *sql.DB, r *http.Request) {
	middle(db, r.URL.Query().Get("x"))
}
`

func TestGoInterproceduralTransitiveTwoHops(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "transitive.go"), []byte(goInterprocTransitive), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "go-sql-injection" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 go-sql-injection issue (inner's db.Query(q), tainted through two hops: handler -> middle -> inner), got %d: %+v", count, issues)
	}
}

// TestGoBuildFuncRegistryExcludesMethods is a direct unit test of
// goBuildFuncRegistry's contract (not observable through Scan()'s output,
// since a method call site is always a *ast.SelectorExpr and so can never
// be matched by goComputeParamSeed's *ast.Ident-only call resolution
// regardless of registry contents) — pins that a method (a func with a
// receiver) is never registered as a same-file free function, only the
// free function of the same name is.
func TestGoBuildFuncRegistryExcludesMethods(t *testing.T) {
	src := `package main

type svc struct{}

func (s svc) runQuery(q string) {}

func runQuery(q string) {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	reg := goBuildFuncRegistry(f)
	info, ok := reg["runQuery"]
	if !ok {
		t.Fatal("expected runQuery to be registered (the free function)")
	}
	if len(info.params) != 1 || info.params[0] != "q" {
		t.Errorf("expected the registered runQuery's params to be [q] (the free function's), got %v — method may have been registered instead", info.params)
	}
	if len(reg) != 1 {
		t.Errorf("expected exactly 1 registered function (the method must be excluded), got %d: %v", len(reg), reg)
	}
}

// goInterprocFewerArgsThanParams exercises a call site with fewer
// arguments than the callee declares parameters (runQuery takes 2, this
// call site passes 1) — tsArgAt/goComputeParamSeed must skip the missing
// positions rather than panicking or misaligning the rest.
const goInterprocFewerArgsThanParams = `package main

import "database/sql"

func runQuery(db *sql.DB, q string) {
	db.Query(q)
}

func handler(db *sql.DB) {
	runQuery(db)
}
`

func TestGoInterproceduralFewerArgsThanParamsDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fewerargs.go"), []byte(goInterprocFewerArgsThanParams), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.RuleID == "go-sql-injection" {
			t.Errorf("expected no go-sql-injection issue: runQuery is never called with a tainted argument here, got: %+v", issues)
		}
	}
}
