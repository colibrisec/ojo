package sast

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

func importedAs(f *ast.File, path string) (string, bool) {
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		parts := strings.Split(path, "/")
		return parts[len(parts)-1], true
	}
	return "", false
}

func isDynamicString(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return false
	case *ast.BinaryExpr:
		return v.Op == token.ADD
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "fmt" &&
				(sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Sprint") {
				return true
			}
		}
		return false
	default:
		return false
	}
}

var secretNameKeywords = []string{"password", "passwd", "secret", "apikey", "api_key", "token"}

func nameLooksSecret(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range secretNameKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func checkHardcodedSecret(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range v.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(v.Rhs) {
					continue
				}
				lit, ok := v.Rhs[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if nameLooksSecret(id.Name) && litLen(lit) > 4 {
					issues = append(issues, issueAt("go-hardcoded-secret", "MEDIUM", path,
						"Hardcoded secret-looking value", "variable "+id.Name+" is assigned a literal string",
						fset, lit.Pos()))
				}
			}
		case *ast.ValueSpec:
			for i, id := range v.Names {
				if i >= len(v.Values) {
					continue
				}
				lit, ok := v.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if nameLooksSecret(id.Name) && litLen(lit) > 4 {
					issues = append(issues, issueAt("go-hardcoded-secret", "MEDIUM", path,
						"Hardcoded secret-looking value", "variable "+id.Name+" is assigned a literal string",
						fset, lit.Pos()))
				}
			}
		}
		return true
	})
	return issues
}

func litLen(lit *ast.BasicLit) int {
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return len(lit.Value)
	}
	return len(s)
}

func checkCommandInjection(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "os/exec")
	if !ok {
		return nil
	}
	var issues []model.Issue
	forEachGoFuncBody(f, func(body *ast.BlockStmt) {
		env := goTaintEnv(body)
		inspectWithinFunc(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != pkg || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
				return true
			}
			args := call.Args
			if sel.Sel.Name == "CommandContext" && len(args) > 0 {
				args = args[1:] // first arg is context.Context
			}
			for _, a := range args {
				if isDynamicString(a) || goExprTainted(a, env) {
					issues = append(issues, issueAt("go-command-injection", "HIGH", path,
						"Command built from a non-literal argument",
						pkg+"."+sel.Sel.Name+" argument is not a string literal (Sprintf/concatenation, or a local variable derived from request/env input)",
						fset, call.Pos()))
					break
				}
			}
			return true
		})
	})
	return issues
}

func checkSQLInjection(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	sqlMethods := map[string]bool{"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true, "Exec": true, "ExecContext": true}
	forEachGoFuncBody(f, func(body *ast.BlockStmt) {
		env := goTaintEnv(body)
		inspectWithinFunc(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !sqlMethods[sel.Sel.Name] || len(call.Args) == 0 {
				return true
			}
			queryArg := call.Args[0]
			if _, isCtx := queryArg.(*ast.SelectorExpr); isCtx && len(call.Args) > 1 {
				queryArg = call.Args[1] // *Context variants take ctx first
			}
			if isDynamicString(queryArg) || goExprTainted(queryArg, env) {
				issues = append(issues, issueAt("go-sql-injection", "HIGH", path,
					"SQL query built from a non-literal string",
					sel.Sel.Name+" query argument is built via Sprintf/concatenation instead of placeholders, or is a local variable derived from request/env input",
					fset, call.Pos()))
			}
			return true
		})
	})
	return issues
}

func checkWeakHash(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	for _, weak := range []string{"crypto/md5", "crypto/sha1"} {
		pkg, ok := importedAs(f, weak)
		if !ok {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
				issues = append(issues, issueAt("go-weak-hash", "LOW", path,
					"Weak hash algorithm", weak+" is cryptographically broken; use crypto/sha256 or stronger",
					fset, sel.Pos()))
			}
			return true
		})
	}
	return issues
}

func checkWeakDES(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "crypto/des")
	if !ok {
		return nil
	}
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
			issues = append(issues, issueAt("go-weak-cipher-des", "MEDIUM", path,
				"Weak cipher DES", "crypto/des is a weak cipher; use crypto/aes",
				fset, sel.Pos()))
		}
		return true
	})
	return issues
}

func checkInsecureRandom(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "math/rand")
	if !ok {
		return nil
	}
	var issues []model.Issue
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !nameLooksSecret(fn.Name.Name) && !strings.Contains(strings.ToLower(fn.Name.Name), "session") {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
					issues = append(issues, issueAt("go-insecure-random-for-secrets", "INFO", path,
						"math/rand used in a security-sounding function",
						"function "+fn.Name.Name+" uses math/rand, which is not cryptographically secure; consider crypto/rand",
						fset, sel.Pos()))
				}
			}
			return true
		})
	}
	return issues
}

var authCallNames = map[string]bool{"Verify": true, "Authenticate": true, "CompareHashAndPassword": true}

func checkDiscardedAuthError(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		stmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}
		call, ok := stmt.X.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !authCallNames[sel.Sel.Name] {
			return true
		}
		issues = append(issues, issueAt("go-discarded-auth-error", "HIGH", path,
			"Auth call result discarded", "return value of "+sel.Sel.Name+" (likely an error) is not checked",
			fset, call.Pos()))
		return true
	})
	return issues
}

func checkTLSInsecureSkipVerify(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Config" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "tls" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "InsecureSkipVerify" {
				continue
			}
			if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" {
				issues = append(issues, issueAt("go-tls-insecure-skip-verify", "HIGH", path,
					"TLS certificate verification disabled", "tls.Config{InsecureSkipVerify: true} disables certificate validation",
					fset, kv.Pos()))
			}
		}
		return true
	})
	return issues
}

var (
	permissiveFileModes = map[string]bool{"0777": true, "0666": true, "0o777": true, "0o666": true}
	fileModeFuncs       = map[string]bool{"OpenFile": true, "MkdirAll": true, "Mkdir": true, "Chmod": true}
)

func checkPermissiveFileMode(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "os")
	if !ok {
		return nil
	}
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != pkg || !fileModeFuncs[sel.Sel.Name] {
			return true
		}
		for _, a := range call.Args {
			lit, ok := a.(*ast.BasicLit)
			if ok && lit.Kind == token.INT && permissiveFileModes[lit.Value] {
				issues = append(issues, issueAt("go-permissive-file-mode", "MEDIUM", path,
					"World-writable file mode", sel.Sel.Name+" called with mode "+lit.Value+" (world-writable)",
					fset, call.Pos()))
			}
		}
		return true
	})
	return issues
}

// rootedAtRequest reports whether e is a selector/call chain rooted at an
// identifier commonly used for the incoming *http.Request (r, req, request) —
// e.g. r.FormValue("next") or r.URL.Query().Get("next").
func goRootedAtRequest(e ast.Expr) bool {
	for {
		switch v := e.(type) {
		case *ast.SelectorExpr:
			e = v.X
		case *ast.CallExpr:
			e = v.Fun
		case *ast.IndexExpr:
			e = v.X
		case *ast.Ident:
			return v.Name == "r" || v.Name == "req" || v.Name == "request"
		default:
			return false
		}
	}
}

func checkOpenRedirect(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "net/http")
	if !ok {
		return nil
	}
	var issues []model.Issue
	forEachGoFuncBody(f, func(body *ast.BlockStmt) {
		env := goTaintEnv(body)
		inspectWithinFunc(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != pkg || sel.Sel.Name != "Redirect" || len(call.Args) < 3 {
				return true
			}
			target := call.Args[2]
			if !isDynamicString(target) && !goExprTainted(target, env) {
				return true
			}
			issues = append(issues, issueAt("go-open-redirect", "MEDIUM", path,
				"Redirect target built from request data",
				"http.Redirect target is derived from request input (directly or through a local variable) or built via Sprintf/concatenation rather than a literal/allowlisted URL",
				fset, call.Pos()))
			return true
		})
	})
	return issues
}

func checkJWTNoneAlgorithm(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SigningMethodNone" {
			return true
		}
		issues = append(issues, issueAt("go-jwt-none-algorithm", "HIGH", path,
			"JWT signing method set to none", "jwt.SigningMethodNone accepts unsigned tokens, allowing signature bypass",
			fset, sel.Pos()))
		return true
	})
	return issues
}

func checkCORSWildcard(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Set" || len(call.Args) != 2 {
			return true
		}
		key, ok := call.Args[0].(*ast.BasicLit)
		if !ok || key.Kind != token.STRING {
			return true
		}
		k, err := strconv.Unquote(key.Value)
		if err != nil || !strings.EqualFold(k, "Access-Control-Allow-Origin") {
			return true
		}
		val, ok := call.Args[1].(*ast.BasicLit)
		if !ok || val.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(val.Value)
		if err != nil || v != "*" {
			return true
		}
		issues = append(issues, issueAt("go-cors-wildcard", "MEDIUM", path,
			"CORS allow-origin set to wildcard",
			`Header().Set("Access-Control-Allow-Origin", "*") allows any origin to make credentialed cross-origin requests`,
			fset, call.Pos()))
		return true
	})
	return issues
}

func checkInsecureCookie(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "net/http")
	if !ok {
		return nil
	}
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Cookie" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != pkg {
			return true
		}
		secureTrue := false
		var sameSiteNone ast.Expr
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Secure", "HttpOnly":
				if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "false" {
					issues = append(issues, issueAt("go-insecure-cookie", "MEDIUM", path,
						"Cookie flag explicitly disabled", "http.Cookie{"+key.Name+": false} weakens cookie protection ("+key.Name+" should normally be true)",
						fset, kv.Pos()))
				}
				if key.Name == "Secure" {
					if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" {
						secureTrue = true
					}
				}
			case "SameSite":
				if valSel, ok := kv.Value.(*ast.SelectorExpr); ok && valSel.Sel.Name == "SameSiteNoneMode" {
					sameSiteNone = kv.Value
				}
			}
		}
		// SameSite=None requires Secure — checked after the full literal is
		// scanned since Secure/SameSite can appear in either order.
		if sameSiteNone != nil && !secureTrue {
			issues = append(issues, issueAt("go-insecure-cookie", "MEDIUM", path,
				"SameSite=None cookie without Secure",
				"http.Cookie{SameSite: http.SameSiteNoneMode} is set without Secure: true in the same literal — SameSite=None requires Secure or modern browsers reject the cookie outright, and without Secure the cookie is also sent over plain HTTP",
				fset, sameSiteNone.Pos()))
		}
		return true
	})
	return issues
}

var pathTraversalFuncs = map[string]bool{"Open": true, "ReadFile": true, "Create": true}

func checkPathTraversal(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "os")
	if !ok {
		return nil
	}
	var issues []model.Issue
	forEachGoFuncBody(f, func(body *ast.BlockStmt) {
		env := goTaintEnv(body)
		inspectWithinFunc(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != pkg || !pathTraversalFuncs[sel.Sel.Name] || len(call.Args) == 0 {
				return true
			}
			arg := call.Args[0]
			if !isDynamicString(arg) && !goExprTainted(arg, env) {
				return true
			}
			issues = append(issues, issueAt("go-path-traversal", "HIGH", path,
				"File path built from request data",
				"os."+sel.Sel.Name+" path is derived from request input (directly or through a local variable) or built via Sprintf/concatenation rather than a validated literal; sanitize/allowlist before use",
				fset, call.Pos()))
			return true
		})
	})
	return issues
}

var httpDirectSSRFFuncs = map[string]bool{"Get": true, "Post": true, "Head": true, "PostForm": true}

// checkSSRF flags an outbound HTTP request whose URL is built from
// request/env data: net/http's package-level Get/Post/Head/PostForm (URL is
// the first argument) and NewRequest/NewRequestWithContext (URL is the
// method/URL-taking argument, not the leading context.Context).
func checkSSRF(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "net/http")
	if !ok {
		return nil
	}
	var issues []model.Issue
	forEachGoFuncBody(f, func(body *ast.BlockStmt) {
		env := goTaintEnv(body)
		inspectWithinFunc(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != pkg {
				return true
			}
			var urlArg ast.Expr
			switch {
			case httpDirectSSRFFuncs[sel.Sel.Name] && len(call.Args) > 0:
				urlArg = call.Args[0]
			case sel.Sel.Name == "NewRequest" && len(call.Args) >= 2:
				urlArg = call.Args[1]
			case sel.Sel.Name == "NewRequestWithContext" && len(call.Args) >= 3:
				urlArg = call.Args[2]
			default:
				return true
			}
			if !isDynamicString(urlArg) && !goExprTainted(urlArg, env) {
				return true
			}
			issues = append(issues, issueAt("go-ssrf", "HIGH", path,
				"Outbound request URL built from request data",
				pkg+"."+sel.Sel.Name+" URL argument is built via Sprintf/concatenation, or is a local variable derived from request/env input, rather than a validated/allowlisted URL",
				fset, call.Pos()))
			return true
		})
	})
	return issues
}

// checkSSTI flags text/template or html/template's New(...).Parse(...) chain
// when the template source itself (not just the data rendered into it) is
// built from request/env data — the template source being attacker-
// controlled is server-side template injection, not just a substitution
// bug. Scoped to the exact New(...).Parse(...) chain (not a bare .Parse(
// method name, which collides with time.Parse/url.Parse/flag.Parse and
// would be a false-positive magnet) rooted at the actually-imported
// package name.
func checkSSTI(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	textPkg, textOK := importedAs(f, "text/template")
	htmlPkg, htmlOK := importedAs(f, "html/template")
	if !textOK && !htmlOK {
		return nil
	}
	var issues []model.Issue
	forEachGoFuncBody(f, func(body *ast.BlockStmt) {
		env := goTaintEnv(body)
		inspectWithinFunc(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Parse" || len(call.Args) == 0 {
				return true
			}
			inner, ok := sel.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			innerSel, ok := inner.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := innerSel.X.(*ast.Ident)
			if !ok || innerSel.Sel.Name != "New" || (id.Name != textPkg && id.Name != htmlPkg) {
				return true
			}
			arg := call.Args[0]
			if !isDynamicString(arg) && !goExprTainted(arg, env) {
				return true
			}
			issues = append(issues, issueAt("go-ssti", "HIGH", path,
				"Template source built from request data",
				id.Name+".New(...).Parse(...) argument is built via Sprintf/concatenation, or is a local variable derived from request/env input — the template source itself is attacker-controlled, which is server-side template injection, not just a data-substitution issue",
				fset, call.Pos()))
			return true
		})
	})
	return issues
}

// checkPredictablePRNGSeed flags math/rand's Seed(...)/NewSource(...) called
// with a compile-time integer literal — a fixed seed makes every subsequent
// "random" value fully predictable, regardless of what the generator is
// later used for (a distinct anti-pattern from go-insecure-random-for-secrets,
// which flags the algorithm choice, not the seed).
func checkPredictablePRNGSeed(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "math/rand")
	if !ok {
		return nil
	}
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != pkg || (sel.Sel.Name != "Seed" && sel.Sel.Name != "NewSource") || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			return true
		}
		issues = append(issues, issueAt("go-predictable-prng-seed", "MEDIUM", path,
			"PRNG seeded with a hardcoded literal",
			pkg+"."+sel.Sel.Name+" is called with a compile-time integer literal; every run produces the same sequence, making all subsequent output predictable — seed from crypto/rand or leave unseeded (math/rand auto-seeds since Go 1.20)",
			fset, call.Pos()))
		return true
	})
	return issues
}

func checkCookieMissingFlags(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "net/http")
	if !ok {
		return nil
	}
	var issues []model.Issue
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Cookie" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != pkg {
			return true
		}
		has := map[string]bool{}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				has[key.Name] = true
			}
		}
		for _, field := range []string{"Secure", "HttpOnly"} {
			if has[field] {
				continue
			}
			issues = append(issues, issueAt("go-cookie-missing-flags", "LOW", path,
				field+" not set on http.Cookie", "http.Cookie{...} doesn't set "+field+"; it defaults to false, weakening cookie protection unless set elsewhere",
				fset, lit.Pos()))
		}
		return true
	})
	return issues
}
