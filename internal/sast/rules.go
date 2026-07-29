package sast

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

// importedAs returns the local identifier a package is imported under (handles aliases).
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

// isDynamicString reports whether e is built at runtime (Sprintf/concatenation)
// rather than a plain string literal.
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

// checkHardcodedSecret flags `var password = "literal"` / `password := "literal"` assignments.
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

// checkCommandInjection flags os/exec.Command(Context) calls whose command/arg
// is built dynamically rather than passed as a literal.
func checkCommandInjection(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	pkg, ok := importedAs(f, "os/exec")
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
		if !ok || id.Name != pkg || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
			return true
		}
		args := call.Args
		if sel.Sel.Name == "CommandContext" && len(args) > 0 {
			args = args[1:] // first arg is context.Context
		}
		for _, a := range args {
			if isDynamicString(a) {
				issues = append(issues, issueAt("go-command-injection", "HIGH", path,
					"Command built from a non-literal argument",
					pkg+"."+sel.Sel.Name+" argument is not a string literal (Sprintf/concatenation)",
					fset, call.Pos()))
				break
			}
		}
		return true
	})
	return issues
}

// checkSQLInjection flags database/sql Query/Exec/QueryRow calls built via
// Sprintf/concatenation instead of a literal query with placeholders.
func checkSQLInjection(f *ast.File, fset *token.FileSet, path string) []model.Issue {
	var issues []model.Issue
	sqlMethods := map[string]bool{"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true, "Exec": true, "ExecContext": true}
	ast.Inspect(f, func(n ast.Node) bool {
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
		if isDynamicString(queryArg) {
			issues = append(issues, issueAt("go-sql-injection", "HIGH", path,
				"SQL query built from a non-literal string",
				sel.Sel.Name+" query argument is built via Sprintf/concatenation instead of placeholders",
				fset, call.Pos()))
		}
		return true
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

// checkInsecureRandom flags math/rand usage inside functions whose name
// suggests it's generating a token/session/key/secret (heuristic, low confidence).
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

// checkDiscardedAuthError flags auth-relevant calls used as a bare statement
// (its error return is silently discarded).
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

// checkTLSInsecureSkipVerify flags tls.Config{InsecureSkipVerify: true}.
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

var permissiveFileModes = map[string]bool{"0777": true, "0666": true, "0o777": true, "0o666": true}
var fileModeFuncs = map[string]bool{"OpenFile": true, "MkdirAll": true, "Mkdir": true, "Chmod": true}

// checkPermissiveFileMode flags world-writable file mode literals passed to os functions.
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
