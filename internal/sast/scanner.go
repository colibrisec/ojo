// Package sast statically analyzes source for common security anti-patterns:
// Go via the standard library's go/ast, Python via gotreesitter (a pure-Go,
// no-cgo tree-sitter runtime — see docs/guide/scanner/sast.md for why cgo
// was avoided) and its query engine.
//
// ponytail ceiling: pattern-matching over syntax only. No taint tracking, no
// interprocedural analysis, no cross-file resolution — each rule is a
// bespoke predicate/query, not a general query language. Expect false
// positives on the "unsanitized input" rules; treat findings as candidates
// for human triage, not proven vulnerabilities.
package sast

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"strings"

	gts "github.com/odvcencio/gotreesitter"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

type rule struct {
	id       string
	severity string
	check    func(f *ast.File, fset *token.FileSet, path string) []model.Issue
}

var rules = []rule{
	{"go-hardcoded-secret", "MEDIUM", checkHardcodedSecret},
	{"go-command-injection", "HIGH", checkCommandInjection},
	{"go-sql-injection", "HIGH", checkSQLInjection},
	{"go-weak-hash", "LOW", checkWeakHash},
	{"go-weak-cipher-des", "MEDIUM", checkWeakDES},
	{"go-insecure-random-for-secrets", "INFO", checkInsecureRandom},
	{"go-discarded-auth-error", "HIGH", checkDiscardedAuthError},
	{"go-tls-insecure-skip-verify", "HIGH", checkTLSInsecureSkipVerify},
	{"go-permissive-file-mode", "MEDIUM", checkPermissiveFileMode},
	{"go-open-redirect", "MEDIUM", checkOpenRedirect},
	{"go-jwt-none-algorithm", "HIGH", checkJWTNoneAlgorithm},
	{"go-cors-wildcard", "MEDIUM", checkCORSWildcard},
	{"go-insecure-cookie", "MEDIUM", checkInsecureCookie},
	{"go-path-traversal", "HIGH", checkPathTraversal},
	{"go-cookie-missing-flags", "LOW", checkCookieMissingFlags},
	{"go-ssrf", "HIGH", checkSSRF},
	{"go-ssti", "HIGH", checkSSTI},
	{"go-predictable-prng-seed", "MEDIUM", checkPredictablePRNGSeed},
}

// Scan walks root, parses every .go file, and runs the rule set against each.
func Scan(root string) ([]model.Issue, error) {
	fset := token.NewFileSet()
	var issues []model.Issue

	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		switch {
		case strings.HasSuffix(path, ".go"):
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil // ponytail: skip files that don't parse, don't fail the whole scan
			}
			for _, r := range rules {
				issues = append(issues, r.check(f, fset, path)...)
			}
		case strings.HasSuffix(path, ".py"):
			pyIssues, err := scanPythonFile(path)
			if err != nil {
				return nil // ponytail: skip files that don't parse, don't fail the whole scan
			}
			issues = append(issues, pyIssues...)
		case strings.HasSuffix(path, ".php"):
			phpIssues, err := scanPHPFile(path)
			if err != nil {
				return nil // ponytail: skip files that don't parse, don't fail the whole scan
			}
			issues = append(issues, phpIssues...)
		case strings.HasSuffix(path, ".rb"):
			rubyIssues, err := scanRubyFile(path)
			if err != nil {
				return nil // ponytail: skip files that don't parse, don't fail the whole scan
			}
			issues = append(issues, rubyIssues...)
		case strings.HasSuffix(path, ".java"):
			javaIssues, err := scanJavaFile(path)
			if err != nil {
				return nil // ponytail: skip files that don't parse, don't fail the whole scan
			}
			issues = append(issues, javaIssues...)
		default:
			if lang := jsLangForPath(path); lang != nil {
				jsIssues, err := scanJSFile(path, lang)
				if err != nil {
					return nil // ponytail: skip files that don't parse, don't fail the whole scan
				}
				issues = append(issues, jsIssues...)
			}
		}
		return nil
	})
	return issues, err
}

func scanPythonFile(path string) ([]model.Issue, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tree, err := gts.NewParser(pyLang).Parse(src)
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	for _, r := range pyRules {
		issues = append(issues, r.check(tree.RootNode(), src, path)...)
	}
	return issues, nil
}

func scanPHPFile(path string) ([]model.Issue, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tree, err := gts.NewParser(phpLang).Parse(src)
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	for _, r := range phpRules {
		issues = append(issues, r.check(tree.RootNode(), src, path)...)
	}
	return issues, nil
}

func scanRubyFile(path string) ([]model.Issue, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tree, err := gts.NewParser(rubyLang).Parse(src)
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	for _, r := range rubyRules {
		issues = append(issues, r.check(tree.RootNode(), src, path)...)
	}
	return issues, nil
}

func scanJavaFile(path string) ([]model.Issue, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tree, err := gts.NewParser(javaLang).Parse(src)
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	for _, r := range javaRules {
		issues = append(issues, r.check(tree.RootNode(), src, path)...)
	}
	return issues, nil
}

// jsLangForPath maps a file extension to the grammar that parses it, or nil
// if the extension isn't JS/TS. .tsx gets its own grammar (JSX support
// layered onto TypeScript); plain .ts can't contain JSX.
func jsLangForPath(path string) *gts.Language {
	switch {
	case strings.HasSuffix(path, ".tsx"):
		return tsxLang
	case strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".mts"), strings.HasSuffix(path, ".cts"):
		return tsLang
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".jsx"), strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".cjs"):
		return jsLang
	default:
		return nil
	}
}

func scanJSFile(path string, lang *gts.Language) ([]model.Issue, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tree, err := gts.NewParser(lang).Parse(src)
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	for _, r := range jsRules {
		issues = append(issues, r.check(tree.RootNode(), lang, src, path)...)
	}
	return issues, nil
}

func issueAt(id, severity, path, title, message string, fset *token.FileSet, pos token.Pos) model.Issue {
	p := fset.Position(pos)
	return model.Issue{
		Scanner:  "sast",
		RuleID:   id,
		Title:    title,
		Severity: severity,
		File:     path,
		Line:     p.Line,
		Message:  message,
	}
}
