// Package sast statically analyzes Go source for common security anti-patterns
// using the standard library's go/ast — no external parser dependency.
//
// ponytail ceiling: pattern-matching over syntax only. No taint tracking, no
// interprocedural analysis, no metavariable pattern language — each rule is
// a bespoke Go predicate, not a general query. Expect false positives on the
// "unsanitized input" rules; treat findings as candidates for human triage,
// not proven vulnerabilities.
package sast

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"

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
}

// Scan walks root, parses every .go file, and runs the rule set against each.
func Scan(root string) ([]model.Issue, error) {
	fset := token.NewFileSet()
	var issues []model.Issue

	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		for _, r := range rules {
			issues = append(issues, r.check(f, fset, path)...)
		}
		return nil
	})
	return issues, err
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
