// Package quality scans for maintainability smells — cyclomatic
// complexity, function length, nesting depth, parameter count,
// cross-file duplicate code, and tracked TODO/FIXME comments — across
// Go, Python, JS/TS, PHP, Ruby, and Java. These are code-quality
// findings, not security ones: a different problem shape from
// internal/sast, and deliberately independent of it — no shared
// taint/query infrastructure, just its own small per-language "what
// counts as a function" node-type sets. Off by default, enabled with
// --scanners quality.
package quality

import (
	"fmt"

	"github.com/colibrisec/ojo/internal/model"
)

const (
	maxFunctionLines = 50
	maxParameters    = 5
	maxNestingDepth  = 4
	maxComplexity    = 10
)

// funcMetrics holds the four per-function measurements for one function/
// method/lambda/closure, regardless of source language.
type funcMetrics struct {
	name       string
	file       string
	startLine  int // 1-based
	endLine    int
	params     int
	nesting    int
	complexity int // McCabe: 1 + decision points
}

func (m funcMetrics) issues() []model.Issue {
	var issues []model.Issue
	length := m.endLine - m.startLine + 1
	if length > maxFunctionLines {
		issues = append(issues, newIssue("quality-function-length", "LOW", m.file, m.startLine,
			"Function too long",
			fmt.Sprintf("%s is %d lines long (threshold: %d) — consider splitting it up", m.name, length, maxFunctionLines)))
	}
	if m.params > maxParameters {
		issues = append(issues, newIssue("quality-parameter-count", "LOW", m.file, m.startLine,
			"Too many parameters",
			fmt.Sprintf("%s takes %d parameters (threshold: %d) — consider grouping related parameters into a struct/object", m.name, m.params, maxParameters)))
	}
	if m.nesting > maxNestingDepth {
		issues = append(issues, newIssue("quality-nesting-depth", "LOW", m.file, m.startLine,
			"Deeply nested code",
			fmt.Sprintf("%s nests %d levels of control flow deep (threshold: %d) — consider extracting inner blocks into their own functions or using early returns", m.name, m.nesting, maxNestingDepth)))
	}
	if m.complexity > maxComplexity {
		issues = append(issues, newIssue("quality-cyclomatic-complexity", "MEDIUM", m.file, m.startLine,
			"High cyclomatic complexity",
			fmt.Sprintf("%s has a cyclomatic complexity of %d (threshold: %d) — consider splitting it into smaller functions", m.name, m.complexity, maxComplexity)))
	}
	return issues
}

func newIssue(id, severity, file string, line int, title, message string) model.Issue {
	return model.Issue{
		Scanner:  "quality",
		RuleID:   id,
		Title:    title,
		Severity: severity,
		File:     file,
		Line:     line,
		Message:  message,
	}
}

// Scan runs every quality metric — the four per-function AST metrics
// across all six languages, plus cross-file duplicate detection — against
// every source file under root.
func Scan(root string) ([]model.Issue, error) {
	var issues []model.Issue

	for _, scan := range []func(string) ([]model.Issue, error){
		scanGo, scanPython, scanJS, scanPHP, scanRuby, scanJava,
	} {
		found, err := scan(root)
		if err != nil {
			return nil, err
		}
		issues = append(issues, found...)
	}

	dupIssues, err := scanDuplicates(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, dupIssues...)

	todoIssues, err := scanTODOComments(root)
	if err != nil {
		return nil, err
	}
	issues = append(issues, todoIssues...)

	return issues, nil
}
