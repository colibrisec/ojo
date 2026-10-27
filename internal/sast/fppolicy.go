package sast

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

// envTaintSources toggles whether env reads (os.Getenv, process.env, ...)
// count as taint sources. runEnvSplit flips it to tell request-derived
// findings apart from env-only ones.
var envTaintSources = true

// Env is deployment config: whoever sets it already controls the process.
// For sinks that take a location (path, URL, redirect target, query,
// template) an env-only source is dropped. For code/command execution sinks
// it is kept at LOW, since env can carry untrusted data in CI jobs and
// wrapper scripts.
var envOnlyLowRules = map[string]bool{
	"command-injection":      true,
	"eval-detected":          true,
	"eval-exec":              true,
	"unsafe-reflection":      true,
	"agent-unsandboxed-exec": true,
}

// Rules about attacker-controlled input. Test code has no attacker, so these
// are not reported in test files. Other rules (secrets, TLS, crypto) still are.
var testExemptRules = map[string]bool{
	"command-injection": true,
	"sql-injection":     true,
	"nosqli":            true,
	"path-traversal":    true,
	"lfi-include":       true,
	"ssrf":              true,
	"open-redirect":     true,
	"ssti":              true,
	"unsafe-reflection": true,
}

func ruleKind(ruleID string) string {
	_, kind, _ := strings.Cut(ruleID, "-")
	return kind
}

// runEnvSplit runs a file's rules without env sources, then with them, and
// keeps the base findings plus the env-only ones the policy allows.
func runEnvSplit(run func() []model.Issue) []model.Issue {
	envTaintSources = false
	base := run()
	envTaintSources = true
	all := run()

	seen := map[string]int{}
	for _, i := range base {
		seen[issueKey(i)]++
	}
	out := base
	for _, i := range all {
		k := issueKey(i)
		if seen[k] > 0 {
			seen[k]--
			continue
		}
		if !envOnlyLowRules[ruleKind(i.RuleID)] {
			continue
		}
		i.Severity = "LOW"
		i.Title = envTitle(i.Title)
		i.Message = "Argument comes from an environment variable, not request input. The environment is deployment config, so this matters only if untrusted data can reach it (e.g. a CI job exporting PR metadata). Original check: " + i.Message
		out = append(out, i)
	}
	return out
}

func issueKey(i model.Issue) string {
	return fmt.Sprintf("%s|%d|%s|%s", i.RuleID, i.Line, i.Title, i.Message)
}

func envTitle(t string) string {
	if strings.Contains(t, "request data") {
		return strings.Replace(t, "request data", "an environment variable", 1)
	}
	return t + " (from an environment variable)"
}

var testDirs = map[string]bool{"test": true, "tests": true, "testdata": true, "fixtures": true, "__tests__": true, "mocks": true, "__mocks__": true, "spec": true}

// isTestFile reports whether rel (relative to the scan root) is test code by
// the usual convention for its language, or sits under a test directory.
func isTestFile(rel string) bool {
	rel = filepath.ToSlash(rel)
	dir, name := "", rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		dir, name = rel[:i], rel[i+1:]
	}
	for _, seg := range strings.Split(dir, "/") {
		if testDirs[seg] {
			return true
		}
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	switch ext {
	case ".go":
		return strings.HasSuffix(stem, "_test")
	case ".py":
		return strings.HasPrefix(stem, "test_") || strings.HasSuffix(stem, "_test") || stem == "conftest"
	case ".rb":
		return strings.HasSuffix(stem, "_spec") || strings.HasSuffix(stem, "_test")
	case ".java":
		return strings.HasSuffix(stem, "Test") || strings.HasSuffix(stem, "Tests") || strings.HasSuffix(stem, "IT") || strings.HasSuffix(stem, "TestCase")
	case ".php":
		return strings.HasSuffix(stem, "Test")
	default:
		if jsLangForPath(name) != nil {
			return strings.Contains(stem, ".test") || strings.Contains(stem, ".spec")
		}
	}
	return false
}

func dropTestExempt(issues []model.Issue) []model.Issue {
	out := issues[:0]
	for _, i := range issues {
		if !testExemptRules[ruleKind(i.RuleID)] {
			out = append(out, i)
		}
	}
	return out
}
