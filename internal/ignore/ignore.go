// Package ignore parses .ojoignore files for accepting risk on specific
// findings/issues without editing scanner code, and applies them to a scan's
// results.
package ignore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

// Rule is one .ojoignore entry: suppress a finding/issue whose ID matches ID
// and whose path matches PathGlob, until Expires (zero means never).
type Rule struct {
	ID       string
	PathGlob string
	Reason   string
	Expires  time.Time
}

var expiresRe = regexp.MustCompile(`\(expires:\s*([^)]*)\)\s*$`)

// Load reads explicitPath, or ".ojoignore" in the current directory if
// explicitPath is empty. A missing default file is not an error (nothing
// ignored); a missing explicit path is, since that's almost certainly a typo.
//
// Each non-blank, non-comment line is:
//
//	<id> <path-glob>  # reason (expires: 2026-12-31)
//
// id matches a Vulnerability's ID/alias or an Issue's RuleID exactly.
// path-glob is matched with path.Match against the finding/issue's
// "/"-separated path relative to the scan root, so "*" spans one path
// segment. A reason is
// required; "(expires: YYYY-MM-DD)" at the end of the reason is optional —
// once past that date the entry stops suppressing instead of erroring.
func Load(explicitPath string) ([]Rule, error) {
	path := explicitPath
	if path == "" {
		path = ".ojoignore"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && explicitPath == "" {
			return nil, nil
		}
		return nil, err
	}

	var rules []Rule
	sc := bufio.NewScanner(bytes.NewReader(data))
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func parseLine(line string) (Rule, error) {
	fields, reason, ok := strings.Cut(line, "#")
	if !ok || strings.TrimSpace(reason) == "" {
		return Rule{}, fmt.Errorf(`missing required reason, expected "<id> <path-glob>  # reason": %q`, line)
	}
	parts := strings.Fields(fields)
	if len(parts) != 2 {
		return Rule{}, fmt.Errorf(`expected "<id> <path-glob>  # reason", got %q`, line)
	}

	rule := Rule{ID: parts[0], PathGlob: parts[1]}
	reason = strings.TrimSpace(reason)
	if m := expiresRe.FindStringSubmatch(reason); m != nil {
		expires, err := time.Parse("2006-01-02", m[1])
		if err != nil {
			return Rule{}, fmt.Errorf("invalid expires date %q: %w", m[1], err)
		}
		rule.Expires = expires
		reason = strings.TrimSpace(reason[:len(reason)-len(m[0])])
	}
	if reason == "" {
		return Rule{}, fmt.Errorf(`missing required reason, expected "<id> <path-glob>  # reason": %q`, line)
	}
	rule.Reason = reason
	return rule, nil
}

// Matches reports whether the rule suppresses id at path as of now. path is
// matched with the "/"-separated path.Match (not path/filepath.Match), which
// treats "/" as the separator on every OS ojo runs on, including Windows.
func (r Rule) Matches(id, p string, now time.Time) bool {
	if r.ID != id || (!r.Expires.IsZero() && !now.Before(r.Expires)) {
		return false
	}
	ok, _ := path.Match(r.PathGlob, filepath.ToSlash(p))
	return ok
}

// SuppressedFinding is a Finding vulnerability matched by a .ojoignore rule.
type SuppressedFinding struct {
	Package model.Package
	Vuln    model.Vulnerability
	Reason  string
}

// SuppressedIssue is an Issue matched by a .ojoignore rule.
type SuppressedIssue struct {
	Issue  model.Issue
	Reason string
}

// Apply splits findings and issues into what's kept and what a rule
// suppresses. A vulnerability is matched by its ID or any alias; an issue by
// its RuleID. A Finding whose every vulnerability is suppressed is dropped
// entirely; one with only some suppressed keeps the rest.
func Apply(findings []model.Finding, issues []model.Issue, rules []Rule, root string, now time.Time) (keptFindings []model.Finding, suppressedFindings []SuppressedFinding, keptIssues []model.Issue, suppressedIssues []SuppressedIssue) {
	for _, f := range findings {
		path := relSlash(root, f.Package.Source)
		var kept []model.Vulnerability
		for _, v := range f.Vulns {
			if reason, ok := matchVuln(rules, v, path, now); ok {
				suppressedFindings = append(suppressedFindings, SuppressedFinding{Package: f.Package, Vuln: v, Reason: reason})
			} else {
				kept = append(kept, v)
			}
		}
		if len(kept) > 0 {
			f.Vulns = kept
			keptFindings = append(keptFindings, f)
		}
	}

	for _, iss := range issues {
		path := relSlash(root, iss.File)
		if reason, ok := matchID(rules, iss.RuleID, path, now); ok {
			suppressedIssues = append(suppressedIssues, SuppressedIssue{Issue: iss, Reason: reason})
		} else {
			keptIssues = append(keptIssues, iss)
		}
	}
	return
}

func matchVuln(rules []Rule, v model.Vulnerability, path string, now time.Time) (string, bool) {
	if reason, ok := matchID(rules, v.ID, path, now); ok {
		return reason, true
	}
	for _, alias := range v.Aliases {
		if reason, ok := matchID(rules, alias, path, now); ok {
			return reason, true
		}
	}
	return "", false
}

func matchID(rules []Rule, id, path string, now time.Time) (string, bool) {
	for _, r := range rules {
		if r.Matches(id, path, now) {
			return r.Reason, true
		}
	}
	return "", false
}

func relSlash(root, path string) string {
	if root != "" {
		if rel, err := filepath.Rel(root, path); err == nil {
			path = rel
		}
	}
	return filepath.ToSlash(path)
}
