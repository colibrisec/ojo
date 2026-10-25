package license

import (
	"fmt"
	"sort"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

// Policy is an allow or deny list of licenses. Entries are SPDX IDs or
// free-form names, matched case-insensitively; a trailing "*" matches a
// prefix ("GPL-*"). Exceptions are package names ("name" or
// "name@version") the policy doesn't apply to.
type Policy struct {
	Allow      []string
	Deny       []string
	Exceptions []string
	// FailUnknown reports a package with no known license as a finding.
	FailUnknown bool
}

// Check returns an issue per package whose license breaks p, plus the
// packages whose license is unknown (reported as issues only when
// p.FailUnknown is set).
func (p Policy) Check(pkgs []model.Package) (issues []model.Issue, unknown []model.Package) {
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		key := pkg.Name + "@" + pkg.Version + "\x00" + pkg.Source
		if seen[key] || p.excepted(pkg) {
			continue
		}
		seen[key] = true

		lic := strings.TrimSpace(pkg.License)
		if lic == "" || lic == "NOASSERTION" {
			unknown = append(unknown, pkg)
			if p.FailUnknown {
				issues = append(issues, issue(pkg, "license-unknown", "LOW", "Unknown license",
					fmt.Sprintf("%s@%s has no known license", pkg.Name, pkg.Version)))
			}
			continue
		}

		expr := parseExpression(lic)
		if len(p.Allow) > 0 {
			if !expr.eval(func(l leaf) bool { return matchesAny(p.Allow, l) }) {
				issues = append(issues, issue(pkg, "license-not-allowed", "HIGH", "License not allowed",
					fmt.Sprintf("%s@%s is licensed %s, which isn't on the license allow list", pkg.Name, pkg.Version, lic)))
			}
		} else if len(p.Deny) > 0 {
			if !expr.eval(func(l leaf) bool { return !matchesAny(p.Deny, l) }) {
				issues = append(issues, issue(pkg, "license-denied", "HIGH", "Denied license",
					fmt.Sprintf("%s@%s is licensed %s, which the license policy denies", pkg.Name, pkg.Version, lic)))
			}
		}
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].File < issues[j].File })
	return issues, unknown
}

func (p Policy) excepted(pkg model.Package) bool {
	for _, e := range p.Exceptions {
		if strings.EqualFold(e, pkg.Name) || strings.EqualFold(e, pkg.Name+"@"+pkg.Version) {
			return true
		}
	}
	return false
}

func issue(pkg model.Package, rule, severity, title, msg string) model.Issue {
	return model.Issue{
		Scanner:  "license",
		RuleID:   rule,
		Title:    title,
		Severity: severity,
		File:     pkg.Source,
		Match:    pkg.Name + "@" + pkg.Version,
		Message:  msg,
	}
}

// leaf is one license in an expression, with its WITH exception if any.
type leaf struct {
	id, exception string
}

func matchesAny(entries []string, l leaf) bool {
	full := l.id
	if l.exception != "" {
		full += " WITH " + l.exception
	}
	for _, e := range entries {
		if matchEntry(e, full) || matchEntry(e, l.id) {
			return true
		}
	}
	return false
}

func matchEntry(entry, license string) bool {
	entry, license = normalize(strings.TrimSpace(entry)), normalize(license)
	if prefix, ok := strings.CutSuffix(entry, "*"); ok {
		return len(license) >= len(prefix) && strings.EqualFold(license[:len(prefix)], prefix)
	}
	return strings.EqualFold(entry, license)
}

// normalize maps deprecated GNU identifiers ("GPL-2.0", "GPL-2.0+") to
// their current form, so a policy written either way matches both.
func normalize(id string) string {
	for _, family := range []string{"AGPL-", "LGPL-", "GPL-", "GFDL-"} {
		if !strings.HasPrefix(id, family) || strings.HasSuffix(id, "-only") || strings.HasSuffix(id, "-or-later") {
			continue
		}
		if base, ok := strings.CutSuffix(id, "+"); ok {
			return base + "-or-later"
		}
		if spdxIDs[id] {
			return id + "-only"
		}
	}
	return id
}

// expr is a parsed SPDX license expression.
type expr struct {
	op       string // "AND", "OR", or "" for a leaf
	leaf     leaf
	children []expr
}

func (e expr) eval(ok func(leaf) bool) bool {
	switch e.op {
	case "AND":
		for _, c := range e.children {
			if !c.eval(ok) {
				return false
			}
		}
		return true
	case "OR":
		for _, c := range e.children {
			if c.eval(ok) {
				return true
			}
		}
		return false
	}
	return ok(e.leaf)
}

// parseExpression parses an SPDX expression. Anything that doesn't parse
// (a free-form license name) is one leaf holding the whole text.
func parseExpression(s string) expr {
	p := &parser{tokens: strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s))}
	e, ok := p.or()
	if !ok || p.pos != len(p.tokens) {
		return expr{leaf: leaf{id: s}}
	}
	return e
}

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *parser) or() (expr, bool) { return p.binary("OR", p.and) }

func (p *parser) and() (expr, bool) { return p.binary("AND", p.atom) }

func (p *parser) binary(op string, next func() (expr, bool)) (expr, bool) {
	first, ok := next()
	if !ok {
		return expr{}, false
	}
	children := []expr{first}
	for p.peek() == op {
		p.pos++
		e, ok := next()
		if !ok {
			return expr{}, false
		}
		children = append(children, e)
	}
	if len(children) == 1 {
		return first, true
	}
	return expr{op: op, children: children}, true
}

func (p *parser) atom() (expr, bool) {
	tok := p.peek()
	switch tok {
	case "", ")", "AND", "OR", "WITH":
		return expr{}, false
	case "(":
		p.pos++
		e, ok := p.or()
		if !ok || p.peek() != ")" {
			return expr{}, false
		}
		p.pos++
		return e, true
	}
	p.pos++
	l := leaf{id: tok}
	if p.peek() == "WITH" {
		p.pos++
		exc := p.peek()
		if exc == "" || exc == "(" || exc == ")" || exc == "AND" || exc == "OR" {
			return expr{}, false
		}
		p.pos++
		l.exception = exc
	}
	return expr{leaf: l}, true
}
