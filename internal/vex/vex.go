// Package vex implements OpenVEX (https://openvex.dev) document generation
// and consumption.
//
// Generation is deliberately low-ambition: ojo has no reachability
// analysis, so the only status it can honestly assert for a finding is
// "affected" -- it found the vulnerable package in the resolved dependency
// tree, full stop. It cannot know whether the vulnerable code path is
// actually reachable, which is what a "not_affected" status requires
// justifying. The real value of this package is the other direction --
// consuming a VEX document a human or another tool authored, and
// suppressing findings its not_affected/fixed statements cover, the same
// way .ojoignore does, just against a standard interchange format instead
// of an ojo-specific one.
package vex

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/colibrisec/ojo/internal/ignore"
	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/report"
)

const contextURL = "https://openvex.dev/ns/v0.2.0"

type Document struct {
	Context    string      `json:"@context"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

type Statement struct {
	Vulnerability   vulnerability `json:"vulnerability"`
	Products        []product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
}

type vulnerability struct {
	Name string `json:"name"`
}

type product struct {
	ID          string `json:"@id,omitempty"`
	Identifiers struct {
		PURL string `json:"purl,omitempty"`
	} `json:"identifiers,omitempty"`
}

// Generate builds an OpenVEX document asserting "affected" for every
// vulnerability in findings -- see the package doc for why that's the only
// status ojo can honestly emit on its own.
func Generate(findings []model.Finding, author string, now time.Time) Document {
	doc := Document{Context: contextURL, Author: author, Timestamp: now.UTC().Format(time.RFC3339), Version: 1}
	for _, f := range findings {
		p := product{ID: report.Purl(f.Package)}
		for _, v := range f.Vulns {
			doc.Statements = append(doc.Statements, Statement{
				Vulnerability: vulnerability{Name: v.ID},
				Products:      []product{p},
				Status:        "affected",
			})
		}
	}
	return doc
}

func Write(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// Load reads an OpenVEX document's statements from path. "" means no VEX
// file (nil, nil). Unlike .ojoignore or ojo's custom-rule YAML -- ojo's own
// formats, parsed strictly to catch typos -- this doesn't reject unknown
// fields: it's an external interchange format other tools and vendors
// author, and a real-world document routinely carries fields ojo doesn't
// model (e.g. "role", "supplier", per-statement "@id").
func Load(path string) ([]Statement, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return doc.Statements, nil
}

// Apply suppresses each finding vulnerability covered by a statement whose
// status is "not_affected" or "fixed" (matched by product purl and
// vulnerability ID/alias). Returns the same shape ignore.Apply does, so the
// caller can merge VEX suppressions into a Report.SuppressedFindings list
// built from .ojoignore right alongside them.
//
// ponytail ceiling: product matching is exact-string purl equality, no
// normalization (case, missing version qualifiers, alternate purl
// spellings for the same package all fail to match) -- a statement's
// product must use the same purl shape internal/report.Purl produces for
// that ecosystem.
func Apply(findings []model.Finding, statements []Statement) (kept []model.Finding, suppressed []ignore.SuppressedFinding) {
	for _, f := range findings {
		purl := report.Purl(f.Package)
		var keptVulns []model.Vulnerability
		for _, v := range f.Vulns {
			if reason, ok := matchStatement(statements, v, purl); ok {
				suppressed = append(suppressed, ignore.SuppressedFinding{Package: f.Package, Vuln: v, Reason: reason})
			} else {
				keptVulns = append(keptVulns, v)
			}
		}
		if len(keptVulns) > 0 {
			f.Vulns = keptVulns
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

func matchStatement(statements []Statement, v model.Vulnerability, purl string) (string, bool) {
	for _, s := range statements {
		if s.Status != "not_affected" && s.Status != "fixed" {
			continue
		}
		if !vulnMatches(s.Vulnerability.Name, v) || !productMatches(s.Products, purl) {
			continue
		}
		reason := "VEX: " + s.Status
		if s.Justification != "" {
			reason += " (" + s.Justification + ")"
		}
		return reason, true
	}
	return "", false
}

func vulnMatches(name string, v model.Vulnerability) bool {
	if name == v.ID {
		return true
	}
	for _, a := range v.Aliases {
		if name == a {
			return true
		}
	}
	return false
}

func productMatches(products []product, purl string) bool {
	for _, p := range products {
		if p.ID == purl || p.Identifiers.PURL == purl {
			return true
		}
	}
	return false
}
