// Package report renders scan findings as a table, JSON, or CycloneDX SBOM.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/colibrisec/ojo/internal/model"
)

// Table prints a human-readable, severity-sorted vulnerability table.
// root, if non-empty, is used to shorten Package.Source paths for display.
func Table(w io.Writer, root string, findings []model.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No vulnerabilities found.")
		return
	}

	type row struct {
		pkg  model.Package
		vuln model.Vulnerability
	}
	var flat []row
	for _, f := range findings {
		for _, v := range f.Vulns {
			flat = append(flat, row{f.Package, v})
		}
	}
	sort.SliceStable(flat, func(i, j int) bool {
		return severityRank(flat[i].vuln.Severity) < severityRank(flat[j].vuln.Severity)
	})

	rows := make([][]string, len(flat))
	for i, r := range flat {
		rows[i] = []string{
			r.vuln.Severity,
			fmt.Sprintf("%s@%s", r.pkg.Name, r.pkg.Version),
			r.vuln.ID,
			r.vuln.Summary,
		}
	}
	writeTable(w, []string{"SEVERITY", "PACKAGE", "VULN ID", "SUMMARY"}, rows, 0, isColorWriter(w))
}

// JSON prints findings as indented JSON.
func JSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// IssueTable prints a human-readable, severity-sorted table of non-SCA
// scanner issues (secret/misconfig/sast). root, if non-empty, shortens
// file paths for display.
func IssueTable(w io.Writer, root string, issues []model.Issue) {
	if len(issues) == 0 {
		return
	}

	sorted := make([]model.Issue, len(issues))
	copy(sorted, issues)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})

	rows := make([][]string, len(sorted))
	for i, iss := range sorted {
		rows[i] = []string{
			iss.Severity,
			fmt.Sprintf("%s:%d", relPath(root, iss.File), iss.Line),
			iss.RuleID,
			iss.Message,
		}
	}
	writeTable(w, []string{"SEVERITY", "LOCATION", "RULE", "MESSAGE"}, rows, 0, isColorWriter(w))
}

// Report is the combined output of every scanner requested in one invocation.
type Report struct {
	Findings []model.Finding `json:"findings,omitempty"`
	Issues   []model.Issue   `json:"issues,omitempty"`
}

// JSON prints the combined report as indented JSON.
func (r Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Table prints the combined report's vuln table, issue table, and a
// severity-bucketed summary line. root, if non-empty, shortens file paths.
func (r Report) Table(w io.Writer, root string) {
	if len(r.Findings) == 0 && len(r.Issues) == 0 {
		fmt.Fprintln(w, "No issues found.")
		return
	}
	if len(r.Findings) > 0 {
		Table(w, root, r.Findings)
	}
	if len(r.Issues) > 0 {
		if len(r.Findings) > 0 {
			fmt.Fprintln(w)
		}
		IssueTable(w, root, r.Issues)
	}
	fmt.Fprintln(w)
	printSummary(w, r.Findings, r.Issues)
}

func printSummary(w io.Writer, findings []model.Finding, issues []model.Issue) {
	counts := map[string]int{}
	vulnTotal := 0
	for _, f := range findings {
		for _, v := range f.Vulns {
			counts[v.Severity]++
			vulnTotal++
		}
	}
	for _, i := range issues {
		counts[i.Severity]++
	}

	color := isColorWriter(w)
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			label := fmt.Sprintf("%s: %d", sev, n)
			if color {
				label = severityCode(sev) + label + ansiReset
			}
			parts = append(parts, label)
		}
	}

	fmt.Fprintf(w, "%d vulnerabilities, %d issues", vulnTotal, len(issues))
	if len(parts) > 0 {
		fmt.Fprint(w, "  [")
		for i, p := range parts {
			if i > 0 {
				fmt.Fprint(w, "  ")
			}
			fmt.Fprint(w, p)
		}
		fmt.Fprint(w, "]")
	}
	fmt.Fprintln(w)
}

// SBOM renders the package inventory as a CycloneDX 1.5 JSON document.
func SBOM(w io.Writer, pkgs []model.Package) error {
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0, len(pkgs))
	for _, p := range pkgs {
		components = append(components, cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: purl(p),
		})
	}
	bom.Components = &components

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

func purl(p model.Package) string {
	switch p.Ecosystem {
	case model.EcosystemGo:
		return fmt.Sprintf("pkg:golang/%s@%s", p.Name, p.Version)
	case model.EcosystemNpm:
		return fmt.Sprintf("pkg:npm/%s@%s", p.Name, p.Version)
	case model.EcosystemPyPI:
		return fmt.Sprintf("pkg:pypi/%s@%s", p.Name, p.Version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", p.Name, p.Version)
	}
}
