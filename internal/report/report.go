// Package report renders scan findings as a table, JSON, or CycloneDX SBOM.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/colibrisec/ojo/internal/model"
)

// Table prints a human-readable findings table.
func Table(w io.Writer, findings []model.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No vulnerabilities found.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tVERSION\tECOSYSTEM\tVULN ID\tSEVERITY\tSUMMARY")
	for _, f := range findings {
		for _, v := range f.Vulns {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				f.Package.Name, f.Package.Version, f.Package.Ecosystem, v.ID, v.Severity, v.Summary)
		}
	}
	tw.Flush()
}

// JSON prints findings as indented JSON.
func JSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// IssueTable prints a human-readable table of non-SCA scanner issues (secret/misconfig/sast).
func IssueTable(w io.Writer, issues []model.Issue) {
	if len(issues) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SCANNER\tSEVERITY\tRULE\tFILE\tLINE\tMESSAGE")
	for _, i := range issues {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", i.Scanner, i.Severity, i.RuleID, i.File, i.Line, i.Message)
	}
	tw.Flush()
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

// Table prints the combined report's vuln table followed by the issue table.
func (r Report) Table(w io.Writer) {
	if len(r.Findings) > 0 {
		Table(w, r.Findings)
	}
	if len(r.Issues) > 0 {
		if len(r.Findings) > 0 {
			fmt.Fprintln(w)
		}
		IssueTable(w, r.Issues)
	}
	if len(r.Findings) == 0 && len(r.Issues) == 0 {
		fmt.Fprintln(w, "No issues found.")
	}
}

// SBOM renders the package inventory as a CycloneDX 1.5 JSON document.
func SBOM(w io.Writer, pkgs []model.Package) error {
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0, len(pkgs))
	for _, p := range pkgs {
		components = append(components, cdx.Component{
			Type:    cdx.ComponentTypeLibrary,
			Name:    p.Name,
			Version: p.Version,
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
