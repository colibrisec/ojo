package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/colibrisec/ojo/internal/model"
)

const titleWrapWidth = 60

func Table(w io.Writer, root string, findings []model.Finding) {
	_ = root
	if len(findings) == 0 {
		fmt.Fprintln(w, "No vulnerabilities found.")
		return
	}

	type vulnRow struct {
		pkg  model.Package
		vuln model.Vulnerability
	}
	var flat []vulnRow
	for _, f := range findings {
		for _, v := range f.Vulns {
			flat = append(flat, vulnRow{f.Package, v})
		}
	}
	sort.SliceStable(flat, func(i, j int) bool {
		if flat[i].pkg.Name != flat[j].pkg.Name {
			return flat[i].pkg.Name < flat[j].pkg.Name
		}
		return severityRank(flat[i].vuln.Severity) < severityRank(flat[j].vuln.Severity)
	})

	rows := make([][]string, len(flat))
	for i, r := range flat {
		title := r.vuln.Summary
		if r.vuln.URL != "" {
			title += "\n" + r.vuln.URL
		}
		rows[i] = []string{r.pkg.Name, r.vuln.ID, r.vuln.Severity, "affected", r.pkg.Version, r.vuln.FixedVersion, title}
	}
	mergeRuns(rows, []int{0, 2, 3, 4})

	cols := []boxColumn{
		{Header: "Library"},
		{Header: "Vulnerability"},
		{Header: "Severity"},
		{Header: "Status"},
		{Header: "Installed Version"},
		{Header: "Fixed Version"},
		{Header: "Title", Wrap: titleWrapWidth},
	}
	writeBoxTable(w, cols, rows, 2, isColorWriter(w))
}

// JSON prints findings as indented JSON.
func JSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

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
	mergeRuns(rows, []int{0}) // blank repeated Severity values, same as the vuln table

	cols := []boxColumn{
		{Header: "Severity"},
		{Header: "Location"},
		{Header: "Rule"},
		{Header: "Message", Wrap: titleWrapWidth},
	}
	writeBoxTable(w, cols, rows, 0, isColorWriter(w))
}

type Report struct {
	Target   string          `json:"target,omitempty"`
	Findings []model.Finding `json:"findings,omitempty"`
	Issues   []model.Issue   `json:"issues,omitempty"`
}

func (r Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (r Report) Table(w io.Writer, root string) {
	if len(r.Findings) == 0 && len(r.Issues) == 0 {
		if r.Target != "" {
			printTargetHeader(w, r.Target)
		}
		fmt.Fprintln(w, "No issues found.")
		return
	}

	if r.Target != "" {
		printTargetHeader(w, r.Target)
	}
	printTotalLine(w, r.Findings, r.Issues)
	fmt.Fprintln(w)

	if len(r.Findings) > 0 {
		Table(w, root, r.Findings)
	}
	if len(r.Issues) > 0 {
		if len(r.Findings) > 0 {
			fmt.Fprintln(w)
		}
		IssueTable(w, root, r.Issues)
	}
}

func printTargetHeader(w io.Writer, target string) {
	fmt.Fprintln(w, target)
	fmt.Fprintln(w, strings.Repeat("=", len([]rune(target))))
}

func printTotalLine(w io.Writer, findings []model.Finding, issues []model.Issue) {
	counts := map[string]int{}
	total := 0
	for _, f := range findings {
		for _, v := range f.Vulns {
			counts[v.Severity]++
			total++
		}
	}
	for _, i := range issues {
		counts[i.Severity]++
		total++
	}

	color := isColorWriter(w)
	order := []string{"UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	var parts []string
	for _, sev := range order {
		n := counts[sev]
		label := fmt.Sprintf("%s: %d", sev, n)
		if color {
			label = severityCode(sev) + label + ansiReset
		}
		parts = append(parts, label)
	}
	fmt.Fprintf(w, "Total: %d (%s)\n", total, strings.Join(parts, ", "))
}

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
