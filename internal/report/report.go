package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/colibrisec/ojo/internal/ignore"
	"github.com/colibrisec/ojo/internal/license"
	"github.com/colibrisec/ojo/internal/model"
)

const titleWrapWidth = 60

// Table prints one vulnerability table per file the affected packages were
// found in, each under that file's path, so a package pinned in two places
// (requirements.txt and uv.lock, say) shows up as two things to fix.
func Table(w io.Writer, root string, findings []model.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No vulnerabilities found.")
		return
	}

	var sources []string
	bySource := map[string][]model.Finding{}
	for _, f := range findings {
		src := relPath(root, f.Package.Source)
		if _, ok := bySource[src]; !ok {
			sources = append(sources, src)
		}
		bySource[src] = append(bySource[src], f)
	}
	for i, src := range sources {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if src != "" {
			fmt.Fprintln(w, src)
			fmt.Fprintln(w, strings.Repeat("-", len([]rune(src))))
		}
		vulnTable(w, bySource[src])
	}
}

func vulnTable(w io.Writer, findings []model.Finding) {
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
		id := r.vuln.ID
		if r.vuln.KEV {
			id += "\n[KEV: exploited in the wild]"
		}
		rows[i] = []string{r.pkg.Name, id, r.vuln.Severity, "affected", r.pkg.Version, r.vuln.FixedVersion, title}
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
		rule := iss.RuleID
		if len(iss.CWEs) > 0 {
			rule = fmt.Sprintf("%s (%s)", rule, strings.Join(iss.CWEs, ", "))
		}
		rows[i] = []string{
			iss.Severity,
			fmt.Sprintf("%s:%d", relPath(root, iss.File), iss.Line),
			rule,
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

	// Suppressed holds findings/issues matched by a .ojoignore rule, set by
	// the caller after filtering Findings/Issues down to the kept set. Only
	// the SARIF writer reads these (as native `suppressions`); every other
	// format just omits suppressed results, so they're excluded from JSON.
	SuppressedFindings []ignore.SuppressedFinding `json:"-"`
	SuppressedIssues   []ignore.SuppressedIssue   `json:"-"`
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

// cyclonedxVersions maps a --cyclonedx-version flag value to the spec
// version it selects. "" (the flag's default) means latest.
var cyclonedxVersions = map[string]cdx.SpecVersion{
	"":    cdx.SpecVersion1_7,
	"1.0": cdx.SpecVersion1_0,
	"1.1": cdx.SpecVersion1_1,
	"1.2": cdx.SpecVersion1_2,
	"1.3": cdx.SpecVersion1_3,
	"1.4": cdx.SpecVersion1_4,
	"1.5": cdx.SpecVersion1_5,
	"1.6": cdx.SpecVersion1_6,
	"1.7": cdx.SpecVersion1_7,
}

// ParseCycloneDXVersion validates a --cyclonedx-version flag value. "" means
// latest. JSON output (the only format ojo writes) isn't supported below 1.2.
func ParseCycloneDXVersion(s string) (cdx.SpecVersion, error) {
	v, ok := cyclonedxVersions[s]
	if !ok {
		return 0, fmt.Errorf("unsupported CycloneDX version %q (supported: 1.0-1.7)", s)
	}
	if v < cdx.SpecVersion1_2 {
		return 0, fmt.Errorf("CycloneDX version %q: ojo's SBOM output is JSON, not supported below 1.2", s)
	}
	return v, nil
}

// SBOM writes pkgs as a CycloneDX document, one component per distinct
// package: a package found in several files is the same component, not
// several.
func SBOM(w io.Writer, pkgs []model.Package, version cdx.SpecVersion) error {
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0, len(pkgs))
	index := map[model.Package]int{}
	for _, p := range pkgs {
		key := model.Package{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem}
		if i, ok := index[key]; ok {
			if components[i].Licenses == nil {
				components[i].Licenses = sbomLicenses(p.License)
			}
			continue
		}
		index[key] = len(components)
		components = append(components, cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: Purl(p),
			Licenses:   sbomLicenses(p.License),
		})
	}
	bom.Components = &components

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, version)
}

// sbomLicenses renders a package's license for CycloneDX, which wants one of
// three shapes: an SPDX license ID, an SPDX expression, or -- for anything
// else, such as a distribution's own short name ("GPLv2+") -- a free-form
// name. Only identifiers internal/license recognizes are written as an ID or
// expression, since the schema rejects an unknown ID.
func sbomLicenses(l string) *cdx.Licenses {
	l = strings.TrimSpace(l)
	switch {
	case l == "":
		return nil
	case license.IsSPDXID(l):
		return &cdx.Licenses{{License: &cdx.License{ID: l}}}
	case license.IsSPDXExpression(l):
		return &cdx.Licenses{{Expression: l}}
	default:
		return &cdx.Licenses{{License: &cdx.License{Name: l}}}
	}
}

// Purl returns a package-url (https://github.com/package-url/purl-spec)
// identifier for p. Used for SBOM component identity and (internal/vex) to
// match a finding's package against a VEX statement's product.
func Purl(p model.Package) string {
	switch p.Ecosystem {
	case model.EcosystemGo:
		return fmt.Sprintf("pkg:golang/%s@%s", p.Name, p.Version)
	case model.EcosystemNpm:
		return fmt.Sprintf("pkg:npm/%s@%s", p.Name, p.Version)
	case model.EcosystemPyPI:
		return fmt.Sprintf("pkg:pypi/%s@%s", p.Name, p.Version)
	case model.EcosystemCocoaPods:
		return fmt.Sprintf("pkg:cocoapods/%s@%s", p.Name, p.Version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", p.Name, p.Version)
	}
}
