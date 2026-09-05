package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

// GitLab security report schemas: https://docs.gitlab.com/ee/user/application_security/#security-report-validation
// SAST and Secret Detection share one shape; Dependency Scanning has its own location/severity fields.

type glScanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type glScan struct {
	Scanner   glScanner `json:"scanner"`
	Analyzer  glScanner `json:"analyzer"`
	Type      string    `json:"type"`
	StartTime string    `json:"start_time"`
	EndTime   string    `json:"end_time"`
	Status    string    `json:"status"`
}

type glIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

func gitlabScan(kind, version string) glScan {
	now := time.Now().UTC().Format("2006-01-02T15:04:05")
	scanner := glScanner{ID: "ojo", Name: "ojo", Version: version}
	return glScan{Scanner: scanner, Analyzer: scanner, Type: kind, StartTime: now, EndTime: now, Status: "success"}
}

func gitlabSeverity(sev string) string {
	switch sev {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM", "MODERATE":
		return "Medium"
	case "LOW":
		return "Low"
	case "INFO":
		return "Info"
	default:
		return "Unknown"
	}
}

func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		io.WriteString(h, p)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// --- SAST / Secret Detection (identical shape, different category) ---

type glIssueVuln struct {
	ID          string         `json:"id"`
	Category    string         `json:"category"`
	Name        string         `json:"name"`
	Message     string         `json:"message"`
	Description string         `json:"description,omitempty"`
	CVE         string         `json:"cve"`
	Severity    string         `json:"severity"`
	Scanner     glScanner      `json:"scanner"`
	Location    glIssueLoc     `json:"location"`
	Identifiers []glIdentifier `json:"identifiers"`
}

type glIssueLoc struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type glIssueReport struct {
	Version         string        `json:"version"`
	Vulnerabilities []glIssueVuln `json:"vulnerabilities"`
	Scan            glScan        `json:"scan"`
}

func writeIssueReport(w io.Writer, root, category, schemaVersion, toolVersion string, issues []model.Issue) error {
	vulns := make([]glIssueVuln, 0, len(issues))
	for _, iss := range issues {
		file := filepath.ToSlash(relPath(root, iss.File))
		id := fingerprint(category, file, fmt.Sprint(iss.Line), iss.RuleID, iss.Message)
		name := iss.Title
		if name == "" {
			name = iss.RuleID
		}
		idents := []glIdentifier{
			{Type: "ojo_rule_id", Name: iss.RuleID, Value: iss.RuleID},
		}
		for _, cwe := range iss.CWEs {
			idents = append(idents, glIdentifier{Type: "cwe", Name: cwe, Value: cwe, URL: model.CWEURL(cwe)})
		}
		vulns = append(vulns, glIssueVuln{
			ID:          id,
			Category:    category,
			Name:        name,
			Message:     iss.Message,
			CVE:         id,
			Severity:    gitlabSeverity(iss.Severity),
			Scanner:     glScanner{ID: "ojo", Name: "ojo"},
			Location:    glIssueLoc{File: file, StartLine: iss.Line, EndLine: iss.Line},
			Identifiers: idents,
		})
	}

	rep := glIssueReport{
		Version:         schemaVersion,
		Vulnerabilities: vulns,
		Scan:            gitlabScan(category, toolVersion),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// GitLabSAST writes a GitLab SAST report (gl-sast-report.json), covering both
// the sast and misconfig scanners since GitLab's own IaC analyzers report
// under the "sast" category too.
func (r Report) GitLabSAST(w io.Writer, root, toolVersion string) error {
	var issues []model.Issue
	for _, iss := range r.Issues {
		if iss.Scanner == "sast" || iss.Scanner == "misconfig" {
			issues = append(issues, iss)
		}
	}
	return writeIssueReport(w, root, "sast", "15.0.7", toolVersion, issues)
}

// GitLabSecretDetection writes a GitLab Secret Detection report (gl-secret-detection-report.json).
func (r Report) GitLabSecretDetection(w io.Writer, root, toolVersion string) error {
	var issues []model.Issue
	for _, iss := range r.Issues {
		if iss.Scanner == "secret" {
			issues = append(issues, iss)
		}
	}
	return writeIssueReport(w, root, "secret_detection", "15.0.7", toolVersion, issues)
}

// --- Dependency Scanning ---

type glDepVuln struct {
	ID          string         `json:"id"`
	Category    string         `json:"category"`
	Name        string         `json:"name"`
	Message     string         `json:"message"`
	CVE         string         `json:"cve"`
	Severity    string         `json:"severity"`
	Solution    string         `json:"solution,omitempty"`
	Scanner     glScanner      `json:"scanner"`
	Location    glDepLoc       `json:"location"`
	Identifiers []glIdentifier `json:"identifiers"`
}

type glDepLoc struct {
	File       string       `json:"file"`
	Dependency glDependency `json:"dependency"`
}

type glDependency struct {
	Package glPackage `json:"package"`
	Version string    `json:"version"`
}

type glPackage struct {
	Name string `json:"name"`
}

type glDepReport struct {
	Version         string      `json:"version"`
	Vulnerabilities []glDepVuln `json:"vulnerabilities"`
	DependencyFiles []any       `json:"dependency_files"`
	Scan            glScan      `json:"scan"`
}

// GitLabDependencyScanning writes a GitLab Dependency Scanning report (gl-dependency-scanning-report.json).
func (r Report) GitLabDependencyScanning(w io.Writer, root, toolVersion string) error {
	var vulns []glDepVuln
	for _, f := range r.Findings {
		file := filepath.ToSlash(relPath(root, f.Package.Source))
		for _, v := range f.Vulns {
			id := fingerprint("dependency_scanning", f.Package.Name, f.Package.Version, v.ID)
			solution := ""
			if v.FixedVersion != "" {
				solution = "Upgrade to " + v.FixedVersion
			}
			idents := []glIdentifier{{Type: "vulnerability_id", Name: v.ID, Value: v.ID, URL: v.URL}}
			for _, a := range v.Aliases {
				idents = append(idents, glIdentifier{Type: "vulnerability_id", Name: a, Value: a})
			}
			vulns = append(vulns, glDepVuln{
				ID:       id,
				Category: "dependency_scanning",
				Name:     v.Summary,
				Message:  v.Summary,
				CVE:      id,
				Severity: gitlabSeverity(v.Severity),
				Solution: solution,
				Scanner:  glScanner{ID: "ojo", Name: "ojo"},
				Location: glDepLoc{
					File:       file,
					Dependency: glDependency{Package: glPackage{Name: f.Package.Name}, Version: f.Package.Version},
				},
				Identifiers: idents,
			})
		}
	}

	rep := glDepReport{
		Version:         "15.0.6",
		Vulnerabilities: vulns,
		DependencyFiles: []any{},
		Scan:            gitlabScan("dependency_scanning", toolVersion),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
