package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestGitLabReports(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	manifestPath := filepath.Join(root, "go.mod")
	issueFile := filepath.Join(root, "src", "config.py")

	r := Report{
		Target: "test-target",
		Findings: []model.Finding{
			{
				Package: model.Package{Name: "django", Version: "3.2.0", Ecosystem: "PyPI", Source: manifestPath},
				Vulns: []model.Vulnerability{
					{ID: "CVE-2022-28346", Summary: "SQL Injection in Django", Severity: "CRITICAL", FixedVersion: "3.2.13", URL: "https://example.com/cve"},
				},
			},
		},
		Issues: []model.Issue{
			{Scanner: "secret", RuleID: "aws-access-key-id", Title: "AWS Access Key ID", Severity: "CRITICAL", File: issueFile, Line: 4, Message: "boom"},
			{Scanner: "sast", RuleID: "go-insecure-random-for-secrets", Title: "insecure random", Severity: "INFO", File: issueFile, Line: 5, Message: "info issue"},
			{Scanner: "misconfig", RuleID: "dockerfile-secret-env", Title: "secret env", Severity: "MEDIUM", File: issueFile, Line: 2, Message: "medium issue"},
		},
	}

	t.Run("dependency scanning", func(t *testing.T) {
		var buf bytes.Buffer
		if err := r.GitLabDependencyScanning(&buf, root, "v1.2.3"); err != nil {
			t.Fatal(err)
		}
		var rep glDepReport
		if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Vulnerabilities) != 1 {
			t.Fatalf("want 1 vulnerability, got %d", len(rep.Vulnerabilities))
		}
		v := rep.Vulnerabilities[0]
		if v.Severity != "Critical" {
			t.Errorf("severity: got %q, want Critical", v.Severity)
		}
		if v.Location.Dependency.Package.Name != "django" || v.Location.Dependency.Version != "3.2.0" {
			t.Errorf("unexpected location: %+v", v.Location)
		}
		if v.Solution != "Upgrade to 3.2.13" {
			t.Errorf("solution: got %q", v.Solution)
		}
		if rep.Scan.Scanner.Version != "v1.2.3" || rep.Scan.Type != "dependency_scanning" {
			t.Errorf("unexpected scan block: %+v", rep.Scan)
		}
	})

	t.Run("sast folds in misconfig", func(t *testing.T) {
		var buf bytes.Buffer
		if err := r.GitLabSAST(&buf, root, "v1.2.3"); err != nil {
			t.Fatal(err)
		}
		var rep glIssueReport
		if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Vulnerabilities) != 2 {
			t.Fatalf("want 2 vulnerabilities (sast+misconfig), got %d", len(rep.Vulnerabilities))
		}
		for _, v := range rep.Vulnerabilities {
			if v.Category != "sast" {
				t.Errorf("category: got %q, want sast", v.Category)
			}
		}
	})

	t.Run("secret detection only secret issues", func(t *testing.T) {
		var buf bytes.Buffer
		if err := r.GitLabSecretDetection(&buf, root, "v1.2.3"); err != nil {
			t.Fatal(err)
		}
		var rep glIssueReport
		if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Vulnerabilities) != 1 {
			t.Fatalf("want 1 vulnerability, got %d", len(rep.Vulnerabilities))
		}
		if rep.Vulnerabilities[0].Location.File != filepath.ToSlash(filepath.Join("src", "config.py")) {
			t.Errorf("location file: got %q", rep.Vulnerabilities[0].Location.File)
		}
	})
}
