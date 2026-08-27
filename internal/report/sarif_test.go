package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/colibrisec/ojo/internal/ignore"
	"github.com/colibrisec/ojo/internal/model"
)

func TestSARIFStructureAndLevels(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	manifestPath := filepath.Join(root, "requirements.txt")
	issueFile := filepath.Join(root, "src", "config.py")

	r := Report{
		Target: "test-target",
		Findings: []model.Finding{
			{
				Package: model.Package{Name: "django", Version: "3.2.0", Ecosystem: "PyPI", Source: manifestPath},
				Vulns: []model.Vulnerability{
					{ID: "CVE-2022-28346", Summary: "SQL Injection in Django", Severity: "CRITICAL", URL: "https://example.com/cve"},
					{ID: "CVE-2022-28346", Summary: "SQL Injection in Django", Severity: "CRITICAL", URL: "https://example.com/cve"}, // duplicate rule, should dedupe
				},
			},
		},
		Issues: []model.Issue{
			{Scanner: "secret", RuleID: "aws-access-key-id", Title: "AWS Access Key ID", Severity: "CRITICAL", File: issueFile, Line: 4, Message: "boom"},
			{Scanner: "sast", RuleID: "go-insecure-random-for-secrets", Title: "insecure random", Severity: "INFO", File: issueFile, Line: 0, Message: "info issue"},
			{Scanner: "misconfig", RuleID: "dockerfile-secret-env", Title: "secret env", Severity: "MEDIUM", File: issueFile, Line: 2, Message: "medium issue"},
			{Scanner: "misconfig", RuleID: "some-rule", Title: "unknown severity", Severity: "UNKNOWN", File: issueFile, Line: 1, Message: "unknown issue"},
		},
	}

	var buf bytes.Buffer
	if err := r.SARIF(&buf, root); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Schema string `json:"$schema"`
		Runs   []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF output isn't valid JSON matching the expected shape: %v\n%s", err, buf.String())
	}

	if log.Schema == "" {
		t.Error("expected a $schema field")
	}
	if log.Runs[0].Tool.Driver.Name != "ojo" {
		t.Errorf("expected tool name \"ojo\", got %q", log.Runs[0].Tool.Driver.Name)
	}

	// Two identical vuln entries for the same CVE should collapse to one rule.
	if len(log.Runs[0].Tool.Driver.Rules) != 5 { // 1 vuln rule + 4 distinct issue rules
		t.Errorf("expected 5 deduped rules, got %d: %+v", len(log.Runs[0].Tool.Driver.Rules), log.Runs[0].Tool.Driver.Rules)
	}

	// ...but both result entries for that CVE should still be present.
	if len(log.Runs[0].Results) != 6 { // 2 vuln results + 4 issue results
		t.Fatalf("expected 6 results, got %d", len(log.Runs[0].Results))
	}

	levels := map[string]string{}
	var findingResult, sastResult, unknownResult *struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region *struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	for i := range log.Runs[0].Results {
		res := &log.Runs[0].Results[i]
		levels[res.RuleID] = res.Level
		switch res.RuleID {
		case "CVE-2022-28346":
			findingResult = res
		case "go-insecure-random-for-secrets":
			sastResult = res
		case "some-rule":
			unknownResult = res
		}
	}

	wantLevels := map[string]string{
		"CVE-2022-28346":                 "error",   // CRITICAL
		"aws-access-key-id":              "error",   // CRITICAL
		"dockerfile-secret-env":          "warning", // MEDIUM
		"go-insecure-random-for-secrets": "note",    // INFO
		"some-rule":                      "warning", // UNKNOWN -> warning, not dropped
	}
	for rule, want := range wantLevels {
		if got := levels[rule]; got != want {
			t.Errorf("level for %s = %q, want %q", rule, got, want)
		}
	}

	if findingResult == nil {
		t.Fatal("missing vuln result")
	}
	if findingResult.Locations[0].PhysicalLocation.Region != nil {
		t.Errorf("expected no region for a package-level Finding (no line number), got %+v", findingResult.Locations[0].PhysicalLocation.Region)
	}
	wantURI := filepath.ToSlash(filepath.Join("requirements.txt"))
	if findingResult.Locations[0].PhysicalLocation.ArtifactLocation.URI != wantURI {
		t.Errorf("expected relativized+forward-slash URI %q, got %q", wantURI, findingResult.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}

	if sastResult == nil {
		t.Fatal("missing sast issue result")
	}
	if sastResult.Locations[0].PhysicalLocation.Region != nil {
		t.Errorf("expected no region for an Issue with Line=0, got %+v", sastResult.Locations[0].PhysicalLocation.Region)
	}

	if unknownResult == nil {
		t.Fatal("missing unknown-severity issue result")
	}
	if unknownResult.Locations[0].PhysicalLocation.Region == nil || unknownResult.Locations[0].PhysicalLocation.Region.StartLine != 1 {
		t.Errorf("expected region with StartLine=1, got %+v", unknownResult.Locations[0].PhysicalLocation.Region)
	}
}

func TestSARIFSuppressionsAreNativelyFlaggedNotOmitted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	manifestPath := filepath.Join(root, "requirements.txt")
	issueFile := filepath.Join(root, "src", "config.py")

	r := Report{
		Findings: []model.Finding{
			{
				Package: model.Package{Name: "kept-pkg", Source: manifestPath},
				Vulns:   []model.Vulnerability{{ID: "CVE-KEPT", Severity: "HIGH"}},
			},
		},
		SuppressedFindings: []ignore.SuppressedFinding{
			{
				Package: model.Package{Name: "django", Version: "3.2.0", Source: manifestPath},
				Vuln:    model.Vulnerability{ID: "CVE-2022-28346", Summary: "SQL Injection in Django", Severity: "CRITICAL"},
				Reason:  "accepted risk, reviewed by security",
			},
		},
		SuppressedIssues: []ignore.SuppressedIssue{
			{
				Issue:  model.Issue{RuleID: "go-insecure-random-for-secrets", Title: "insecure random", Severity: "INFO", File: issueFile, Line: 4, Message: "boom"},
				Reason: "false positive, reviewed",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.SARIF(&buf, root); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF output isn't valid JSON: %v\n%s", err, buf.String())
	}

	results := log.Runs[0].Results
	if len(results) != 3 { // 1 kept vuln + 1 suppressed vuln + 1 suppressed issue
		t.Fatalf("expected suppressed results to still appear in SARIF, got %d results", len(results))
	}

	byRule := map[string]struct {
		Kind          string
		Justification string
		suppressed    bool
	}{}
	for _, res := range results {
		if len(res.Suppressions) > 0 {
			byRule[res.RuleID] = struct {
				Kind          string
				Justification string
				suppressed    bool
			}{res.Suppressions[0].Kind, res.Suppressions[0].Justification, true}
		}
	}

	kept, ok := byRule["CVE-KEPT"]
	if ok && kept.suppressed {
		t.Error("expected the kept finding to have no suppressions entry")
	}

	sv, ok := byRule["CVE-2022-28346"]
	if !ok {
		t.Fatal("expected the suppressed vuln result to carry a suppressions entry")
	}
	if sv.Kind != "external" || sv.Justification != "accepted risk, reviewed by security" {
		t.Errorf("suppressed vuln = %+v", sv)
	}

	si, ok := byRule["go-insecure-random-for-secrets"]
	if !ok {
		t.Fatal("expected the suppressed issue result to carry a suppressions entry")
	}
	if si.Kind != "external" || si.Justification != "false positive, reviewed" {
		t.Errorf("suppressed issue = %+v", si)
	}
}

func TestSARIFEmptyReportProducesValidEmptyArrays(t *testing.T) {
	var buf bytes.Buffer
	if err := (Report{}).SARIF(&buf, ""); err != nil {
		t.Fatal(err)
	}
	// Must be "[]", not "null" -- SARIF consumers expect arrays, not nulls.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	var runs []json.RawMessage
	if err := json.Unmarshal(raw["runs"], &runs); err != nil || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %v (err=%v)", runs, err)
	}
	var run map[string]json.RawMessage
	if err := json.Unmarshal(runs[0], &run); err != nil {
		t.Fatal(err)
	}
	if string(run["results"]) != "[]" {
		t.Errorf("expected results to be [], got %s", run["results"])
	}
}
