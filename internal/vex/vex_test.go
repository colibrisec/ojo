package vex

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

func TestGenerate_AssertsAffectedForEveryVuln(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Name: "foo", Version: "1.0", Ecosystem: model.EcosystemNpm},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}, {ID: "CVE-2024-2"}},
	}}

	doc := Generate(findings, "ojo test", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	if doc.Context != contextURL || doc.Author != "ojo test" {
		t.Errorf("unexpected doc header: %+v", doc)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d: %+v", len(doc.Statements), doc.Statements)
	}
	for _, s := range doc.Statements {
		if s.Status != "affected" {
			t.Errorf("expected status affected, got %q", s.Status)
		}
		if len(s.Products) != 1 || s.Products[0].ID != "pkg:npm/foo@1.0" {
			t.Errorf("unexpected product: %+v", s.Products)
		}
	}
}

func TestWrite_ProducesValidJSON(t *testing.T) {
	doc := Generate([]model.Finding{{
		Package: model.Package{Name: "foo", Version: "1.0", Ecosystem: model.EcosystemGo},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}, "ojo test", time.Now())

	var buf bytes.Buffer
	if err := Write(&buf, doc); err != nil {
		t.Fatal(err)
	}
	var round Document
	if err := json.Unmarshal(buf.Bytes(), &round); err != nil {
		t.Fatal(err)
	}
	if len(round.Statements) != 1 || round.Statements[0].Vulnerability.Name != "CVE-2024-1" {
		t.Errorf("round-tripped doc doesn't match, got %+v", round)
	}
}

func TestLoad_EmptyPathIsNotAnError(t *testing.T) {
	statements, err := Load("")
	if err != nil || statements != nil {
		t.Errorf("expected no statements and no error for an empty path, got %+v, err=%v", statements, err)
	}
}

const sampleDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "vendor",
  "timestamp": "2026-01-01T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2024-1"},
      "products": [{"@id": "pkg:npm/foo@1.0"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    },
    {
      "vulnerability": {"name": "CVE-2024-2"},
      "products": [{"@id": "pkg:npm/foo@1.0"}],
      "status": "affected"
    }
  ]
}`

func TestLoad_ParsesStatements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(path, []byte(sampleDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	statements, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(statements))
	}
}

func TestApply_SuppressesNotAffectedAndFixed_ButNotAffected(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Name: "foo", Version: "1.0", Ecosystem: model.EcosystemNpm},
		Vulns: []model.Vulnerability{
			{ID: "CVE-2024-1"},
			{ID: "CVE-2024-2"},
			{ID: "CVE-2024-3"},
		},
	}}
	statements := []Statement{
		{Vulnerability: vulnerability{Name: "CVE-2024-1"}, Products: []product{{ID: "pkg:npm/foo@1.0"}}, Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path"},
		{Vulnerability: vulnerability{Name: "CVE-2024-2"}, Products: []product{{ID: "pkg:npm/foo@1.0"}}, Status: "fixed"},
		{Vulnerability: vulnerability{Name: "CVE-2024-3"}, Products: []product{{ID: "pkg:npm/foo@1.0"}}, Status: "affected"},
	}

	kept, suppressed := Apply(findings, statements)

	if len(kept) != 1 || len(kept[0].Vulns) != 1 || kept[0].Vulns[0].ID != "CVE-2024-3" {
		t.Errorf("expected only CVE-2024-3 (status affected) to remain, got %+v", kept)
	}
	if len(suppressed) != 2 {
		t.Fatalf("expected 2 suppressed, got %+v", suppressed)
	}
	if suppressed[0].Reason != "VEX: not_affected (vulnerable_code_not_in_execute_path)" {
		t.Errorf("unexpected reason: %q", suppressed[0].Reason)
	}
	if suppressed[1].Reason != "VEX: fixed" {
		t.Errorf("unexpected reason: %q", suppressed[1].Reason)
	}
}

func TestApply_MatchesVulnByAlias(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Name: "foo", Version: "1.0", Ecosystem: model.EcosystemNpm},
		Vulns:   []model.Vulnerability{{ID: "OSV-1", Aliases: []string{"CVE-2024-1"}}},
	}}
	statements := []Statement{
		{Vulnerability: vulnerability{Name: "CVE-2024-1"}, Products: []product{{ID: "pkg:npm/foo@1.0"}}, Status: "not_affected"},
	}

	kept, suppressed := Apply(findings, statements)
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Errorf("expected the alias match to suppress the finding, kept=%+v suppressed=%+v", kept, suppressed)
	}
}

func TestApply_ProductMismatchDoesNotSuppress(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Name: "foo", Version: "1.0", Ecosystem: model.EcosystemNpm},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}
	statements := []Statement{
		{Vulnerability: vulnerability{Name: "CVE-2024-1"}, Products: []product{{ID: "pkg:npm/other@2.0"}}, Status: "not_affected"},
	}

	kept, suppressed := Apply(findings, statements)
	if len(kept) != 1 || len(suppressed) != 0 {
		t.Errorf("expected no suppression on a product mismatch, kept=%+v suppressed=%+v", kept, suppressed)
	}
}

func TestApply_MatchesByIdentifiersPURL(t *testing.T) {
	findings := []model.Finding{{
		Package: model.Package{Name: "foo", Version: "1.0", Ecosystem: model.EcosystemNpm},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}
	statements := []Statement{
		{Vulnerability: vulnerability{Name: "CVE-2024-1"}, Status: "not_affected"},
	}
	statements[0].Products = []product{{}}
	statements[0].Products[0].Identifiers.PURL = "pkg:npm/foo@1.0"

	kept, suppressed := Apply(findings, statements)
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Errorf("expected identifiers.purl match to suppress, kept=%+v suppressed=%+v", kept, suppressed)
	}
}
