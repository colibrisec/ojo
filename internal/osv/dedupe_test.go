package osv

import (
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestDedupeVulnsMergesByAlias(t *testing.T) {
	vulns := []model.Vulnerability{
		{ID: "GHSA-2gwj-7jmv-h26r", Summary: "SQL Injection in Django", Severity: "CRITICAL", Aliases: []string{"CVE-2022-28346", "PYSEC-2022-190"}},
		{ID: "PYSEC-2022-190", Summary: "", Severity: "UNKNOWN"}, // no aliases populated, same advisory under a different ID
		{ID: "GHSA-unrelated-0000", Summary: "Different bug", Severity: "HIGH"},
	}

	got := dedupeVulns(vulns)
	if len(got) != 2 {
		t.Fatalf("expected 2 groups after dedup, got %d: %+v", len(got), got)
	}

	var djangoVuln *model.Vulnerability
	for i := range got {
		if got[i].ID == "GHSA-2gwj-7jmv-h26r" {
			djangoVuln = &got[i]
		}
	}
	if djangoVuln == nil {
		t.Fatalf("expected the GHSA entry (more informative) to be the surviving representative, got: %+v", got)
	}
	found := false
	for _, a := range djangoVuln.Aliases {
		if a == "PYSEC-2022-190" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected merged aliases to include PYSEC-2022-190, got: %+v", djangoVuln.Aliases)
	}
}

func TestDedupeVulnsNoFalseMerge(t *testing.T) {
	vulns := []model.Vulnerability{
		{ID: "GHSA-aaaa", Severity: "HIGH"},
		{ID: "GHSA-bbbb", Severity: "LOW"},
	}
	got := dedupeVulns(vulns)
	if len(got) != 2 {
		t.Errorf("expected unrelated vulns to stay separate, got %d: %+v", len(got), got)
	}
}
