package osv

import "testing"

func TestCVSS3BaseScore(t *testing.T) {
	cases := []struct {
		vector    string
		wantScore float64
		wantLabel string
	}{
		// Standard "everything maxed" example from the CVSS v3.1 spec/calculator.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"},
		// Debian's tar CVE-2026-5704 vector (real, seen from the live API).
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.5, "MEDIUM"},
		// Scope-changed example (S:C exercises the alternate impact/base formula).
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6, "CRITICAL"},
	}
	for _, c := range cases {
		score, ok := cvss3BaseScore(c.vector)
		if !ok {
			t.Errorf("cvss3BaseScore(%q): expected ok=true", c.vector)
			continue
		}
		if score != c.wantScore {
			t.Errorf("cvss3BaseScore(%q) = %v, want %v", c.vector, score, c.wantScore)
		}
		label, ok := cvss3SeverityLabel(c.vector)
		if !ok || label != c.wantLabel {
			t.Errorf("cvss3SeverityLabel(%q) = %q,%v want %q", c.vector, label, ok, c.wantLabel)
		}
	}
}

func TestCVSS3BaseScoreRejectsNonV3(t *testing.T) {
	if _, ok := cvss3BaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P"); ok {
		t.Error("expected a CVSS v2 vector (no CVSS:3.x prefix) to be rejected")
	}
	if _, ok := cvss3BaseScore("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); ok {
		t.Error("expected an invalid metric value to be rejected")
	}
}
