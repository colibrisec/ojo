package report

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestTableSortsBySeverityWithinPackage(t *testing.T) {
	findings := []model.Finding{
		{
			Package: model.Package{Name: "foo", Version: "1.0"},
			Vulns: []model.Vulnerability{
				{ID: "OSV-1", Summary: "low issue", Severity: "LOW"},
				{ID: "OSV-2", Summary: "critical issue", Severity: "CRITICAL"},
				{ID: "OSV-3", Summary: "medium issue", Severity: "MEDIUM"},
			},
		},
	}

	var buf bytes.Buffer
	Table(&buf, "", findings) // bytes.Buffer isn't *os.File, so color is deterministically off

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// border, header, separator, then 3 rows each followed by a separator, then bottom border.
	var dataLines []string
	for _, l := range lines {
		if strings.Contains(l, "OSV-") {
			dataLines = append(dataLines, l)
		}
	}
	if len(dataLines) != 3 {
		t.Fatalf("expected 3 vuln rows, got %d:\n%s", len(dataLines), buf.String())
	}
	if !strings.Contains(dataLines[0], "CRITICAL") || !strings.Contains(dataLines[1], "MEDIUM") || !strings.Contains(dataLines[2], "LOW") {
		t.Errorf("expected rows sorted CRITICAL, MEDIUM, LOW, got:\n%s", buf.String())
	}

	// Library "foo" should print once (row 1) and merge-blank on the following rows.
	if !strings.Contains(dataLines[0], "foo") {
		t.Errorf("expected first row to show the Library, got: %q", dataLines[0])
	}
	if strings.Contains(dataLines[1], "foo") || strings.Contains(dataLines[2], "foo") {
		t.Errorf("expected Library to merge-blank on repeated rows, got:\n%s\n%s", dataLines[1], dataLines[2])
	}
}

func TestIssueTableUsesRelativePath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	file := filepath.Join(root, "src", "config.py")
	issues := []model.Issue{
		{Scanner: "secret", RuleID: "test-rule", Severity: "HIGH", File: file, Line: 4, Message: "boom"},
	}
	var buf bytes.Buffer
	IssueTable(&buf, root, issues)
	want := filepath.Join("src", "config.py") + ":4"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("expected relative path %q in output, got:\n%s", want, buf.String())
	}
	if strings.Contains(buf.String(), root) {
		t.Errorf("expected path to be relativized, still contains absolute root %q:\n%s", root, buf.String())
	}
}

func TestMergeRunsBlanksRepeatedValues(t *testing.T) {
	rows := [][]string{
		{"tar", "affected", "MEDIUM"},
		{"tar", "affected", "LOW"},
		{"util-linux", "affected", "LOW"},
	}
	mergeRuns(rows, []int{0, 1})
	if rows[0][0] != "tar" || rows[1][0] != "" {
		t.Errorf("expected column 0 to merge on row 2, got %+v", rows)
	}
	if rows[0][1] != "affected" || rows[1][1] != "" || rows[2][1] != "" {
		t.Errorf("expected column 1 (always \"affected\") to merge across all rows, got %+v", rows)
	}
	if rows[2][2] != "LOW" {
		t.Errorf("column 2 wasn't in the merge set, should be untouched: %+v", rows)
	}
}

func TestWrapTextHardBreaksLongURL(t *testing.T) {
	lines := wrapText("short title\nhttps://example.com/very/long/url/that/exceeds/the/wrap/width", 20)
	for _, l := range lines {
		if len([]rune(l)) > 20 {
			t.Errorf("expected every wrapped line to fit width 20, got %q (%d runes)", l, len([]rune(l)))
		}
	}
	if len(lines) < 2 {
		t.Errorf("expected the URL to wrap onto its own line(s), got: %+v", lines)
	}
}

func TestPrintTotalLineOrderAndCounts(t *testing.T) {
	findings := []model.Finding{{Vulns: []model.Vulnerability{{Severity: "CRITICAL"}, {Severity: "LOW"}}}}
	issues := []model.Issue{{Severity: "HIGH"}}

	var buf bytes.Buffer
	printTotalLine(&buf, findings, issues)
	got := buf.String()
	if !strings.Contains(got, "Total: 3 (") {
		t.Errorf("expected total count 3, got: %s", got)
	}
	// Trivy orders ascending: UNKNOWN, INFO, LOW, MEDIUM, HIGH, CRITICAL.
	lowIdx := strings.Index(got, "LOW:")
	highIdx := strings.Index(got, "HIGH:")
	critIdx := strings.Index(got, "CRITICAL:")
	if !(lowIdx < highIdx && highIdx < critIdx) {
		t.Errorf("expected ascending severity order LOW < HIGH < CRITICAL in: %s", got)
	}
}
