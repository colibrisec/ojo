package report

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestTableSortsBySeverityAndAligns(t *testing.T) {
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
	if len(lines) != 4 { // header + 3 rows
		t.Fatalf("expected 4 lines, got %d: %q", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[1], "CRITICAL") || !strings.HasPrefix(lines[2], "MEDIUM") || !strings.HasPrefix(lines[3], "LOW") {
		t.Errorf("expected rows sorted CRITICAL, MEDIUM, LOW, got:\n%s", buf.String())
	}

	// every non-color row should be the same width up to the last column, since
	// columns are padded to a common width.
	col1End := strings.Index(lines[1], "foo")
	col2End := strings.Index(lines[2], "foo")
	if col1End != col2End {
		t.Errorf("columns not aligned: PACKAGE starts at %d on row 1 but %d on row 2", col1End, col2End)
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
