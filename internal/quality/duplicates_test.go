package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanDuplicatesFindsRealDuplicateBlock(t *testing.T) {
	block := "func validateUser(u *User) error {\n" +
		"\tif u.Name == \"\" {\n" +
		"\t\treturn errors.New(\"name required\")\n" +
		"\t}\n" +
		"\tif u.Email == \"\" {\n" +
		"\t\treturn errors.New(\"email required\")\n" +
		"\t}\n" +
		"\tif u.Age < 0 {\n" +
		"\t\treturn errors.New(\"age invalid\")\n" +
		"\t}\n" +
		"\treturn nil\n" +
		"}\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n\n"+block), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package b\n\n"+block), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := scanDuplicates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 2 {
		t.Fatalf("expected 2 quality-duplicate-code issues (one per occurrence), got %d: %+v", len(issues), issues)
	}
	for _, i := range issues {
		if i.RuleID != "quality-duplicate-code" {
			t.Errorf("unexpected rule id: %s", i.RuleID)
		}
	}
}

func TestScanDuplicatesIgnoresTrivialRepeatedLines(t *testing.T) {
	// Six lines of "}" repeats across two files — same shape as a real
	// duplicate window, but each window's non-whitespace content is well
	// under dupMinChars, so it must not fire.
	trivial := strings.Repeat("}\n", dupWindowLines+2)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(trivial), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte(trivial), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := scanDuplicates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for trivial repeated lines, got %d: %+v", len(issues), issues)
	}
}

func TestScanDuplicatesNoFalsePositiveOnDistinctFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n\nfunc F() int {\n\treturn 1\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package b\n\nfunc G() int {\n\treturn 2\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := scanDuplicates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for distinct short files, got %d: %+v", len(issues), issues)
	}
}
