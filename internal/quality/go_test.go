package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanGo(t *testing.T) {
	filler := strings.Repeat("\t_ = 1\n", 45)
	src := "package main\n\n" +
		"func bad(a, b, c, d, e, f int) int {\n" +
		"\tif a > 0 {\n\t\tif b > 0 {\n\t\t\tif c > 0 {\n\t\t\t\tif d > 0 {\n\t\t\t\t\tif e > 0 {\n\t\t\t\t\t\treturn f\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n" +
		"\tif a == 1 {\n\t\treturn 1\n\t}\n\tif a == 2 {\n\t\treturn 2\n\t}\n\tif a == 3 {\n\t\treturn 3\n\t}\n\tif a == 4 {\n\t\treturn 4\n\t}\n\tif a == 5 {\n\t\treturn 5\n\t}\n\tif a == 6 {\n\t\treturn 6\n\t}\n\tif a == 7 {\n\t\treturn 7\n\t}\n\tif a == 8 {\n\t\treturn 8\n\t}\n\tif a == 9 {\n\t\treturn 9\n\t}\n\tif a == 10 {\n\t\treturn 10\n\t}\n" +
		filler +
		"\treturn 0\n}\n\n" +
		"func clean(a int) int {\n\treturn a + 1\n}\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := scanGo(dir)
	if err != nil {
		t.Fatal(err)
	}
	assertQualityIssues(t, issues, map[string]int{
		"quality-function-length":       1,
		"quality-parameter-count":       1,
		"quality-nesting-depth":         1,
		"quality-cyclomatic-complexity": 1,
	})
}
