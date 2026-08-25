package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanJS(t *testing.T) {
	filler := strings.Repeat("\tx = 1;\n", 45)
	src := "function bad(a, b, c, d, e, f) {\n" +
		"\tif (a > 0) {\n\t\tif (b > 0) {\n\t\t\tif (c > 0) {\n\t\t\t\tif (d > 0) {\n\t\t\t\t\tif (e > 0) {\n\t\t\t\t\t\treturn f;\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n" +
		"\tif (a == 1) { return 1; }\n\tif (a == 2) { return 2; }\n\tif (a == 3) { return 3; }\n\tif (a == 4) { return 4; }\n\tif (a == 5) { return 5; }\n\tif (a == 6) { return 6; }\n\tif (a == 7) { return 7; }\n\tif (a == 8) { return 8; }\n\tif (a == 9) { return 9; }\n\tif (a == 10) { return 10; }\n" +
		filler +
		"\treturn 0;\n}\n\n" +
		"function clean(a) {\n\treturn a + 1;\n}\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := scanJS(dir)
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
