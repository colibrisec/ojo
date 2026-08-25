package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanJava(t *testing.T) {
	filler := strings.Repeat("\t\tint x = 1;\n", 45)
	src := "class C {\n" +
		"\tint bad(int a, int b, int c, int d, int e, int f) {\n" +
		"\t\tif (a > 0) {\n\t\t\tif (b > 0) {\n\t\t\t\tif (c > 0) {\n\t\t\t\t\tif (d > 0) {\n\t\t\t\t\t\tif (e > 0) {\n\t\t\t\t\t\t\treturn f;\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n" +
		"\t\tif (a == 1) { return 1; }\n\t\tif (a == 2) { return 2; }\n\t\tif (a == 3) { return 3; }\n\t\tif (a == 4) { return 4; }\n\t\tif (a == 5) { return 5; }\n\t\tif (a == 6) { return 6; }\n\t\tif (a == 7) { return 7; }\n\t\tif (a == 8) { return 8; }\n\t\tif (a == 9) { return 9; }\n\t\tif (a == 10) { return 10; }\n" +
		filler +
		"\t\treturn 0;\n\t}\n\n" +
		"\tint clean(int a) {\n\t\treturn a + 1;\n\t}\n" +
		"}\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "C.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := scanJava(dir)
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
