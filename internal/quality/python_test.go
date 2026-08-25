package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPython(t *testing.T) {
	filler := strings.Repeat("    x = 1\n", 45)
	src := "def bad(a, b, c, d, e, f):\n" +
		"    if a > 0:\n        if b > 0:\n            if c > 0:\n                if d > 0:\n                    if e > 0:\n                        return f\n" +
		"    if a == 1:\n        return 1\n" +
		"    if a == 2:\n        return 2\n" +
		"    if a == 3:\n        return 3\n" +
		"    if a == 4:\n        return 4\n" +
		"    if a == 5:\n        return 5\n" +
		"    if a == 6:\n        return 6\n" +
		"    if a == 7:\n        return 7\n" +
		"    if a == 8:\n        return 8\n" +
		"    if a == 9:\n        return 9\n" +
		"    if a == 10:\n        return 10\n" +
		filler +
		"    return 0\n\n" +
		"def clean(a):\n    return a + 1\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := scanPython(dir)
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
