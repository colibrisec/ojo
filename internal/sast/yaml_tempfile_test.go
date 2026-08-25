package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const javaYAMLFixture = `import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

class C {
	void unsafe(String x) {
		Object obj = new Yaml().load(x);
	}

	void safe(String x) {
		Object obj = new Yaml(new SafeConstructor()).load(x);
	}
}
`

func TestJavaYAMLUnsafeLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "C.java"), []byte(javaYAMLFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "java-yaml-unsafe-load" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 java-yaml-unsafe-load issue (zero-arg new Yaml() only, not new Yaml(new SafeConstructor())), got %d: %+v", count, issues)
	}
}

const pyTempfileFixture = `import tempfile

def unsafe():
    path = tempfile.mktemp()
    return path

def safe():
    f = tempfile.NamedTemporaryFile()
    return f.name
`

func TestPythonInsecureTempfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyTempfileFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-insecure-tempfile" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-insecure-tempfile issue, got %d: %+v", count, issues)
	}
}
