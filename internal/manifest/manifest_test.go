package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover(t *testing.T) {
	dir := t.TempDir()

	write(t, dir, "go.mod", "module example.com/x\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n")
	write(t, dir, "requirements.txt", "django==3.2.0\n# comment\nnumpy>=1.0\n")
	write(t, dir, "package-lock.json", `{"packages":{"":{"name":"root"},"node_modules/lodash":{"version":"4.17.21"}}}`)

	pkgs, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"github.com/pkg/errors@0.9.1": false, "django@3.2.0": false, "lodash@4.17.21": false}
	for _, p := range pkgs {
		key := p.Name + "@" + p.Version
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("expected package %s not found in %+v", k, pkgs)
		}
	}
	// numpy has no pinned version (>=), pip parser should have skipped it.
	for _, p := range pkgs {
		if p.Name == "numpy" {
			t.Errorf("unpinned requirement numpy should have been skipped, got %+v", p)
		}
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
