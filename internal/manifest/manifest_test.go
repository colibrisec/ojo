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

func TestDiscoverKeepsSamePackageFromEachManifest(t *testing.T) {
	dir := t.TempDir()
	// Same package+version, same ecosystem, in two different files: each is
	// a location to report, so neither may be dropped.
	write(t, dir, "requirements.txt", "requests==2.28.1\nrequests==2.28.1\n")
	write(t, dir, "uv.lock", "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.28.1\"\n")

	pkgs, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]int{}
	for _, p := range pkgs {
		if p.Name == "requests" && p.Version == "2.28.1" {
			sources[filepath.Base(p.Source)]++
		}
	}
	// Once per file -- a repeat within one file is still a duplicate.
	if len(sources) != 2 || sources["requirements.txt"] != 1 || sources["uv.lock"] != 1 {
		t.Errorf("expected requests@2.28.1 once from each of requirements.txt and uv.lock, got %v: %+v", sources, pkgs)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
