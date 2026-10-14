package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPipRequirements(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", `# top
-i https://pypi.org/simple
-r requirements-base.txt
-c constraints.txt
django==3.2.0
requests[security,socks] == 2.28.1 ; python_version >= "3.7"
urllib3==1.26.4 \
    --hash=sha256:aaaa \
    --hash=sha256:bbbb
jinja2 (==2.10.1)
flask>=1.0,==1.0.2
pyyaml===5.3.1  # trailing comment
numpy>=1.0
pandas
scipy==1.5.*
mylib @ git+https://example.com/mylib.git
git+https://example.com/other.git#egg=otherlib
https://example.com/archive.tar.gz
-e ./local#egg=localpkg
`)
	write(t, dir, "requirements-base.txt", "-r requirements.txt\nsix==1.15.0\n")
	write(t, dir, "constraints.txt", "notinstalled==9.9.9\n")

	pkgs, skipped, err := pipRequirementsParser{}.ParsePartial(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	want := map[string]string{
		"six": "1.15.0", "django": "3.2.0", "requests": "2.28.1", "urllib3": "1.26.4",
		"jinja2": "2.10.1", "flask": "1.0.2", "pyyaml": "5.3.1",
	}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s: got %q, want %q", name, got[name], v)
		}
	}
	for _, p := range pkgs {
		if p.Name == "six" && filepath.Base(p.Source) != "requirements-base.txt" {
			t.Errorf("included package should keep its own file as source, got %q", p.Source)
		}
	}

	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.Name] = s.Reason
	}
	wantSkipped := map[string]string{
		"numpy": "version range", "pandas": "no version", "scipy": "version range",
		"mylib": "URL or path", "otherlib": "URL or path", "https://example.com/archive.tar.gz": "URL or path", "localpkg": "editable install",
	}
	if len(reasons) != len(wantSkipped) {
		t.Errorf("got skipped %v, want %v", reasons, wantSkipped)
	}
	for name, r := range wantSkipped {
		if reasons[name] != r {
			t.Errorf("%s: got reason %q, want %q", name, reasons[name], r)
		}
	}
}

func TestPipRequirementsMatch(t *testing.T) {
	for name, want := range map[string]bool{
		"requirements.txt": true, "requirements-dev.txt": true, "requirements_test.txt": true,
		"dev-requirements.txt": true, "docs-requirements.txt": true,
		"constraints.txt": false, "README.txt": false, "requirements.in": false,
	} {
		if got := (pipRequirementsParser{}).Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestDiscoverAllReportsUnpinned(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "-r requirements-dev.txt\ndjango==3.2.0\nnumpy>=1.0\n")
	write(t, dir, "requirements-dev.txt", "pytest\n")

	pkgs, skipped, err := DiscoverAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "django" {
		t.Errorf("got %+v", pkgs)
	}
	// pytest is reached both directly and through -r, but reported once.
	if len(skipped) != 2 {
		t.Errorf("expected numpy and pytest once each, got %+v", skipped)
	}
}

func TestPipMissingIncludeIsSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte("-r nope.txt\ndjango==3.2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := pipRequirementsParser{}.Parse(path)
	if err != nil || len(pkgs) != 1 {
		t.Errorf("got %v, %+v", err, pkgs)
	}
}
