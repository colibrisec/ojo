package manifest

import "testing"

func TestPipfileLockParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Pipfile.lock", `{
		"default": {
			"requests": {"version": "==2.28.1"},
			"local-lib": {"path": "./vendor/local-lib"}
		},
		"develop": {
			"pytest": {"version": "==7.1.0"}
		}
	}`)

	pkgs, err := pipfileLockParser{}.Parse(dir + "/Pipfile.lock")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"requests@2.28.1": false, "pytest@7.1.0": false}
	for _, p := range pkgs {
		if p.Name == "local-lib" {
			t.Errorf("path dependency with no pinned version should have been skipped, got %+v", p)
		}
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
}
