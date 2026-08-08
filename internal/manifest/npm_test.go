package manifest

import "testing"

func TestNpmLockSkipsLocalWorkspaceMembers(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package-lock.json", `{"packages":{
		"": {"name": "root"},
		"packages/ui": {"name": "@myapp/ui", "version": "1.0.0"},
		"node_modules/react": {"version": "18.2.0"}
	}}`)

	pkgs, err := npmLockParser{}.Parse(dir + "/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range pkgs {
		if p.Name == "packages/ui" || p.Name == "@myapp/ui" {
			t.Errorf("expected local workspace member to be skipped, got it in results: %+v", pkgs)
		}
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "react" && p.Version == "18.2.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected react@18.2.0 to still be found, got: %+v", pkgs)
	}
}
