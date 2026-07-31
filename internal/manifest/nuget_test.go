package manifest

import "testing"

func TestNugetLockParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "packages.lock.json", `{
		"version": 1,
		"dependencies": {
			"net6.0": {
				"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}
			},
			"net7.0": {
				"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}
			}
		}
	}`)

	pkgs, err := nugetLockParser{}.Parse(dir + "/packages.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected duplicate across target frameworks to be deduped, got %d packages: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "Newtonsoft.Json" || pkgs[0].Version != "13.0.1" || pkgs[0].Ecosystem != "NuGet" {
		t.Errorf("unexpected package: %+v", pkgs[0])
	}
}
