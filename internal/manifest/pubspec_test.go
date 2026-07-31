package manifest

import "testing"

func TestPubspecLockParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pubspec.lock", `packages:
  http:
    dependency: "direct main"
    source: hosted
    version: "0.13.0"
sdks:
  dart: ">=2.12.0 <3.0.0"
`)

	pkgs, err := pubspecLockParser{}.Parse(dir + "/pubspec.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "http" || pkgs[0].Version != "0.13.0" || pkgs[0].Ecosystem != "Pub" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
}
