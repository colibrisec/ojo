package manifest

import "testing"

func TestSwiftPackageResolvedParserV2(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Package.resolved", `{
		"pins": [
			{
				"identity": "swift-nio",
				"kind": "remoteSourceControl",
				"location": "https://github.com/apple/swift-nio.git",
				"state": {"revision": "abc123", "version": "2.0.0"}
			},
			{
				"identity": "unreleased-fork",
				"kind": "remoteSourceControl",
				"location": "https://github.com/example/fork.git",
				"state": {"branch": "main", "revision": "def456"}
			}
		],
		"version": 2
	}`)

	pkgs, err := swiftPackageResolvedParser{}.Parse(dir + "/Package.resolved")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "github.com/apple/swift-nio" || pkgs[0].Version != "2.0.0" || pkgs[0].Ecosystem != "SwiftURL" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
}

func TestSwiftPackageResolvedParserV1(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Package.resolved", `{
		"object": {
			"pins": [
				{
					"package": "swift-nio",
					"repositoryURL": "https://github.com/apple/swift-nio.git",
					"state": {"branch": null, "revision": "abc123", "version": "2.0.0"}
				}
			]
		},
		"version": 1
	}`)

	pkgs, err := swiftPackageResolvedParser{}.Parse(dir + "/Package.resolved")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "github.com/apple/swift-nio" || pkgs[0].Version != "2.0.0" || pkgs[0].Ecosystem != "SwiftURL" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
}
