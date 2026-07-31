package manifest

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type swiftPackageResolvedParser struct{}

func (swiftPackageResolvedParser) Match(name string) bool { return name == "Package.resolved" }

type swiftPinState struct {
	Version string `json:"version"`
}

// swiftResolvedFile handles both the v1 ({"object":{"pins":[...]}}, pre-Xcode
// 13) and v2/v3 ({"pins":[...]}) Package.resolved shapes.
type swiftResolvedFile struct {
	Pins   []swiftPinV2 `json:"pins"` // v2/v3
	Object *struct {
		Pins []swiftPinV1 `json:"pins"`
	} `json:"object"` // v1
}

type swiftPinV2 struct {
	Location string        `json:"location"`
	State    swiftPinState `json:"state"`
}

type swiftPinV1 struct {
	RepositoryURL string        `json:"repositoryURL"`
	State         swiftPinState `json:"state"`
}

func (swiftPackageResolvedParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f swiftResolvedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var pkgs []model.Package
	if f.Object != nil {
		for _, p := range f.Object.Pins {
			if pkg, ok := swiftPackage(p.RepositoryURL, p.State.Version, path); ok {
				pkgs = append(pkgs, pkg)
			}
		}
		return pkgs, nil
	}
	for _, p := range f.Pins {
		if pkg, ok := swiftPackage(p.Location, p.State.Version, path); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs, nil
}

// swiftPackage builds a package from a pin, skipping branch/revision-only
// pins with no tagged version -- OSV's SwiftURL ecosystem matches by
// SemVer tag, so there's nothing to query without one.
func swiftPackage(url, version, path string) (model.Package, bool) {
	if url == "" || version == "" {
		return model.Package{}, false
	}
	return model.Package{Name: normalizeSwiftURL(url), Version: version, Ecosystem: model.EcosystemSwiftURL, Source: path}, true
}

// normalizeSwiftURL matches OSV's SwiftURL package name convention: the
// repository URL without scheme or ".git" suffix (e.g.
// "https://github.com/apple/swift-nio.git" -> "github.com/apple/swift-nio").
func normalizeSwiftURL(url string) string {
	for _, prefix := range []string{"https://", "http://", "ssh://", "git://"} {
		url = strings.TrimPrefix(url, prefix)
	}
	return strings.TrimSuffix(url, ".git")
}
