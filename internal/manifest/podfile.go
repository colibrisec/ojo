package manifest

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/colibrisec/ojo/internal/model"
)

type podfileLockParser struct{}

func (podfileLockParser) Match(name string) bool { return name == "Podfile.lock" }

type podfileLockFile struct {
	// Each entry is either "Name (1.2.3)" or, for a pod with dependencies,
	// a one-key map of that same string to its dependency list.
	Pods []any `yaml:"PODS"`
}

func (podfileLockParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock podfileLockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var pkgs []model.Package
	seen := map[string]bool{}
	add := func(entry string) {
		name, version, ok := splitPodEntry(entry)
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		pkgs = append(pkgs, model.Package{Name: name, Version: version, Ecosystem: model.EcosystemCocoaPods, Source: path})
	}
	for _, p := range lock.Pods {
		switch p := p.(type) {
		case string:
			add(p)
		case map[string]any:
			for entry := range p {
				add(entry)
			}
		}
	}
	return pkgs, nil
}

// splitPodEntry splits "Name (1.2.3)". A subspec ("Firebase/Core") is
// reported as its root pod: subspecs are released, versioned and advised on
// together with it.
func splitPodEntry(entry string) (name, version string, ok bool) {
	name, version, ok = strings.Cut(strings.TrimSpace(entry), " (")
	if !ok || !strings.HasSuffix(version, ")") {
		return "", "", false
	}
	name, _, _ = strings.Cut(name, "/")
	version = strings.TrimSuffix(version, ")")
	return name, version, name != "" && version != ""
}
