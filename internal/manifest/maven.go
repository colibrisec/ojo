package manifest

import (
	"encoding/xml"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type mavenPomParser struct{}

func (mavenPomParser) Match(name string) bool { return name == "pom.xml" }

type pomProject struct {
	Properties   pomProperties   `xml:"properties"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
}

// pomProperties captures <properties> as a map: Maven properties are
// arbitrary tag names (<spring.version>5.3.20</spring.version>), which
// encoding/xml can't decode straight into a map -- the ",any" catch-all plus
// XMLName is the standard idiom for that.
type pomProperties struct {
	Items []pomProperty `xml:",any"`
}

type pomProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// Parse extracts <dependency> coordinates from pom.xml.
//
// ponytail ceiling: pom.xml is not a lockfile. Versions are frequently
// property placeholders resolved via parent POM inheritance or a
// <dependencyManagement> section in a different file -- correctly resolving
// those means fetching and merging parent POMs, real Maven dependency
// resolution. Out of scope. This only resolves ${property} references
// against this same file's own <properties> block (catches a large
// fraction of real-world single-file cases) and silently skips anything
// still unresolved, the same "don't guess" precedent as pip.go skipping
// unpinned requirements.txt lines.
func (mavenPomParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var proj pomProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}

	props := make(map[string]string, len(proj.Properties.Items))
	for _, p := range proj.Properties.Items {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}

	var pkgs []model.Package
	for _, d := range proj.Dependencies {
		groupID, artifactID := strings.TrimSpace(d.GroupID), strings.TrimSpace(d.ArtifactID)
		version := resolveMavenVersion(d.Version, props)
		if groupID == "" || artifactID == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, model.Package{
			Name: groupID + ":" + artifactID, Version: version, Ecosystem: model.EcosystemMaven, Source: path,
		})
	}
	return pkgs, nil
}

func resolveMavenVersion(v string, props map[string]string) string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "${") || !strings.HasSuffix(v, "}") {
		return v
	}
	key := strings.TrimSuffix(strings.TrimPrefix(v, "${"), "}")
	return props[key] // "" if unresolved (e.g. a parent-POM or built-in property), caller skips
}
