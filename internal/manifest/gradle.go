package manifest

import (
	"bufio"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type gradleLockParser struct{}

func (gradleLockParser) Match(name string) bool { return name == "gradle.lockfile" }

// Parse reads Gradle's dependency-locking output: one
// "group:artifact:version=configurations" line per resolved dependency.
// This is an opt-in file (dependency locking must be enabled) -- ojo
// doesn't parse build.gradle/build.gradle.kts itself (Groovy/Kotlin DSL,
// not data).
func (gradleLockParser) Parse(path string) ([]model.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []model.Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coord, _, _ := strings.Cut(line, "=")
		parts := strings.Split(coord, ":")
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		pkgs = append(pkgs, model.Package{
			Name: group + ":" + artifact, Version: version, Ecosystem: model.EcosystemMaven, Source: path,
		})
	}
	return pkgs, scanner.Err()
}
