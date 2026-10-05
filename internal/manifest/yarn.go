package manifest

import (
	"bufio"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type yarnLockParser struct{}

func (yarnLockParser) Match(name string) bool { return name == "yarn.lock" }

// yarnLocalProtocols are the specifier protocols that point at something
// other than a published registry package (a workspace member, a symlinked
// or copied local directory).
var yarnLocalProtocols = []string{"workspace:", "link:", "portal:", "file:"}

// Parse reads both yarn.lock dialects with one line-based pass: classic (v1,
// a custom format -- `version "1.2.3"`) and berry (v2+, YAML --
// `version: 1.2.3`). Both put an entry's specifiers on an unindented line
// ending in ":" and its fields indented beneath it, which is all this needs.
func (yarnLockParser) Parse(path string) ([]model.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []model.Package
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			pkgs = append(pkgs, model.Package{Name: name, Version: version, Ecosystem: model.EcosystemNpm, Source: path})
		}
		name, version = "", ""
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // a header line lists every specifier that resolved to the entry
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			name = yarnEntryName(line)
			continue
		}
		if name == "" {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSuffix(key, ":") {
		case "version":
			version = value
		case "resolution":
			// berry: the real package behind an alias ("foo@npm:bar@1.0.0"
			// resolves to "bar@npm:1.0.0").
			if n, spec, ok := splitYarnSpecifier(value); ok && strings.HasPrefix(spec, "npm:") {
				name = n
			}
		}
	}
	flush()
	return pkgs, scanner.Err()
}

// yarnEntryName returns the package name from an entry's header line, or ""
// for a line that isn't a registry package entry.
func yarnEntryName(line string) string {
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")
	first, _, _ := strings.Cut(line, ",") // every specifier on the line names the same package
	name, spec, ok := splitYarnSpecifier(strings.Trim(strings.TrimSpace(first), `"`))
	if !ok {
		return "" // "__metadata" and anything else that isn't name@range
	}
	for _, proto := range yarnLocalProtocols {
		if strings.HasPrefix(spec, proto) {
			return ""
		}
	}
	// classic alias: "foo@npm:bar@^1.0.0" installs bar under the name foo.
	if rest, ok := strings.CutPrefix(spec, "npm:"); ok {
		if real, _, ok := splitYarnSpecifier(rest); ok {
			return real
		}
	}
	return name
}

// splitYarnSpecifier splits "name@range", where a scoped name carries its
// own leading "@".
func splitYarnSpecifier(s string) (name, spec string, ok bool) {
	if len(s) < 2 {
		return "", "", false
	}
	i := strings.Index(s[1:], "@")
	if i < 0 {
		return "", "", false
	}
	return s[:i+1], s[i+2:], true
}
