package manifest

import (
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/colibrisec/ojo/internal/model"
)

type pnpmLockParser struct{}

func (pnpmLockParser) Match(name string) bool { return name == "pnpm-lock.yaml" }

type pnpmLockFile struct {
	LockfileVersion any                  `yaml:"lockfileVersion"` // a number before v6, a quoted string since
	Packages        map[string]yaml.Node `yaml:"packages"`
}

func (pnpmLockParser) Parse(path string) ([]model.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock pnpmLockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	slashForm := pnpmMajorVersion(lock.LockfileVersion) < 6

	pkgs := make([]model.Package, 0, len(lock.Packages))
	for key := range lock.Packages {
		name, version, ok := splitPnpmKey(key, slashForm)
		if !ok {
			continue
		}
		pkgs = append(pkgs, model.Package{Name: name, Version: version, Ecosystem: model.EcosystemNpm, Source: path})
	}
	return pkgs, nil
}

func pnpmMajorVersion(v any) int {
	var s string
	switch v := v.(type) {
	case string:
		s = v
	case int:
		return v
	case float64:
		return int(v)
	}
	major, _, _ := strings.Cut(s, ".")
	n, _ := strconv.Atoi(major)
	return n
}

// splitPnpmKey splits a `packages:` key into name and version. The key shape
// changed across lockfile versions:
//
//	v5:  /lodash/4.17.21, /@babel/core/7.0.0_react@17.0.0  (slashForm)
//	v6:  /lodash@4.17.21, /@babel/core@7.0.0(react@17.0.0)
//	v9:  lodash@4.17.21, @babel/core@7.0.0
//
// Peer-dependency suffixes ("_..." / "(...)") are dropped. Entries with no
// registry version (git, tarball and file dependencies) are skipped.
func splitPnpmKey(key string, slashForm bool) (name, version string, ok bool) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	if slashForm {
		i := strings.LastIndex(key, "/")
		if i <= 0 {
			return "", "", false
		}
		name, version = key[:i], key[i+1:]
		version, _, _ = strings.Cut(version, "_")
	} else {
		i := strings.LastIndex(key, "@")
		if i <= 0 {
			return "", "", false
		}
		name, version = key[:i], key[i+1:]
	}
	if name == "" || version == "" || version[0] < '0' || version[0] > '9' {
		return "", "", false
	}
	return name, version, true
}
