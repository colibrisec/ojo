// Package config loads optional .ojo.yaml defaults for CLI flags.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Config mirrors a subset of ojo's CLI flags for use as per-repo defaults.
type Config struct {
	Scanners string  `yaml:"scanners"`
	Format   string  `yaml:"format"`
	Quality  Quality `yaml:"quality"`
}

// Quality overrides quality thresholds; zero keeps the default.
type Quality struct {
	MaxFunctionLines  int `yaml:"max-function-lines"`
	MaxParameters     int `yaml:"max-parameters"`
	MaxNestingDepth   int `yaml:"max-nesting-depth"`
	MaxComplexity     int `yaml:"max-complexity"`
	MinDuplicateLines int `yaml:"min-duplicate-lines"`
}

// Load reads explicitPath, or ".ojo.yaml" in the current directory if
// explicitPath is empty. A missing default file is not an error (no
// overrides); a missing explicit path is, since that's almost certainly a
// typo. Unrecognized keys are also an error, for the same reason.
func Load(explicitPath string) (*Config, error) {
	path := explicitPath
	if path == "" {
		path = ".ojo.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && explicitPath == "" {
			return &Config{}, nil
		}
		return nil, err
	}

	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	for _, f := range []struct {
		name  string
		value int
	}{
		{"max-function-lines", c.Quality.MaxFunctionLines},
		{"max-parameters", c.Quality.MaxParameters},
		{"max-nesting-depth", c.Quality.MaxNestingDepth},
		{"max-complexity", c.Quality.MaxComplexity},
		{"min-duplicate-lines", c.Quality.MinDuplicateLines},
	} {
		if f.value < 0 {
			return nil, fmt.Errorf("parsing %s: quality.%s must be positive, got %d", path, f.name, f.value)
		}
	}
	return &c, nil
}
