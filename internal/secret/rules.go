package secret

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed default_rules.yaml
var defaultRulesYAML []byte

type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`
	MinEntropy  float64  `yaml:"minEntropy"`
	Severity    string   `yaml:"severity"`

	compiled *regexp.Regexp
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

func DefaultRules() ([]Rule, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(defaultRulesYAML, &rf); err != nil {
		return nil, fmt.Errorf("parsing default secret rules: %w", err)
	}
	if err := compileRules(rf.Rules); err != nil {
		return nil, err
	}
	return rf.Rules, nil
}

// LoadRules reads additional secret rules from a user-supplied YAML file —
// the same "rules: [...]" shape as the embedded defaults — so a user rule
// is a copy-pasteable variant of a default one. An empty path means no
// custom rules, same "absent means off" policy as --rules-dir/.ojo.yaml.
func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf ruleFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := compileRules(rf.Rules); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rf.Rules, nil
}

func compileRules(rules []Rule) error {
	for i := range rules {
		if rules[i].ID == "" {
			return fmt.Errorf("rule missing id")
		}
		re, err := regexp.Compile(rules[i].Regex)
		if err != nil {
			return fmt.Errorf("rule %s: %w", rules[i].ID, err)
		}
		rules[i].compiled = re
	}
	return nil
}

// mergeRules appends extra to base, erroring on an id collision so a custom
// rule can't silently shadow (or duplicate) a default one.
func mergeRules(base, extra []Rule) ([]Rule, error) {
	seen := map[string]bool{}
	for _, r := range base {
		seen[r.ID] = true
	}
	for _, r := range extra {
		if seen[r.ID] {
			return nil, fmt.Errorf("rule id %q already defined", r.ID)
		}
		seen[r.ID] = true
	}
	return append(base, extra...), nil
}
