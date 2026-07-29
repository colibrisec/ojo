package secret

import (
	_ "embed"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed default_rules.yaml
var defaultRulesYAML []byte

// Rule is one secret-detection pattern.
type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`   // if set, line must contain one (case-insensitive) before Regex runs
	MinEntropy  float64  `yaml:"minEntropy"` // 0 = no entropy check
	Severity    string   `yaml:"severity"`

	compiled *regexp.Regexp
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// DefaultRules returns the embedded v1 ruleset, compiled and ready to use.
func DefaultRules() ([]Rule, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(defaultRulesYAML, &rf); err != nil {
		return nil, fmt.Errorf("parsing default secret rules: %w", err)
	}
	for i := range rf.Rules {
		re, err := regexp.Compile(rf.Rules[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rf.Rules[i].ID, err)
		}
		rf.Rules[i].compiled = re
	}
	return rf.Rules, nil
}
