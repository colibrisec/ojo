// Package customrules loads user-authored SAST rules from YAML files and
// runs them alongside ojo's built-in rules.
//
// ponytail ceiling: a rule's "query" field is a raw tree-sitter S-expression
// query — the exact same query language internal/sast's own built-in rules
// are written in, not a friendlier Semgrep-style `pattern: eval($X)`
// syntax. That's a deliberate scope decision (see TODO.md's phase-2 note),
// not an oversight: it reuses the query engine directly instead of building
// a pattern-string-to-query compiler (parsing a code snippet, walking its
// AST, turning metavariable identifiers into captures — a real subsystem
// on its own). The tradeoff is a more expert-facing authoring experience in
// exchange for shipping something that's exactly as accurate as what the
// engine actually does, with no separate compiler to keep in sync.
//
// Go has no custom rules: its built-in rules are hand-rolled go/ast
// predicates with no query layer to hang a YAML-driven rule off of.
package customrules

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"gopkg.in/yaml.v3"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

// Rule is one user-authored rule loaded from a YAML file. The query must
// contain a capture named @match — the node used as the finding's
// file/line location — matching nothing produces no findings, but a query
// with no @match capture at all is a load-time error (see validate).
type Rule struct {
	ID       string `yaml:"id"`
	Language string `yaml:"language"`
	Severity string `yaml:"severity"`
	Title    string `yaml:"title"`
	Message  string `yaml:"message"`
	Query    string `yaml:"query"`

	lang  *gts.Language
	query *gts.Query
}

var languages = map[string]*gts.Language{
	"python":     grammars.PythonLanguage(),
	"javascript": grammars.JavascriptLanguage(),
	"typescript": grammars.TypescriptLanguage(),
	"tsx":        grammars.TsxLanguage(),
	"php":        grammars.PhpLanguage(),
	"ruby":       grammars.RubyLanguage(),
	"java":       grammars.JavaLanguage(),
}

// extsFor mirrors internal/sast's own per-language extension handling
// (jsLangForPath in scanner.go) — kept in sync by hand since the two
// packages don't share this mapping.
var extsFor = map[string][]string{
	"python":     {".py"},
	"javascript": {".js", ".jsx", ".mjs", ".cjs"},
	"typescript": {".ts", ".mts", ".cts"},
	"tsx":        {".tsx"},
	"php":        {".php"},
	"ruby":       {".rb"},
	"java":       {".java"},
}

var validSeverities = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
}

// Load reads every *.yaml/*.yml file directly inside dir (not recursive) as
// a Rule. A dir that doesn't exist is not an error — no custom rules,
// same "absent means off" policy as .ojo.yaml — but an existing dir
// containing an invalid rule file is.
func Load(dir string) ([]Rule, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic load order regardless of directory listing order

	seen := map[string]string{} // id -> file that defined it, for the duplicate-id error message
	var rules []Rule
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		var r Rule
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if prior, ok := seen[r.ID]; ok {
			return nil, fmt.Errorf("%s: rule id %q already defined in %s", path, r.ID, prior)
		}
		seen[r.ID] = path

		r.lang = languages[r.Language]
		q, err := gts.NewQuery(r.Query, r.lang)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid query: %w", path, err)
		}
		r.query = q
		rules = append(rules, r)
	}
	return rules, nil
}

func (r Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("missing id")
	}
	if _, ok := languages[r.Language]; !ok {
		return fmt.Errorf("unknown language %q (want one of: python, javascript, typescript, tsx, php, ruby, java)", r.Language)
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("unknown severity %q (want one of: CRITICAL, HIGH, MEDIUM, LOW, INFO)", r.Severity)
	}
	if strings.TrimSpace(r.Query) == "" {
		return fmt.Errorf("missing query")
	}
	if r.Message == "" {
		return fmt.Errorf("missing message")
	}
	if !strings.Contains(r.Query, "@match") {
		return fmt.Errorf("query has no @match capture — that's what a finding's file/line location is taken from")
	}
	return nil
}

// Scan runs every rule against every file under root whose extension
// matches that rule's language, parsing each file once per language even
// when multiple rules share it.
func Scan(root string, rules []Rule) ([]model.Issue, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	byExt := map[string][]Rule{}
	for _, r := range rules {
		for _, ext := range extsFor[r.Language] {
			byExt[ext] = append(byExt[ext], r)
		}
	}

	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		matching := byExt[filepath.Ext(path)]
		if len(matching) == 0 {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil // ponytail: skip unreadable files, don't fail the whole scan
		}
		lang := matching[0].lang // every rule in matching shares one language (grouped by extsFor)
		tree, err := gts.NewParser(lang).Parse(src)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		root := tree.RootNode()
		for _, r := range matching {
			for _, m := range r.query.ExecuteNode(root, lang, src) {
				var match *gts.Node
				for _, c := range m.Captures {
					if c.Name == "match" {
						match = c.Node
					}
				}
				if match == nil {
					continue
				}
				issues = append(issues, model.Issue{
					Scanner:  "sast",
					RuleID:   r.ID,
					Title:    r.Title,
					Severity: r.Severity,
					File:     path,
					Line:     int(match.StartPoint().Row) + 1,
					Message:  r.Message,
				})
			}
		}
		return nil
	})
	return issues, err
}
