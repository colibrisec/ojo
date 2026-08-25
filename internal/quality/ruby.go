package quality

import (
	"io/fs"
	"os"
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

var rubyLang = grammars.RubyLanguage()

// rubySpec: Ruby's grammar uses the bare keyword as the node type name for
// if/elsif/for/while/when/rescue/case/begin — verified directly, not
// assumed (same verification already relied on by internal/sast's Ruby
// rules). A method with an empty body has no body field at all (no
// body_statement node constructed) — tsMeasureFuncs/tsComplexity/
// tsNestingDepth already handle a nil body as the zero case.
var rubySpec = tsLangSpec{
	funcTypes:   map[string]bool{"method": true, "singleton_method": true, "lambda": true, "block": true},
	branchTypes: map[string]bool{"if": true, "elsif": true, "for": true, "while": true, "when": true, "rescue": true, "conditional": true},
	nestTypes:   map[string]bool{"if": true, "for": true, "while": true, "case": true, "begin": true},
	binaryTypes: map[string]bool{"binary": true},
	logicalOps:  map[string]bool{"&&": true, "||": true, "and": true, "or": true},
}

func scanRuby(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !strings.HasSuffix(path, ".rb") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		tree, err := gts.NewParser(rubyLang).Parse(src)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		for _, m := range tsMeasureFuncs(tree.RootNode(), rubyLang, rubySpec, src, path) {
			issues = append(issues, m.issues()...)
		}
		return nil
	})
	return issues, err
}
